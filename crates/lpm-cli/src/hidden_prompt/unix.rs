//! The terminal on Unix: standard input in raw mode, with bracketed paste.

use std::cell::UnsafeCell;
use std::io;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};
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
/// most Emacs buffers show what's typed themselves, whatever the terminal's
/// echo.
pub(super) fn can_hide_input() -> bool {
    hides_typed_input(std::env::var_os("INSIDE_EMACS").as_deref())
}

/// [`can_hide_input`] for the `INSIDE_EMACS` an Emacs front end sets. Only
/// its terminal emulators hide what's typed as any terminal does: term and
/// ansi-term (`30.1,term:0.96`), vterm and eat. A shell buffer (`comint`),
/// eshell, a compile buffer or any other front end shows it.
fn hides_typed_input(inside_emacs: Option<&std::ffi::OsStr>) -> bool {
    inside_emacs.is_none_or(|front_end| {
        front_end
            .to_string_lossy()
            .split(',')
            .any(|part| part == "vterm" || part == "eat" || part.starts_with("term:"))
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
    ending_signals: EndingSignals,
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
        let ending_signals = EndingSignals::take(&original);
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
            ending_signals,
        };
        if takes_escape_sequences() {
            terminal.ending_signals.paste_through(descriptor(output));
            terminal.paste_marked = output.write(BRACKETED_PASTE_ON).is_ok();
            if !terminal.paste_marked {
                terminal.ending_signals.paste_through(-1);
            }
        }
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
        // starts it, and a string's with its introducer; one nothing follows
        // soon was the Escape key, or a Meta chord.
        if (self.bytes.after_escape() || self.bytes.after_chord())
            && !input_by(Some(
                Instant::now() + escape_budget(wait, started.elapsed()),
            ))?
        {
            self.bytes.escape_key();
            self.bytes.chord_key();
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
        let paste_output = if self.paste_marked {
            descriptor(self.output)
        } else {
            -1
        };
        put_back(&self.original, paste_output);
    }
}

/// The descriptor `output` writes to.
fn descriptor(output: Output) -> libc::c_int {
    match output {
        Output::Stderr => libc::STDERR_FILENO,
        Output::Stdout => libc::STDOUT_FILENO,
    }
}

/// Turns bracketed paste off through `paste_output` (-1 when it isn't on),
/// discards input not read yet rather than leave it for the shell, or show
/// it once echo returns, and gives standard input `original` back. It makes
/// only async-signal-safe calls, since a signal handler makes it too.
fn put_back(original: &libc::termios, paste_output: libc::c_int) {
    if paste_output >= 0 {
        let mut rest = BRACKETED_PASTE_OFF;
        while !rest.is_empty() {
            // SAFETY: `rest` is valid for reads of its whole length.
            let written = unsafe { libc::write(paste_output, rest.as_ptr().cast(), rest.len()) };
            match usize::try_from(written) {
                Ok(written) => rest = &rest[written..],
                Err(_) if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    }
    // SAFETY: standard input is open and `original` is the termios read
    // from it.
    unsafe {
        libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, original);
    }
}

/// The signals readline puts the terminal back for before they end the
/// process. In raw mode no key sends one, but `kill`, a terminal that
/// closes or a supervisor still can, and the process would end with echo
/// off. A stop signal isn't among them: a shell keeps the terminal modes of
/// a job it stops and gives them back when the job resumes.
const ENDING_SIGNALS: [libc::c_int; 5] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGALRM,
];

/// No prompt has the handler.
const IDLE: u8 = 0;
/// A prompt is saving its terminal's state for the handler.
const SAVING: u8 = 1;
/// The handler restores the saved state.
const ARMED: u8 = 2;
/// A handler took the saved state, and the process is ending.
const ENDING: u8 = 3;

/// Where [`SAVED_TERMIOS`] stands. It's written only while `SAVING`, and
/// read only by the handler that moved this from `ARMED` to `ENDING`, which
/// nothing leaves.
static HANDLER_STATE: AtomicU8 = AtomicU8::new(IDLE);

/// The terminal's state outside the prompt, for the handler.
static SAVED_TERMIOS: SavedTermios = SavedTermios(UnsafeCell::new(MaybeUninit::uninit()));

/// The descriptor bracketed paste was turned on through, or -1.
static PASTE_OUTPUT: AtomicI32 = AtomicI32::new(-1);

/// The handler, read from one place so the address an installed action
/// holds compares equal to it.
static HANDLER: extern "C" fn(libc::c_int) = put_back_and_end;

struct SavedTermios(UnsafeCell<MaybeUninit<libc::termios>>);

// SAFETY: `HANDLER_STATE` keeps every write before the read that follows
// it, and none during a read.
unsafe impl Sync for SavedTermios {}

/// The prompt's handler of each of [`ENDING_SIGNALS`] that would end the
/// process, for as long as it lives.
struct EndingSignals {
    /// Whether this prompt saved its terminal's state for the handler.
    armed: bool,
    /// The action each signal had before the handler took it.
    replaced: [Option<libc::sigaction>; ENDING_SIGNALS.len()],
}

impl EndingSignals {
    /// Gives the handler each signal whose default action would end the
    /// process, once `original` is saved for it. A signal that's ignored or
    /// handled, as under `nohup`, keeps its action. Nothing is taken while
    /// another prompt has the handler, or a handler is ending the process.
    fn take(original: &libc::termios) -> Self {
        let mut taken = Self {
            armed: false,
            replaced: [None; ENDING_SIGNALS.len()],
        };
        if HANDLER_STATE
            .compare_exchange(IDLE, SAVING, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return taken;
        }
        // SAFETY: only the thread that moved the state to `SAVING` writes,
        // and no handler reads until it's `ARMED`.
        unsafe { (*SAVED_TERMIOS.0.get()).write(*original) };
        taken.armed = HANDLER_STATE
            .compare_exchange(SAVING, ARMED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if !taken.armed {
            return taken;
        }
        // SAFETY: an all-zero sigaction is a valid value of its plain
        // integer fields.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = HANDLER as libc::sighandler_t;
        action.sa_flags = libc::SA_RESETHAND | libc::SA_RESTART;
        // SAFETY: `sa_mask` is a valid signal set for these calls.
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            for signal in ENDING_SIGNALS {
                libc::sigaddset(&mut action.sa_mask, signal);
            }
        }
        for (replaced, signal) in taken.replaced.iter_mut().zip(ENDING_SIGNALS) {
            if let Some(previous) = current_action(signal)
                && previous.sa_sigaction == libc::SIG_DFL
                // SAFETY: `action` is a valid action whose handler makes only
                // async-signal-safe calls.
                && unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0
            {
                *replaced = Some(previous);
            }
        }
        taken
    }

    /// Has the handler turn bracketed paste off through `output`, or not
    /// when -1.
    fn paste_through(&self, output: libc::c_int) {
        if self.armed {
            PASTE_OUTPUT.store(output, Ordering::SeqCst);
        }
    }
}

impl Drop for EndingSignals {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = HANDLER_STATE.compare_exchange(ARMED, IDLE, Ordering::SeqCst, Ordering::SeqCst);
        PASTE_OUTPUT.store(-1, Ordering::SeqCst);
        for (replaced, signal) in self.replaced.iter().zip(ENDING_SIGNALS) {
            // A handler installed since keeps the signal; the one it
            // replaced does nothing once called in turn.
            if let Some(previous) = replaced
                && current_action(signal)
                    .is_some_and(|current| current.sa_sigaction == HANDLER as libc::sighandler_t)
            {
                // SAFETY: `previous` is the action the signal had.
                unsafe { libc::sigaction(signal, previous, std::ptr::null_mut()) };
            }
        }
    }
}

/// The action `signal` has now.
fn current_action(signal: libc::c_int) -> Option<libc::sigaction> {
    let mut current = MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: a null new action only reads the current one, which the call
    // initializes when it returns zero.
    (unsafe { libc::sigaction(signal, std::ptr::null(), current.as_mut_ptr()) } == 0)
        // SAFETY: the successful call initialized it.
        .then(|| unsafe { current.assume_init() })
}

/// Puts the terminal back, then ends the process by `signal` as its
/// default action would have: `SA_RESETHAND` restored that action on
/// entry, and the signal raised here takes it once the handler returns. A
/// handler that took the signal over since and calls this one in turn, as
/// signal-hook calls the one it replaced, gets nothing done, since for it
/// the signal doesn't end the process.
extern "C" fn put_back_and_end(signal: libc::c_int) {
    if current_action(signal).is_none_or(|current| current.sa_sigaction != libc::SIG_DFL) {
        return;
    }
    if HANDLER_STATE.swap(ENDING, Ordering::SeqCst) == ARMED {
        // SAFETY: the state was `ARMED`, so the saved state is written, and
        // `ENDING` keeps it from being written again.
        let original = unsafe { (*SAVED_TERMIOS.0.get()).assume_init_ref() };
        put_back(original, PASTE_OUTPUT.load(Ordering::SeqCst));
    }
    // SAFETY: raising a signal is async-signal-safe.
    unsafe { libc::raise(signal) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emacs_s_shell_buffer_shows_what_s_typed_and_its_terminals_hide_it() {
        use std::ffi::OsStr;
        assert!(hides_typed_input(None));
        for buffer in [
            "29.4,comint",
            "30.1,eshell",
            "30.1,compile",
            "30.1,tramp:2.7",
        ] {
            assert!(!hides_typed_input(Some(OsStr::new(buffer))), "{buffer}");
        }
        for terminal in ["vterm", "29.4,eat", "30.1,term:0.96"] {
            assert!(hides_typed_input(Some(OsStr::new(terminal))), "{terminal}");
        }
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

    static TAKEN_OVER_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    extern "C" fn count_call(_: libc::c_int) {
        TAKEN_OVER_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    static TAKEN_OVER: extern "C" fn(libc::c_int) = count_call;

    /// Gives `signal` `handler`, returning the action it had.
    fn set_action(signal: libc::c_int, handler: libc::sighandler_t) -> libc::sigaction {
        let previous = current_action(signal).expect("read the signal's action");
        let mut action = previous;
        action.sa_sigaction = handler;
        action.sa_flags = 0;
        // SAFETY: `action` is a valid action for the signal.
        let set = unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) };
        assert_eq!(set, 0, "set the signal's action");
        previous
    }

    fn handler_of(signal: libc::c_int) -> libc::sighandler_t {
        current_action(signal)
            .expect("read the signal's action")
            .sa_sigaction
    }

    // SIGINT and SIGTERM aren't checked: other tests in this process hand
    // them to signal-hook, which never gives them back.
    #[test]
    fn the_prompt_takes_only_signals_that_would_end_the_process_and_gives_them_back() {
        // SAFETY: an all-zero termios is a valid value of its plain fields,
        // and no handler runs to restore it.
        let original: libc::termios = unsafe { std::mem::zeroed() };
        let ours = HANDLER as libc::sighandler_t;
        let quit = set_action(libc::SIGQUIT, libc::SIG_DFL);
        let hangup = set_action(libc::SIGHUP, libc::SIG_IGN);
        let alarm = set_action(libc::SIGALRM, libc::SIG_DFL);

        let prompt = EndingSignals::take(&original);
        assert!(prompt.armed);
        assert_eq!(handler_of(libc::SIGQUIT), ours);
        assert_eq!(handler_of(libc::SIGHUP), libc::SIG_IGN, "as under nohup");

        let another = EndingSignals::take(&original);
        assert!(!another.armed && another.replaced.iter().all(Option::is_none));
        drop(another);
        assert_eq!(HANDLER_STATE.load(Ordering::SeqCst), ARMED);

        set_action(libc::SIGALRM, TAKEN_OVER as libc::sighandler_t);
        drop(prompt);
        assert_eq!(handler_of(libc::SIGQUIT), libc::SIG_DFL);
        assert_eq!(handler_of(libc::SIGHUP), libc::SIG_IGN);
        assert_eq!(
            handler_of(libc::SIGALRM),
            TAKEN_OVER as libc::sighandler_t,
            "a handler installed during the prompt keeps its signal"
        );
        assert_eq!(HANDLER_STATE.load(Ordering::SeqCst), IDLE);

        put_back_and_end(libc::SIGALRM);
        assert_eq!(
            TAKEN_OVER_CALLS.load(Ordering::SeqCst),
            0,
            "called in turn by the handler that took the signal over, it raises nothing"
        );
        assert_eq!(HANDLER_STATE.load(Ordering::SeqCst), IDLE);

        for (signal, previous) in [
            (libc::SIGQUIT, quit),
            (libc::SIGHUP, hangup),
            (libc::SIGALRM, alarm),
        ] {
            // SAFETY: `previous` is the action the signal had.
            unsafe { libc::sigaction(signal, &previous, std::ptr::null_mut()) };
        }
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
