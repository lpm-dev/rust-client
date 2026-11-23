//! The terminal on Unix: standard input in raw mode, with bracketed paste.

use std::cell::UnsafeCell;
use std::io;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicUsize, Ordering};
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
    signals: PromptSignals,
    /// How many times the prompt had started over when this read last.
    restarts_seen: u32,
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
        let signals = PromptSignals::take(&original, &raw);
        signals.enter(|| {
            // SAFETY: standard input is open and `raw` is a valid termios.
            if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })?;
        let mut terminal = Self {
            original,
            output,
            paste_marked: false,
            bytes: Bytes::default(),
            signals,
            restarts_seen: RESTARTS.load(Ordering::SeqCst),
        };
        if takes_escape_sequences() {
            terminal.signals.paste_through(descriptor(output));
            terminal.paste_marked = output.write(BRACKETED_PASTE_ON).is_ok();
            if !terminal.paste_marked {
                terminal.signals.paste_through(-1);
            }
        }
        Ok(terminal)
    }

    /// Shows `prompt`, which the prompt shows again when it continues after
    /// a stop.
    pub(super) fn show(&mut self, prompt: &[u8]) -> io::Result<()> {
        self.output.write(prompt)?;
        self.signals.show_again(prompt, descriptor(self.output));
        Ok(())
    }
}

impl Keyboard for Terminal {
    /// Raises `SIGTSTP`, whose handler gives the terminal back and stops the
    /// process where its default action would.
    fn suspend(&mut self) {
        // SAFETY: raising a signal takes no pointers.
        unsafe { libc::raise(libc::SIGTSTP) };
    }

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
        // A stop gave the terminal back and showed the prompt again once it
        // continued, so what's read now begins a value of its own.
        let restarts = RESTARTS.load(Ordering::SeqCst);
        if restarts != self.restarts_seen {
            self.restarts_seen = restarts;
            self.bytes = Bytes::default();
            each(Event::Restart);
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
        self.signals.leave();
        let paste_output = if self.paste_marked {
            descriptor(self.output)
        } else {
            -1
        };
        if terminal_is_ours() {
            put_back(&self.original, paste_output);
        }
        self.signals.put_back_done();
    }
}

/// Whether standard input is this process's to change: a terminal whose
/// foreground process group is this one's, or one that isn't its
/// controlling terminal. A job in the background that changed it would be
/// stopped by `SIGTTOU`, and the terminal is the shell's then, in the
/// shell's mode. It makes only async-signal-safe calls.
fn terminal_is_ours() -> bool {
    // SAFETY: neither call takes a pointer, and both are async-signal-safe.
    let foreground = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
    // SAFETY: as above.
    foreground < 0 || foreground == unsafe { libc::getpgrp() }
}

/// The descriptor `output` writes to.
fn descriptor(output: Output) -> libc::c_int {
    match output {
        Output::Stderr => libc::STDERR_FILENO,
        Output::Stdout => libc::STDOUT_FILENO,
    }
}

/// Gives standard input `original` back, once input not read yet is
/// discarded rather than left for the shell, then turns bracketed paste off
/// through `paste_output` (-1 when it isn't on), within [`WRITE_BUDGET_MS`].
/// Echo comes back first, so a terminal that takes no output can't keep it
/// off. It makes only async-signal-safe calls, since a signal handler makes
/// it too.
fn put_back(original: &libc::termios, paste_output: libc::c_int) {
    put_back_input(original);
    turn_paste_off(paste_output);
}

/// How long the writes of one handler, or one put-back, may take in all:
/// less than the [`PUT_BACK_STEPS`] a handler ending the process waits for
/// one giving raw mode.
const WRITE_BUDGET_MS: i64 = 1000;

/// Milliseconds on a clock that only goes forward. It makes only
/// async-signal-safe calls.
#[allow(
    clippy::useless_conversion,
    reason = "timespec's fields are i64 on 64-bit targets, and narrower on others"
)]
fn now_ms() -> i64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is valid for the call to write, and `clock_gettime` is
    // async-signal-safe.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    i64::from(now.tv_sec) * 1000 + i64::from(now.tv_nsec) / 1_000_000
}

fn put_back_input(original: &libc::termios) {
    // SAFETY: standard input is open and `original` is the termios read
    // from it.
    unsafe {
        libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, original);
    }
}

fn turn_paste_off(paste_output: libc::c_int) {
    write_by(
        paste_output,
        BRACKETED_PASTE_OFF,
        now_ms() + WRITE_BUDGET_MS,
    );
}

/// Whether the terminal took it by `deadline`.
fn turn_paste_on(paste_output: libc::c_int, deadline: i64) -> bool {
    write_by(paste_output, BRACKETED_PASTE_ON, deadline)
}

/// The most one write in [`write_by`] passes: a terminal that says it can
/// take output has room for at least this much, so no write blocks.
const WRITE_PIECE: usize = 64;

/// Writes `bytes` to `output` (none when -1), a piece at a time, each once
/// the terminal can take it, until `deadline` (see [`now_ms`]); whether it
/// all went. It makes only async-signal-safe calls.
fn write_by(output: libc::c_int, bytes: &[u8], deadline: i64) -> bool {
    if output < 0 {
        return true;
    }
    let mut rest = bytes;
    while !rest.is_empty() {
        let left = deadline - now_ms();
        if left <= 0 {
            return false;
        }
        let mut writable = libc::pollfd {
            fd: output,
            events: libc::POLLOUT,
            revents: 0,
        };
        let timeout = libc::c_int::try_from(left).unwrap_or(libc::c_int::MAX);
        // SAFETY: `writable` is one valid pollfd for the call.
        match unsafe { libc::poll(&mut writable, 1, timeout) } {
            0 => return false,
            ready if ready < 0 => {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
            _ => {}
        }
        let piece = rest.len().min(WRITE_PIECE);
        // SAFETY: `rest` is valid for reads of its first `piece` bytes.
        let written = unsafe { libc::write(output, rest.as_ptr().cast(), piece) };
        match usize::try_from(written) {
            Ok(0) => return false,
            Ok(written) => rest = &rest[written..],
            Err(_) if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

/// The signals readline puts the terminal back for before they end the
/// process. In raw mode no key sends one, but `kill`, a terminal that
/// closes or a supervisor still can, and the process would end with echo
/// off. `SIGTSTP` puts it back before it stops the process, and `SIGCONT`
/// gives the prompt's raw mode back: bash and zsh give a job they resume
/// cooked mode with echo.
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

/// Where [`SAVED_TERMIOS`] and [`SAVED_RAW`] stand. They're written only
/// while `SAVING`, and read by the handler that moved this from `ARMED` to
/// `ENDING`, which nothing leaves, and by the others while `ARMED`: each of
/// those counts itself in [`RAW_MODE_WRITERS`] first, and the prompt waits
/// for them once it's `IDLE` again.
static HANDLER_STATE: AtomicU8 = AtomicU8::new(IDLE);

/// Set once the handler that is ending the process gave the terminal its
/// state back, bracketed paste included, or found none to give back.
static TERMINAL_PUT_BACK: AtomicBool = AtomicBool::new(false);

/// How many are giving standard input raw mode, or reading the saved state
/// to, right now: the prompt as it starts, and the handlers of `SIGCONT` and
/// `SIGTSTP`. The handler that is ending the process waits for them, then
/// undoes what they did, and so does the prompt as it ends.
static RAW_MODE_WRITERS: AtomicU32 = AtomicU32::new(0);

/// Whether the prompt wants raw mode, which `SIGCONT` gives back: from when
/// it has it until it starts to end.
static RAW_WANTED: AtomicBool = AtomicBool::new(false);

/// Whether the prompt gave standard input raw mode and hasn't given the
/// terminal its state back yet, so `SIGTSTP` puts it back before a stop.
static RAW_GIVEN: AtomicBool = AtomicBool::new(false);

/// How many times the prompt started over: each time a handler gave it raw
/// mode back after a stop and showed it again.
static RESTARTS: AtomicU32 = AtomicU32::new(0);

/// How many `SIGTSTP` handlers are running: each gives raw mode back and
/// shows the prompt again itself once the stop is over, so `SIGCONT` leaves
/// that to it.
static STOPPING: AtomicU32 = AtomicU32::new(0);

/// How long a handler that finds another ending the process waits for it to
/// give standard input back, in steps of [`PUT_BACK_STEP`].
const PUT_BACK_STEPS: u32 = 2000;
const PUT_BACK_STEP: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 1_000_000,
};

/// The terminal's state outside the prompt, for the handler.
static SAVED_TERMIOS: SavedTermios = SavedTermios(UnsafeCell::new(MaybeUninit::uninit()));

/// The prompt's raw mode, which `SIGCONT` gives back; saved with
/// [`SAVED_TERMIOS`].
static SAVED_RAW: SavedTermios = SavedTermios(UnsafeCell::new(MaybeUninit::uninit()));

/// The descriptor bracketed paste was turned on through, or -1.
static PASTE_OUTPUT: AtomicI32 = AtomicI32::new(-1);

/// The most of a prompt `SIGCONT` shows again; a longer one isn't.
const PROMPT_CAPACITY: usize = 1024;

/// The prompt the person was shown, which `SIGCONT` shows again: its first
/// [`PROMPT_LENGTH`] bytes, written once a prompt, before the length says
/// they're there.
static PROMPT: SavedPrompt = SavedPrompt(UnsafeCell::new([0; PROMPT_CAPACITY]));

/// How much of [`PROMPT`] holds the prompt; 0 while none is shown.
static PROMPT_LENGTH: AtomicUsize = AtomicUsize::new(0);

/// The descriptor the prompt was shown through.
static PROMPT_OUTPUT: AtomicI32 = AtomicI32::new(-1);

/// The handler, read from one place so the address an installed action
/// holds compares equal to it.
static HANDLER: extern "C" fn(libc::c_int) = put_back_and_end;

/// The handler of `SIGCONT`, read from one place for the same reason.
static CONTINUE_HANDLER: extern "C" fn(libc::c_int) = give_raw_mode_back;

/// The handler of `SIGTSTP`, read from one place for the same reason.
static STOP_HANDLER: extern "C" fn(libc::c_int) = put_back_and_stop;

/// Every signal the prompt handles, which each of its handlers blocks on
/// its thread, and the prompt blocks while it gives raw mode.
const HANDLED_SIGNALS: [libc::c_int; ENDING_SIGNALS.len() + 2] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGALRM,
    libc::SIGCONT,
    libc::SIGTSTP,
];

struct SavedTermios(UnsafeCell<MaybeUninit<libc::termios>>);

// SAFETY: `HANDLER_STATE` keeps every write before the read that follows
// it, and none during a read.
unsafe impl Sync for SavedTermios {}

struct SavedPrompt(UnsafeCell<[u8; PROMPT_CAPACITY]>);

// SAFETY: `PROMPT_LENGTH` is 0 while the bytes are written, and a handler
// reads only as many as it says, after it says them.
unsafe impl Sync for SavedPrompt {}

/// The set of [`HANDLED_SIGNALS`].
fn handled_signals() -> libc::sigset_t {
    // SAFETY: an all-zero sigset_t is a valid value for `sigemptyset` to
    // initialize, and these calls only change it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for signal in HANDLED_SIGNALS {
            libc::sigaddset(&mut set, signal);
        }
        set
    }
}

/// [`HANDLED_SIGNALS`] blocked on this thread for as long as it lives; any
/// that arrives meanwhile is handled once they're unblocked, or by another
/// thread.
struct BlockedSignals(libc::sigset_t);

impl BlockedSignals {
    fn block() -> Self {
        let handled = handled_signals();
        // SAFETY: an all-zero sigset_t is a valid value the call overwrites.
        let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: both sets are valid for the call.
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &handled, &mut previous) };
        Self(previous)
    }
}

impl Drop for BlockedSignals {
    fn drop(&mut self) {
        // SAFETY: the set is the thread's mask from before.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
    }
}

/// The prompt's handler of each of [`ENDING_SIGNALS`] that would end the
/// process, and of `SIGCONT` and `SIGTSTP`, for as long as it lives.
struct PromptSignals {
    /// Whether this prompt saved its terminal's state for the handler.
    armed: bool,
    /// The action each signal had before the handler took it.
    replaced: [Option<libc::sigaction>; ENDING_SIGNALS.len()],
    /// The action `SIGCONT` had before its handler took it.
    continued: Option<libc::sigaction>,
    /// The action `SIGTSTP` had before its handler took it.
    stopped: Option<libc::sigaction>,
}

impl PromptSignals {
    /// Gives the handler each signal whose default action would end the
    /// process, once `original` is saved for it, `SIGCONT`, with `raw` to
    /// give back, and `SIGTSTP`. A signal that's ignored or handled, as
    /// under `nohup`, keeps its action. Nothing is taken while another
    /// prompt has the handler, or a handler is ending the process.
    fn take(original: &libc::termios, raw: &libc::termios) -> Self {
        let mut taken = Self {
            armed: false,
            replaced: [None; ENDING_SIGNALS.len()],
            continued: None,
            stopped: None,
        };
        if HANDLER_STATE
            .compare_exchange(IDLE, SAVING, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return taken;
        }
        // SAFETY: only the thread that moved the state to `SAVING` writes,
        // and no handler reads until it's `ARMED`.
        unsafe {
            (*SAVED_TERMIOS.0.get()).write(*original);
            (*SAVED_RAW.0.get()).write(*raw);
        }
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
        action.sa_flags = libc::SA_RESTART;
        // Each handler blocks the others on its thread, so none interrupts
        // another there.
        action.sa_mask = handled_signals();
        for (replaced, signal) in taken.replaced.iter_mut().zip(ENDING_SIGNALS) {
            *replaced = take_default(signal, &action);
        }
        let mut continued = action;
        continued.sa_sigaction = CONTINUE_HANDLER as libc::sighandler_t;
        taken.continued = take_default(libc::SIGCONT, &continued);
        let mut stopped = action;
        stopped.sa_sigaction = STOP_HANDLER as libc::sighandler_t;
        taken.stopped = take_default(libc::SIGTSTP, &stopped);
        taken
    }

    /// Gives standard input raw mode with `enter`, unless a handler is
    /// ending the process already, which then gives the saved state back
    /// after it. Raw mode is wanted before it's given, so a stop in between
    /// finds it wanted, and the handled signals wait on this thread
    /// meanwhile, since a handler that interrupted it here would wait for
    /// it.
    fn enter(&self, enter: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        if !self.armed {
            return enter();
        }
        let blocked = BlockedSignals::block();
        RAW_MODE_WRITERS.fetch_add(1, Ordering::SeqCst);
        RAW_WANTED.store(true, Ordering::SeqCst);
        let entered = if HANDLER_STATE.load(Ordering::SeqCst) == ENDING {
            Err(io::Error::from(io::ErrorKind::Interrupted))
        } else {
            enter()
        };
        RAW_MODE_WRITERS.fetch_sub(1, Ordering::SeqCst);
        match &entered {
            Ok(()) => RAW_GIVEN.store(true, Ordering::SeqCst),
            // `SIGCONT` may have given raw mode meanwhile, and no prompt
            // will end to undo it; a handler ending the process undoes it
            // itself, and a terminal in the background is the shell's.
            Err(_) => {
                self.leave();
                if HANDLER_STATE.load(Ordering::SeqCst) == ARMED && terminal_is_ours() {
                    // SAFETY: the prompt is armed, so the saved state is
                    // written, and standard input is open.
                    unsafe {
                        libc::tcsetattr(
                            libc::STDIN_FILENO,
                            libc::TCSANOW,
                            (*SAVED_TERMIOS.0.get()).assume_init_ref(),
                        )
                    };
                }
            }
        }
        drop(blocked);
        entered
    }

    /// Has a handler show `prompt` again through `output`, at the start of
    /// its line, when it fits.
    fn show_again(&self, prompt: &[u8], output: libc::c_int) {
        if !self.armed || prompt.len() >= PROMPT_CAPACITY {
            return;
        }
        // SAFETY: the length is 0 until the bytes are written, so no handler
        // reads them meanwhile, and only the armed prompt writes them.
        unsafe {
            let saved = PROMPT.0.get().cast::<u8>();
            saved.write(b'\r');
            std::ptr::copy_nonoverlapping(prompt.as_ptr(), saved.add(1), prompt.len());
        };
        PROMPT_OUTPUT.store(output, Ordering::SeqCst);
        PROMPT_LENGTH.store(prompt.len() + 1, Ordering::SeqCst);
    }

    /// Notes that the prompt gave the terminal its state back, so
    /// `SIGTSTP` has nothing to put back.
    fn put_back_done(&self) {
        if self.armed {
            RAW_GIVEN.store(false, Ordering::SeqCst);
        }
    }

    /// Stops `SIGCONT` giving raw mode back, once a handler doing so ends,
    /// before the prompt gives the terminal its state back.
    fn leave(&self) {
        if self.armed {
            RAW_WANTED.store(false, Ordering::SeqCst);
            // However long a handler is held up, none may give raw mode back
            // after the prompt gave the terminal its state back, and each
            // write a handler makes waits a bounded time, so this ends.
            while RAW_MODE_WRITERS.load(Ordering::SeqCst) > 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    /// Has the handler turn bracketed paste off through `output`, or not
    /// when -1.
    fn paste_through(&self, output: libc::c_int) {
        if self.armed {
            PASTE_OUTPUT.store(output, Ordering::SeqCst);
        }
    }
}

impl Drop for PromptSignals {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        PROMPT_LENGTH.store(0, Ordering::SeqCst);
        RAW_GIVEN.store(false, Ordering::SeqCst);
        let _ = HANDLER_STATE.compare_exchange(ARMED, IDLE, Ordering::SeqCst, Ordering::SeqCst);
        // A handler that found the state `ARMED` counted itself first, so
        // this waits for it before another prompt may save its state; one
        // that counts itself from now on finds it `IDLE`.
        while RAW_MODE_WRITERS.load(Ordering::SeqCst) > 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        PASTE_OUTPUT.store(-1, Ordering::SeqCst);
        for (replaced, signal) in self.replaced.iter().zip(ENDING_SIGNALS) {
            give_back(signal, replaced.as_ref(), HANDLER);
        }
        give_back(libc::SIGCONT, self.continued.as_ref(), CONTINUE_HANDLER);
        give_back(libc::SIGTSTP, self.stopped.as_ref(), STOP_HANDLER);
    }
}

/// Gives `signal` `action` when its action is the default one, returning
/// that default.
fn take_default(signal: libc::c_int, action: &libc::sigaction) -> Option<libc::sigaction> {
    let previous = current_action(signal)?;
    // SAFETY: `action` is a valid action whose handler makes only
    // async-signal-safe calls.
    (previous.sa_sigaction == libc::SIG_DFL
        && unsafe { libc::sigaction(signal, action, std::ptr::null_mut()) } == 0)
        .then_some(previous)
}

/// Gives `signal` back the action it had, `previous`, while `handler` still
/// has it: a handler installed since keeps the signal, and the one it
/// replaced does nothing once called in turn.
fn give_back(
    signal: libc::c_int,
    previous: Option<&libc::sigaction>,
    handler: extern "C" fn(libc::c_int),
) {
    if let Some(previous) = previous
        && current_action(signal)
            .is_some_and(|current| current.sa_sigaction == handler as libc::sighandler_t)
    {
        // SAFETY: `previous` is the action the signal had.
        unsafe { libc::sigaction(signal, previous, std::ptr::null_mut()) };
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
/// default action would have: the handler gives the signal that action and
/// raises it, and it takes the process once the handler returns. A second
/// signal, on another thread, waits until standard input is back first. A
/// handler that took the signal over since and calls this one in turn, as
/// signal-hook calls the one it replaced, gets nothing done, since for it
/// the signal doesn't end the process.
extern "C" fn put_back_and_end(signal: libc::c_int) {
    // Ours while the prompt has the signal, or the default action once a
    // handler ending the process gave it back.
    if current_action(signal).is_none_or(|current| {
        current.sa_sigaction != HANDLER as libc::sighandler_t
            && current.sa_sigaction != libc::SIG_DFL
    }) {
        return;
    }
    match HANDLER_STATE.swap(ENDING, Ordering::SeqCst) {
        ARMED => {
            if terminal_is_ours() {
                // SAFETY: the state was `ARMED`, so the saved state is
                // written, and `ENDING` keeps it from being written again.
                let original = unsafe { (*SAVED_TERMIOS.0.get()).assume_init_ref() };
                put_back_input(original);
                // Raw mode the prompt or `SIGCONT` was giving standard input
                // meanwhile is undone once it's given.
                if wait_for_writers() {
                    put_back_input(original);
                }
                turn_paste_off(PASTE_OUTPUT.load(Ordering::SeqCst));
            }
            TERMINAL_PUT_BACK.store(true, Ordering::SeqCst);
        }
        ENDING => {
            wait_while(&TERMINAL_PUT_BACK, false);
        }
        _ => TERMINAL_PUT_BACK.store(true, Ordering::SeqCst),
    }
    // SAFETY: an all-zero sigaction with SIG_DFL is the default action, and
    // these calls are async-signal-safe.
    unsafe {
        let mut default: libc::sigaction = std::mem::zeroed();
        default.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(signal, &default, std::ptr::null_mut());
        libc::raise(signal);
    }
}

/// Gives standard input the prompt's raw mode, and bracketed paste, back
/// once the process continues after it was stopped, and shows the prompt
/// again: bash and zsh give a job they resume cooked mode with echo, which
/// would show what's typed, and print its command line. Only while the
/// prompt wants raw mode, no handler is ending the process, and the
/// terminal is this process's; a job continued in the background gets raw
/// mode back from the `SIGCONT` that brings it to the foreground. The
/// prompt, or a handler ending the process, waits for this handler, then
/// gives the terminal its state back. It returns to what the signal
/// interrupted, so `errno` is left as it was.
extern "C" fn give_raw_mode_back(_: libc::c_int) {
    let errno = errno::errno();
    RAW_MODE_WRITERS.fetch_add(1, Ordering::SeqCst);
    if STOPPING.load(Ordering::SeqCst) == 0 && raw_mode_wanted() {
        let deadline = now_ms() + WRITE_BUDGET_MS;
        if give_raw_mode(deadline) && raw_mode_wanted() {
            show_prompt_again(deadline);
        }
    }
    RAW_MODE_WRITERS.fetch_sub(1, Ordering::SeqCst);
    errno::set_errno(errno);
}

/// Whether a handler gives standard input the prompt's raw mode: while the
/// prompt wants it, no handler is ending the process, and the terminal is
/// this process's.
fn raw_mode_wanted() -> bool {
    HANDLER_STATE.load(Ordering::SeqCst) == ARMED
        && RAW_WANTED.load(Ordering::SeqCst)
        && terminal_is_ours()
}

/// Gives standard input the prompt's raw mode and bracketed paste, by
/// `deadline`, and has the prompt start over. Only for a handler counted in
/// [`RAW_MODE_WRITERS`] that found the state `ARMED`.
fn give_raw_mode(deadline: i64) -> bool {
    // SAFETY: the state is `ARMED`, so the raw mode is saved, and it's
    // written only while no counted handler can read it.
    let raw = unsafe { (*SAVED_RAW.0.get()).assume_init_ref() };
    // SAFETY: standard input is open and `raw` is a valid termios.
    unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, raw) };
    RESTARTS.fetch_add(1, Ordering::SeqCst);
    turn_paste_on(PASTE_OUTPUT.load(Ordering::SeqCst), deadline)
}

/// Shows the prompt again at the start of its line, by `deadline`. Only for
/// a handler counted in [`RAW_MODE_WRITERS`].
fn show_prompt_again(deadline: i64) {
    let shown = PROMPT_LENGTH.load(Ordering::SeqCst);
    if shown == 0 {
        return;
    }
    // SAFETY: the first `shown` bytes are written, and stay so while the
    // length isn't 0, which the prompt's end waits for counted handlers to
    // finish before it changes.
    let prompt =
        unsafe { std::slice::from_raw_parts(PROMPT.0.get().cast::<u8>().cast_const(), shown) };
    write_by(PROMPT_OUTPUT.load(Ordering::SeqCst), prompt, deadline);
}

/// Gives standard input the state it had outside the prompt, with what's
/// typed and not read yet discarded and bracketed paste off, then stops the
/// process exactly as `SIGTSTP`'s default action would: it raises the
/// signal with that action, which the kernel discards for an orphaned
/// process group, such as a session leader's under `ssh -t` or `docker exec
/// -it`, and a container's first process ignores. However the process goes
/// on, raw mode and bracketed paste come back here, without waiting for a
/// `SIGCONT` that may never come, and the prompt starts over and shows
/// itself again; `SIGCONT` leaves both to it meanwhile. A process that is
/// ending isn't stopped, and a handler that took the signal over since and
/// calls this one in turn gets nothing done. It counts itself in
/// [`RAW_MODE_WRITERS`] throughout, so the prompt's end waits for it, and it
/// leaves `errno` as it was.
extern "C" fn put_back_and_stop(signal: libc::c_int) {
    if current_action(signal).is_none_or(|current| {
        current.sa_sigaction != STOP_HANDLER as libc::sighandler_t
            && current.sa_sigaction != libc::SIG_DFL
    }) {
        return;
    }
    let errno = errno::errno();
    STOPPING.fetch_add(1, Ordering::SeqCst);
    RAW_MODE_WRITERS.fetch_add(1, Ordering::SeqCst);
    let state = HANDLER_STATE.load(Ordering::SeqCst);
    if state != ENDING {
        let put_back = state == ARMED && RAW_GIVEN.load(Ordering::SeqCst) && terminal_is_ours();
        if put_back {
            // SAFETY: the state was `ARMED` once this handler was counted,
            // so the saved state is written and stays so until it's done.
            let original = unsafe { (*SAVED_TERMIOS.0.get()).assume_init_ref() };
            put_back_input(original);
            // Raw mode another thread was giving meanwhile is undone once
            // it's given.
            if wait_for_writers_beyond(1) {
                put_back_input(original);
            }
            turn_paste_off(PASTE_OUTPUT.load(Ordering::SeqCst));
        }
        stop_as_default_would(signal);
        if put_back && raw_mode_wanted() {
            let deadline = now_ms() + WRITE_BUDGET_MS;
            if give_raw_mode(deadline) && raw_mode_wanted() {
                show_prompt_again(deadline);
            }
        }
    }
    RAW_MODE_WRITERS.fetch_sub(1, Ordering::SeqCst);
    STOPPING.fetch_sub(1, Ordering::SeqCst);
    errno::set_errno(errno);
}

/// Raises `signal` with its default action, then gives it back the action
/// it had. It makes only async-signal-safe calls.
fn stop_as_default_would(signal: libc::c_int) {
    // SAFETY: all-zero sigaction and sigset_t values are valid ones the
    // calls initialize or read, and every call is async-signal-safe.
    unsafe {
        let mut default: libc::sigaction = std::mem::zeroed();
        default.sa_sigaction = libc::SIG_DFL;
        let mut ours: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(signal, &default, &mut ours) != 0 {
            return;
        }
        let mut only: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut only);
        libc::sigaddset(&mut only, signal);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &only, std::ptr::null_mut());
        libc::raise(signal);
        libc::pthread_sigmask(libc::SIG_BLOCK, &only, std::ptr::null_mut());
        libc::sigaction(signal, &ours, std::ptr::null_mut());
    }
}

/// Waits, at most [`PUT_BACK_STEPS`] steps, until no one is giving
/// standard input raw mode; true when one was at first. It makes only
/// async-signal-safe calls.
fn wait_for_writers() -> bool {
    wait_for_writers_beyond(0)
}

/// [`wait_for_writers`] for a handler that counts itself among them, `own`
/// times.
fn wait_for_writers_beyond(own: u32) -> bool {
    let was = RAW_MODE_WRITERS.load(Ordering::SeqCst) > own;
    for _ in 0..PUT_BACK_STEPS {
        if RAW_MODE_WRITERS.load(Ordering::SeqCst) <= own {
            break;
        }
        // SAFETY: `nanosleep` is async-signal-safe, and a null remainder is
        // allowed.
        unsafe { libc::nanosleep(&PUT_BACK_STEP, std::ptr::null_mut()) };
    }
    was
}

/// Waits, at most [`PUT_BACK_STEPS`] steps, while `flag` is `value`; true
/// when it was at first. It makes only async-signal-safe calls.
fn wait_while(flag: &AtomicBool, value: bool) -> bool {
    let was = flag.load(Ordering::SeqCst) == value;
    for _ in 0..PUT_BACK_STEPS {
        if flag.load(Ordering::SeqCst) != value {
            break;
        }
        // SAFETY: `nanosleep` is async-signal-safe, and a null remainder is
        // allowed.
        unsafe { libc::nanosleep(&PUT_BACK_STEP, std::ptr::null_mut()) };
    }
    was
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

        let prompt = PromptSignals::take(&original, &original);
        assert!(prompt.armed);
        assert_eq!(handler_of(libc::SIGQUIT), ours);
        assert_eq!(handler_of(libc::SIGHUP), libc::SIG_IGN, "as under nohup");
        assert_eq!(
            handler_of(libc::SIGCONT),
            CONTINUE_HANDLER as libc::sighandler_t
        );
        assert_eq!(
            handler_of(libc::SIGTSTP),
            STOP_HANDLER as libc::sighandler_t
        );

        let another = PromptSignals::take(&original, &original);
        assert!(!another.armed && another.replaced.iter().all(Option::is_none));
        drop(another);
        assert_eq!(HANDLER_STATE.load(Ordering::SeqCst), ARMED);

        set_action(libc::SIGALRM, TAKEN_OVER as libc::sighandler_t);
        drop(prompt);
        assert_eq!(handler_of(libc::SIGQUIT), libc::SIG_DFL);
        assert_eq!(handler_of(libc::SIGCONT), libc::SIG_DFL);
        assert_eq!(handler_of(libc::SIGTSTP), libc::SIG_DFL);
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

    fn blocked_on_this_thread(signal: libc::c_int) -> bool {
        // SAFETY: an all-zero sigset_t is a valid value the call overwrites,
        // and a null new set only reads the mask.
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask);
            libc::sigismember(&mask, signal) == 1
        }
    }

    #[test]
    fn the_prompt_wants_raw_mode_before_giving_it_and_holds_its_signals_off_this_thread_meanwhile()
    {
        // SAFETY: an all-zero termios is a valid value of its plain fields,
        // and nothing gives it to a terminal.
        let original: libc::termios = unsafe { std::mem::zeroed() };
        let prompt = PromptSignals::take(&original, &original);
        assert!(prompt.armed);
        let mut seen = None;

        prompt
            .enter(|| {
                seen = Some((
                    RAW_WANTED.load(Ordering::SeqCst),
                    HANDLED_SIGNALS
                        .iter()
                        .all(|signal| blocked_on_this_thread(*signal)),
                ));
                Ok(())
            })
            .expect("raw mode");
        prompt.leave();
        drop(prompt);

        assert_eq!(seen, Some((true, true)));
        assert!(
            HANDLED_SIGNALS
                .iter()
                .all(|signal| !blocked_on_this_thread(*signal)),
            "the thread's mask comes back"
        );
    }

    /// Where a forked prompt runs in a new session whose controlling
    /// terminal is a new PTY.
    #[derive(Clone, Copy)]
    enum Group {
        /// A job of the session in the background: another process group
        /// has the terminal in the foreground, and this one isn't orphaned.
        Background,
        /// The session leader, in the foreground of its terminal: its
        /// process group is orphaned, since its parent is in another session,
        /// as a prompt's is under `ssh -t` or `docker exec -it`.
        OrphanedForeground,
    }

    /// How `work` ended, run as `group` in a new session: a stop is
    /// reported, and the stopped process killed.
    fn in_a_session(group: Group, work: fn() -> !) -> Ended {
        // SAFETY: the children make only async-signal-safe calls, or calls
        // to code that allocates nothing, until they exit.
        let status = unsafe {
            let leader = libc::fork();
            assert!(leader >= 0, "fork a session leader");
            if leader == 0 {
                libc::_exit(lead_a_session(group, work));
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(leader, &mut status, libc::WUNTRACED), leader);
            if libc::WIFSTOPPED(status) {
                libc::kill(leader, libc::SIGKILL);
                libc::waitpid(leader, std::ptr::null_mut(), 0);
                return Ended::Stopped(libc::WSTOPSIG(status));
            }
            status
        };
        assert!(libc::WIFEXITED(status), "the session leader exited");
        match libc::WEXITSTATUS(status) {
            code @ 0..50 => Ended::Exited(code),
            code @ 50..100 => Ended::Stopped(code - 50),
            code => Ended::Signaled(code - 100),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Ended {
        Exited(libc::c_int),
        Stopped(libc::c_int),
        Signaled(libc::c_int),
    }

    /// Runs `work` as `group` of a new session whose terminal is a new PTY,
    /// returning how a background job ended as an exit code; the leader
    /// runs foreground work itself.
    ///
    /// # Safety
    /// Only in a child process, which exits with the code it returns.
    unsafe fn lead_a_session(group: Group, work: fn() -> !) -> libc::c_int {
        // SAFETY: async-signal-safe calls on descriptors this process owns.
        unsafe {
            let (mut master, mut terminal) = (-1, -1);
            if libc::setsid() < 0
                || libc::openpty(
                    &mut master,
                    &mut terminal,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ) != 0
                || libc::ioctl(terminal, libc::TIOCSCTTY as _, 0) != 0
                || libc::tcsetpgrp(terminal, libc::getpgrp()) != 0
            {
                return 40;
            }
            if let Group::OrphanedForeground = group {
                if libc::dup2(terminal, libc::STDIN_FILENO) < 0 {
                    return 41;
                }
                work();
            }
            let job = libc::fork();
            if job == 0 {
                if libc::setpgid(0, 0) != 0 || libc::dup2(terminal, libc::STDIN_FILENO) < 0 {
                    libc::_exit(41);
                }
                work();
            }
            let mut status = 0;
            if libc::waitpid(job, &mut status, libc::WUNTRACED) != job {
                return 42;
            }
            if libc::WIFSTOPPED(status) {
                libc::kill(job, libc::SIGKILL);
                libc::waitpid(job, std::ptr::null_mut(), 0);
                return 50 + libc::WSTOPSIG(status);
            }
            if libc::WIFSIGNALED(status) {
                return 100 + libc::WTERMSIG(status);
            }
            libc::WEXITSTATUS(status)
        }
    }

    /// Arms the prompt's handlers over standard input in raw mode, as a
    /// prompt that gave it, then raises `signal`. It exits with a code on
    /// any failure, since a forked child of a test process mustn't panic.
    fn arm_and_raise(signal: libc::c_int) {
        let prompt = arm();
        RAW_GIVEN.store(true, Ordering::SeqCst);
        // SAFETY: raising a signal this process handles.
        unsafe { libc::raise(signal) };
        std::mem::forget(prompt);
    }

    /// Arms the prompt's handlers over standard input, in raw mode when the
    /// terminal is the process's, wanting raw mode. It exits with a code on
    /// any failure.
    fn arm() -> PromptSignals {
        // SAFETY: exiting the child, and calls that take valid values.
        unsafe {
            for taken in [libc::SIGALRM, libc::SIGCONT, libc::SIGTSTP, libc::SIGTTOU] {
                if libc::signal(taken, libc::SIG_DFL) == libc::SIG_ERR {
                    libc::_exit(43);
                }
            }
            let mut original = MaybeUninit::<libc::termios>::uninit();
            if libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) != 0 {
                libc::_exit(44);
            }
            let original = original.assume_init();
            let mut raw = original;
            libc::cfmakeraw(&mut raw);
            if terminal_is_ours() && libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) != 0 {
                libc::_exit(45);
            }
            let prompt = PromptSignals::take(&original, &raw);
            if !prompt.armed {
                libc::_exit(46);
            }
            RAW_WANTED.store(true, Ordering::SeqCst);
            prompt
        }
    }

    /// Whether standard input echoes what's typed; exits the child when it
    /// can't be told.
    fn echoes() -> bool {
        let mut attributes = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: standard input is the PTY; exiting the child.
        unsafe {
            if libc::tcgetattr(libc::STDIN_FILENO, attributes.as_mut_ptr()) != 0 {
                libc::_exit(47);
            }
            attributes.assume_init().c_lflag & libc::ECHO != 0
        }
    }

    #[test]
    fn a_signal_that_ends_a_prompt_in_the_background_ends_it_without_its_terminal() {
        let ended = in_a_session(Group::Background, || {
            arm_and_raise(libc::SIGALRM);
            // SAFETY: exiting the child.
            unsafe { libc::_exit(1) }
        });

        assert_eq!(
            ended,
            Ended::Signaled(libc::SIGALRM),
            "the terminal is the shell's, and SIGTTOU would stop lpm"
        );
    }

    #[test]
    fn a_prompt_continued_in_the_background_leaves_the_terminal_to_the_shell() {
        let ended = in_a_session(Group::Background, || {
            arm_and_raise(libc::SIGCONT);
            // SAFETY: exiting the child.
            unsafe { libc::_exit(0) }
        });

        assert_eq!(ended, Ended::Exited(0));
    }

    #[test]
    fn a_prompt_stopped_in_the_background_stops_as_the_default_action_would_without_its_terminal() {
        let ended = in_a_session(Group::Background, || {
            arm_and_raise(libc::SIGTSTP);
            // SAFETY: exiting the child.
            unsafe { libc::_exit(1) }
        });

        assert_eq!(ended, Ended::Stopped(libc::SIGTSTP));
    }

    #[test]
    fn a_stop_the_kernel_discards_leaves_the_prompt_running_and_hiding_what_s_typed() {
        let ended = in_a_session(Group::OrphanedForeground, || {
            arm_and_raise(libc::SIGTSTP);
            // SAFETY: exiting the child.
            unsafe { libc::_exit(if echoes() { 1 } else { 0 }) }
        });

        assert_eq!(
            ended,
            Ended::Exited(0),
            "an orphaned process group doesn't stop, and raw mode comes back"
        );
    }

    #[test]
    fn a_stop_while_the_process_is_ending_doesn_t_hold_it_up() {
        let ended = in_a_session(Group::Background, || {
            let prompt = arm();
            HANDLER_STATE.store(ENDING, Ordering::SeqCst);
            // SAFETY: raising a signal this process handles; exiting.
            unsafe {
                libc::raise(libc::SIGTSTP);
                std::mem::forget(prompt);
                libc::_exit(0)
            }
        });

        assert_eq!(ended, Ended::Exited(0), "a job that's ending isn't stopped");
    }

    static CHAINED_STOP: extern "C" fn(libc::c_int) = call_the_stop_handler;

    extern "C" fn call_the_stop_handler(signal: libc::c_int) {
        put_back_and_stop(signal);
    }

    #[test]
    fn a_handler_that_took_sigtstp_over_and_calls_this_one_gets_nothing_stopped() {
        let ended = in_a_session(Group::Background, || {
            let prompt = arm();
            // SAFETY: a valid action whose handler calls the prompt's in
            // turn, as signal-hook calls the one it replaced; exiting.
            unsafe {
                if libc::signal(libc::SIGTSTP, CHAINED_STOP as libc::sighandler_t) == libc::SIG_ERR
                {
                    libc::_exit(48);
                }
                libc::raise(libc::SIGTSTP);
                std::mem::forget(prompt);
                libc::_exit(0)
            }
        });

        assert_eq!(ended, Ended::Exited(0));
    }

    #[test]
    fn a_failed_entry_in_the_background_leaves_the_terminal_to_the_shell() {
        let ended = in_a_session(Group::Background, || {
            let prompt = arm();
            let entered = prompt.enter(|| Err(io::Error::other("refused")));
            std::mem::forget(prompt);
            // SAFETY: exiting the child.
            unsafe { libc::_exit(if entered.is_err() { 0 } else { 1 }) }
        });

        assert_eq!(
            ended,
            Ended::Exited(0),
            "putting the terminal back from the background would stop lpm by SIGTTOU"
        );
    }

    #[test]
    fn a_write_stops_at_its_deadline_when_the_terminal_takes_nothing() {
        let mut ends = [0; 2];
        // SAFETY: `ends` is valid for the two descriptors the call writes.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        let [read_end, write_end] = ends;
        // SAFETY: the descriptors are this test's own.
        unsafe {
            let flags = libc::fcntl(write_end, libc::F_GETFL);
            libc::fcntl(write_end, libc::F_SETFL, flags | libc::O_NONBLOCK);
            let chunk = [b'.'; 1024];
            while libc::write(write_end, chunk.as_ptr().cast(), chunk.len()) > 0 {}
        }
        let started = Instant::now();

        let written = write_by(write_end, b"x", now_ms() + 100);

        assert!(!written);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        // SAFETY: closing this test's own descriptors.
        unsafe {
            libc::close(read_end);
            libc::close(write_end);
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
