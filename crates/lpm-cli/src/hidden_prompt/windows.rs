//! The console on Windows: keys read as the characters they type, which
//! covers AltGr, Alt codes and an input method, without echo, line editing,
//! Ctrl+C's signal or escape sequences. Without processed input the console
//! doesn't paste on Ctrl+V, so the prompt pastes the clipboard itself, as one
//! paste.

use std::io;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    FALSE, HANDLE, INVALID_HANDLE_VALUE, STATUS_CONTROL_C_EXIT, TRUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, CTRL_BREAK_EVENT, CTRL_C_EVENT, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    ENABLE_MOUSE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_WINDOW_INPUT,
    FlushConsoleInputBuffer, GetConsoleMode, GetStdHandle, INPUT_RECORD, KEY_EVENT,
    ReadConsoleInputW, ReadConsoleW, STD_INPUT_HANDLE, SetConsoleCtrlHandler, SetConsoleMode,
};
use windows_sys::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use windows_sys::Win32::System::Threading::{ExitProcess, WaitForSingleObject};
use windows_sys::core::BOOL;
use zeroize::Zeroizing;

use super::decode::{Utf16, clipboard_units, paste_units, typed_unit};
use super::{Event, Keyboard, Output};

/// The character Ctrl+V types.
const CTRL_V: u16 = 0x16;

/// Whether standard input is a console, the one terminal whose echo the
/// prompt can turn off.
pub(super) fn can_hide_input() -> bool {
    // SAFETY: the call takes a constant and returns a handle the process
    // owns, or none.
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: the call writes one mode, and fails on a handle that isn't a
    // console's.
    !input.is_null()
        && input != INVALID_HANDLE_VALUE
        && unsafe { GetConsoleMode(input, &mut mode) } != 0
}

/// The clipboard's text as a paste of a value of at most `limit` bytes needs
/// it (see [`clipboard_units`]), or `None` when it holds none.
fn clipboard_text(limit: usize) -> Option<Zeroizing<Vec<u16>>> {
    // SAFETY: opening the clipboard for this thread, with no window.
    if unsafe { OpenClipboard(std::ptr::null_mut()) } == 0 {
        return None;
    }
    // SAFETY: the clipboard is open; the handle stays the clipboard's.
    let data = unsafe { GetClipboardData(u32::from(CF_UNICODETEXT)) };
    let text = if data.is_null() {
        None
    } else {
        // SAFETY: `data` is the clipboard's memory object, locked while read.
        let units = unsafe { GlobalLock(data) }.cast::<u16>();
        if units.is_null() {
            None
        } else {
            // SAFETY: the object holds `GlobalSize` bytes, read in place.
            let held = unsafe { std::slice::from_raw_parts(units, GlobalSize(data) / 2) };
            let text = clipboard_units(held, limit);
            let mut copied = Zeroizing::new(Vec::with_capacity(text.len()));
            copied.extend_from_slice(text);
            // SAFETY: unlocking what was locked above.
            unsafe { GlobalUnlock(data) };
            Some(copied)
        }
    };
    // SAFETY: closing the clipboard opened above.
    unsafe { CloseClipboard() };
    text
}

/// The console's input mode for as long as it lives.
pub(super) struct Terminal {
    input: HANDLE,
    original_mode: CONSOLE_MODE,
    utf16: Utf16,
    /// The most bytes the value may hold, which bounds a clipboard paste.
    limit: usize,
    _control_events: ControlEvents,
}

impl Terminal {
    pub(super) fn enter(_output: Output, limit: usize) -> io::Result<Self> {
        // SAFETY: the call takes a constant and returns a handle the process
        // owns, or none.
        let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if input.is_null() || input == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut original_mode: CONSOLE_MODE = 0;
        // SAFETY: `input` is the console input handle and the call writes
        // one mode.
        if unsafe { GetConsoleMode(input, &mut original_mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mode = original_mode
            & !(ENABLE_LINE_INPUT
                | ENABLE_ECHO_INPUT
                | ENABLE_PROCESSED_INPUT
                | ENABLE_VIRTUAL_TERMINAL_INPUT
                | ENABLE_MOUSE_INPUT
                | ENABLE_WINDOW_INPUT);
        let control_events = ControlEvents::take(input, original_mode, || {
            // SAFETY: `input` is the console input handle.
            if unsafe { SetConsoleMode(input, mode) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })?;
        Ok(Self {
            input,
            original_mode,
            utf16: Utf16::default(),
            limit,
            _control_events: control_events,
        })
    }

    /// Characters as the console types them, waiting for at least one.
    fn read_characters(&mut self, each: &mut dyn FnMut(Event)) -> io::Result<()> {
        let mut units = Zeroizing::new([0_u16; 256]);
        let mut read = 0_u32;
        // SAFETY: `units` is valid for writes of its whole length, which the
        // call is given, and `read` for one count.
        let succeeded = unsafe {
            ReadConsoleW(
                self.input,
                units.as_mut_ptr().cast(),
                units.len() as u32,
                &mut read,
                std::ptr::null(),
            )
        };
        if succeeded == 0 {
            return Err(io::Error::last_os_error());
        }
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the console closed",
            ));
        }
        for &unit in &units[..read as usize] {
            if unit == CTRL_V {
                self.utf16.end(each);
                if let Some(text) = clipboard_text(self.limit) {
                    paste_units(&text, each);
                }
            } else {
                self.utf16.feed(unit, each);
            }
        }
        Ok(())
    }

    /// Whatever arrives within `wait`. The console's records are read
    /// instead of its characters, which would wait for a key that types one:
    /// the release of Enter, a focus change or a resize arrives as a record
    /// too, and carries no text.
    fn read_records(&mut self, wait: Duration, each: &mut dyn FnMut(Event)) -> io::Result<bool> {
        let milliseconds = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: `input` is the console input handle, which is signaled
        // while it holds records.
        match unsafe { WaitForSingleObject(self.input, milliseconds) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Ok(false),
            _ => return Err(io::Error::last_os_error()),
        }
        // SAFETY: an all-zero INPUT_RECORD is a valid value of its plain
        // integer fields and unions.
        let mut records: [INPUT_RECORD; 64] = unsafe { std::mem::zeroed() };
        let mut read = 0_u32;
        // SAFETY: `records` is valid for writes of its whole length, which
        // the call is given, and `read` for one count.
        let succeeded = unsafe {
            ReadConsoleInputW(
                self.input,
                records.as_mut_ptr(),
                records.len() as u32,
                &mut read,
            )
        };
        let result = if succeeded == 0 {
            Err(io::Error::last_os_error())
        } else {
            for record in &records[..read as usize] {
                if u32::from(record.EventType) != KEY_EVENT {
                    continue;
                }
                // SAFETY: a KEY_EVENT record holds a key event.
                let key = unsafe { record.Event.KeyEvent };
                // SAFETY: the console fills the character as UTF-16.
                let unit = unsafe { key.uChar.UnicodeChar };
                if let Some(unit) = typed_unit(key.bKeyDown != 0, key.wVirtualKeyCode, unit) {
                    self.utf16.feed(unit, each);
                }
            }
            Ok(true)
        };
        // SAFETY: `records` is plain data, valid when all zero.
        unsafe { zeroize::zeroize_flat_type(&mut records) };
        result
    }
}

impl Keyboard for Terminal {
    fn read(&mut self, wait: Option<Duration>, each: &mut dyn FnMut(Event)) -> io::Result<bool> {
        match wait {
            None => self.read_characters(each).map(|()| true),
            Some(wait) => self.read_records(wait, each),
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // Input that arrived since the last read is discarded rather than
        // left for the shell.
        // SAFETY: `input` is the console input handle and `original_mode`
        // the mode read from it.
        unsafe {
            FlushConsoleInputBuffer(self.input);
            SetConsoleMode(self.input, self.original_mode);
        }
    }
}

/// The console a control event puts back, while a prompt has it.
struct HeldConsole {
    input: HANDLE,
    mode: CONSOLE_MODE,
}

// SAFETY: a console input handle is the process's, for any thread to use.
unsafe impl Send for HeldConsole {}

static HELD_CONSOLE: Mutex<Option<HeldConsole>> = Mutex::new(None);

/// The prompt's handler of the console's control events, for as long as it
/// lives. Without processed input Ctrl+C is a key, but Ctrl+Break, closing
/// the console, logging off or shutting down still end the process, which
/// would leave the console without echo.
struct ControlEvents {
    held: bool,
}

impl ControlEvents {
    /// Gives `input` the prompt's mode with `enter`, and has the handler give
    /// it back `mode`, unless another prompt has it. The handler waits while
    /// the prompt's mode is set, so it can't put the console back before the
    /// prompt's mode replaces it.
    fn take(
        input: HANDLE,
        mode: CONSOLE_MODE,
        enter: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Self> {
        let mut held = HELD_CONSOLE.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: the handler is a valid routine for the process's lifetime.
        let registered =
            held.is_none() && unsafe { SetConsoleCtrlHandler(Some(put_back_console), TRUE) } != 0;
        if let Err(error) = enter() {
            if registered {
                // SAFETY: removing the routine added above.
                unsafe { SetConsoleCtrlHandler(Some(put_back_console), FALSE) };
            }
            return Err(error);
        }
        if registered {
            *held = Some(HeldConsole { input, mode });
        }
        Ok(Self { held: registered })
    }
}

impl Drop for ControlEvents {
    fn drop(&mut self) {
        if self.held {
            *HELD_CONSOLE.lock().unwrap_or_else(PoisonError::into_inner) = None;
            // SAFETY: removing the routine added above.
            unsafe { SetConsoleCtrlHandler(Some(put_back_console), FALSE) };
        }
    }
}

/// Gives the console its mode back before a control event ends the
/// process. Ctrl+Break, or a Ctrl+C a program sends, ends it here as the
/// default handler would: a handler added before this one that kept the
/// process going would leave the prompt reading with echo on. The other
/// events end the process whatever the handlers return.
unsafe extern "system" fn put_back_console(event: u32) -> BOOL {
    let held = HELD_CONSOLE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(console) = held.as_ref() {
        // SAFETY: `input` is the console input handle and `mode` the mode
        // read from it.
        unsafe {
            FlushConsoleInputBuffer(console.input);
            SetConsoleMode(console.input, console.mode);
        }
        if matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
            // SAFETY: ending the process, as the default handler does.
            unsafe { ExitProcess(STATUS_CONTROL_C_EXIT as u32) };
        }
    }
    FALSE
}
