//! The console on Windows: keys read as the characters they type, which
//! covers AltGr, Alt codes and an input method, without echo, line editing,
//! Ctrl+C's signal or escape sequences.

use std::io;
use std::time::Duration;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, FlushConsoleInputBuffer, GetConsoleMode, GetStdHandle,
    INPUT_RECORD, KEY_EVENT, ReadConsoleInputW, ReadConsoleW, STD_INPUT_HANDLE, SetConsoleMode,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use zeroize::Zeroizing;

use super::decode::Utf16;
use super::{Event, Keyboard, Output};

/// The console's input mode for as long as it lives.
pub(super) struct Terminal {
    input: HANDLE,
    original_mode: CONSOLE_MODE,
    utf16: Utf16,
}

impl Terminal {
    pub(super) fn enter(_output: Output) -> io::Result<Self> {
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
                | ENABLE_VIRTUAL_TERMINAL_INPUT);
        // SAFETY: `input` is the console input handle.
        if unsafe { SetConsoleMode(input, mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            input,
            original_mode,
            utf16: Utf16::default(),
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
        for &unit in &units[..read as usize] {
            self.utf16.feed(unit, each);
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
                if key.bKeyDown != 0 && unit != 0 {
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
