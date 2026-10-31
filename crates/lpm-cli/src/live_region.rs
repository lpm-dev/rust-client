//! Rows redrawn in place at the bottom of the terminal.
//!
//! While a [`LiveRegion`] is open, every line LPM writes to stderr — slim UI
//! rows and tracing events alike — is printed above the region's rows, which
//! are then drawn again beneath it, so the region stays pinned under the
//! output that scrolls past.

use crossterm::Command as _;
use std::io::{IsTerminal as _, Write as _};
use std::sync::{Mutex, MutexGuard};

/// The rows on screen while a region is open.
static REGION: Mutex<Option<Vec<String>>> = Mutex::new(None);

fn region() -> MutexGuard<'static, Option<Vec<String>>> {
    REGION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The open region. Dropping it leaves its last rows on screen and starts
/// later output on the line below them.
pub(crate) struct LiveRegion {
    _open: (),
}

impl LiveRegion {
    /// Opens the region, or returns `None` where stderr can't be redrawn in
    /// place: it isn't a terminal, the terminal is dumb, or a region is open.
    pub(crate) fn open() -> Option<Self> {
        if !std::io::stderr().is_terminal()
            || std::env::var_os("TERM").is_some_and(|term| term == "dumb")
        {
            return None;
        }
        #[cfg(windows)]
        if !crossterm::ansi_support::supports_ansi() {
            return None;
        }
        crate::install_ui::settle_spinner();
        let mut region = region();
        if region.is_some() {
            return None;
        }
        *region = Some(Vec::new());
        Some(Self { _open: () })
    }

    /// Replaces the region's rows. Rows must not contain line breaks; a row
    /// wider than the terminal wraps.
    pub(crate) fn draw(&self, rows: Vec<String>) {
        let mut region = region();
        let Some(drawn) = region.as_mut() else {
            return;
        };
        let (width, height) = terminal_size();
        let rows = fit_height(rows, width, height);
        let mut out =
            String::with_capacity(rows.iter().map(|row| row.len() + 2).sum::<usize>() + 32);
        redraw(&mut out, drawn, None, &rows, width);
        *drawn = rows;
        write_stderr(out.as_bytes());
    }
}

impl Drop for LiveRegion {
    fn drop(&mut self) {
        if region().take().is_some_and(|drawn| !drawn.is_empty()) {
            write_stderr(b"\r\n");
        }
    }
}

/// Whether a region is open, so nothing else may draw at the cursor.
pub(crate) fn is_open() -> bool {
    region().is_some()
}

/// Prints one line of output, above the open region's rows if there is one.
pub(crate) fn print_line(line: &str) {
    let region = region();
    match region.as_deref() {
        Some(drawn) if !drawn.is_empty() => print_above(drawn, line),
        _ => eprintln!("{line}"),
    }
}

/// The tracing writer for one event: it collects the formatted event and
/// prints it as [`print_line`] does, ignoring write errors as tracing's own
/// stderr writer does.
#[derive(Default)]
pub(crate) struct TracingEvent {
    bytes: Vec<u8>,
}

impl std::io::Write for TracingEvent {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for TracingEvent {
    fn drop(&mut self) {
        if self.bytes.is_empty() {
            return;
        }
        let region = region();
        match region.as_deref() {
            Some(drawn) if !drawn.is_empty() => {
                let event = String::from_utf8_lossy(&self.bytes);
                print_above(drawn, event.strip_suffix('\n').unwrap_or(&event));
            }
            _ => write_stderr(&self.bytes),
        }
    }
}

fn print_above(drawn: &[String], line: &str) {
    let (width, _) = terminal_size();
    let mut out = String::with_capacity(
        line.len() + drawn.iter().map(|row| row.len() + 2).sum::<usize>() + 32,
    );
    redraw(&mut out, drawn, Some(line), drawn, width);
    write_stderr(out.as_bytes());
}

/// The terminal's columns and rows, or 80×24 when it doesn't say.
pub(crate) fn terminal_size() -> (u16, u16) {
    match crossterm::terminal::size() {
        Ok((width, height)) if width > 0 && height > 0 => (width, height),
        _ => (80, 24),
    }
}

/// Erases the rows drawn, prints `line` where they began, and draws `rows`
/// below it, as one synchronized update.
fn redraw(out: &mut String, drawn: &[String], line: Option<&str>, rows: &[String], width: u16) {
    let _ = crossterm::terminal::BeginSynchronizedUpdate.write_ansi(out);
    if !drawn.is_empty() {
        // Terminals reflow wrapped rows when they resize, so the rows to
        // climb are counted at the width the terminal has now.
        let screen_rows: usize = drawn.iter().map(|row| screen_rows(row, width)).sum();
        out.push('\r');
        if let Ok(up) = u16::try_from(screen_rows - 1)
            && up > 0
        {
            let _ = crossterm::cursor::MoveUp(up).write_ansi(out);
        }
        let _ = crossterm::terminal::Clear(crossterm::terminal::ClearType::FromCursorDown)
            .write_ansi(out);
    }
    if let Some(line) = line {
        out.push_str(line);
        out.push_str("\r\n");
    }
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            out.push_str("\r\n");
        }
        out.push_str(row);
    }
    let _ = crossterm::terminal::EndSynchronizedUpdate.write_ansi(out);
}

/// The terminal rows `row` takes at `width` columns.
pub(crate) fn screen_rows(row: &str, width: u16) -> usize {
    console::measure_text_width(row)
        .div_ceil(usize::from(width))
        .max(1)
}

/// Keeps the last rows that fit on screen: cursor movement can't reach rows
/// scrolled off its top.
fn fit_height(mut rows: Vec<String>, width: u16, height: u16) -> Vec<String> {
    let mut total: usize = rows.iter().map(|row| screen_rows(row, width)).sum();
    let mut first = 0;
    while total > usize::from(height) && first + 1 < rows.len() {
        total -= screen_rows(&rows[first], width);
        first += 1;
    }
    rows.drain(..first);
    rows
}

fn write_stderr(bytes: &[u8]) {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(bytes);
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A terminal screen that interprets the sequences a region writes:
    /// text with pending autowrap, CR, LF with scrolling, cursor up, erase
    /// below, and the styling and synchronization it ignores.
    struct Screen {
        width: usize,
        height: usize,
        rows: Vec<Vec<char>>,
        row: usize,
        column: usize,
        wrap_pending: bool,
    }

    impl Screen {
        fn new(width: usize, height: usize) -> Self {
            Self {
                width,
                height,
                rows: vec![Vec::new(); height],
                row: 0,
                column: 0,
                wrap_pending: false,
            }
        }

        fn line_feed(&mut self) {
            if self.row + 1 == self.height {
                self.rows.remove(0);
                self.rows.push(Vec::new());
            } else {
                self.row += 1;
            }
        }

        fn feed(&mut self, bytes: &str) {
            let mut chars = bytes.chars().peekable();
            while let Some(character) = chars.next() {
                match character {
                    '\r' => {
                        self.column = 0;
                        self.wrap_pending = false;
                    }
                    '\n' => {
                        self.line_feed();
                        self.wrap_pending = false;
                    }
                    '\u{1b}' => {
                        assert_eq!(chars.next(), Some('['));
                        let mut parameters = String::new();
                        let command = loop {
                            let next = chars.next().unwrap();
                            if next.is_ascii_alphabetic() {
                                break next;
                            }
                            parameters.push(next);
                        };
                        match command {
                            'A' => {
                                let up: usize = parameters.parse().unwrap_or(1);
                                self.row = self.row.saturating_sub(up);
                                self.wrap_pending = false;
                            }
                            'J' => {
                                self.rows[self.row].truncate(self.column);
                                for row in &mut self.rows[self.row + 1..] {
                                    row.clear();
                                }
                            }
                            'm' | 'h' | 'l' => {}
                            other => panic!("unexpected sequence {parameters}{other}"),
                        }
                    }
                    character => {
                        if self.wrap_pending {
                            self.column = 0;
                            self.line_feed();
                            self.wrap_pending = false;
                        }
                        let row = &mut self.rows[self.row];
                        row.resize(row.len().max(self.column), ' ');
                        if self.column < row.len() {
                            row[self.column] = character;
                        } else {
                            row.push(character);
                        }
                        if self.column + 1 == self.width {
                            self.wrap_pending = true;
                        } else {
                            self.column += 1;
                        }
                    }
                }
            }
        }

        fn text(&self) -> Vec<String> {
            let mut text: Vec<String> = self
                .rows
                .iter()
                .map(|row| row.iter().collect::<String>().trim_end().to_owned())
                .collect();
            while text.last().is_some_and(String::is_empty) {
                text.pop();
            }
            text
        }
    }

    fn rows(rows: &[&str]) -> Vec<String> {
        rows.iter().map(|row| (*row).to_owned()).collect()
    }

    fn draw(screen: &mut Screen, drawn: &mut Vec<String>, next: Vec<String>) {
        let next = fit_height(next, screen.width as u16, screen.height as u16);
        let mut out = String::new();
        redraw(&mut out, drawn, None, &next, screen.width as u16);
        screen.feed(&out);
        *drawn = next;
    }

    #[test]
    fn redrawing_replaces_the_rows_in_place_under_earlier_output() {
        let mut screen = Screen::new(40, 10);
        screen.feed("› Opening tunnel\r\n");
        let mut drawn = Vec::new();

        draw(
            &mut screen,
            &mut drawn,
            rows(&["usage 1 / 100", "✓ Listening", "  press q"]),
        );
        draw(
            &mut screen,
            &mut drawn,
            rows(&[
                "usage 2 / 100",
                "✓ Listening · 1 request",
                "  GET / 200",
                "  press q",
            ]),
        );
        draw(
            &mut screen,
            &mut drawn,
            rows(&["usage 3 / 100", "✓ Listening", "  press q"]),
        );

        assert_eq!(
            screen.text(),
            [
                "› Opening tunnel",
                "usage 3 / 100",
                "✓ Listening",
                "  press q"
            ]
        );
    }

    #[test]
    fn a_line_printed_while_open_lands_above_the_rows() {
        let mut screen = Screen::new(40, 10);
        let mut drawn = Vec::new();
        draw(&mut screen, &mut drawn, rows(&["✓ Listening", "  press q"]));

        let mut out = String::new();
        redraw(&mut out, &drawn, Some(" WARN relay hiccup"), &drawn, 40);
        screen.feed(&out);

        assert_eq!(
            screen.text(),
            [" WARN relay hiccup", "✓ Listening", "  press q"]
        );
    }

    #[test]
    fn rows_that_wrap_are_erased_whole() {
        let mut screen = Screen::new(10, 10);
        let mut drawn = Vec::new();
        draw(
            &mut screen,
            &mut drawn,
            rows(&["0123456789abcdef", "status"]),
        );

        draw(&mut screen, &mut drawn, rows(&["short", "status 2"]));

        assert_eq!(screen.text(), ["short", "status 2"]);
    }

    #[test]
    fn rows_reflowed_by_a_narrower_terminal_are_erased_whole() {
        let mut wide = Screen::new(20, 10);
        let mut drawn = Vec::new();
        draw(&mut wide, &mut drawn, rows(&["0123456789abcdef", "status"]));
        // The terminal reflows the 16-column row onto two rows of 10.
        let mut narrow = Screen::new(10, 10);
        narrow.feed("0123456789abcdef\r\nstatus");

        draw(&mut narrow, &mut drawn, rows(&["fresh", "status 2"]));

        assert_eq!(narrow.text(), ["fresh", "status 2"]);
    }

    #[test]
    fn a_region_taller_than_the_terminal_keeps_its_last_rows() {
        let fitted = fit_height(rows(&["a", "b", "c", "d", "e"]), 20, 3);

        assert_eq!(fitted, ["c", "d", "e"]);
    }

    #[test]
    fn styling_does_not_count_toward_a_rows_width() {
        assert_eq!(screen_rows("\u{1b}[32m0123456789\u{1b}[0m", 10), 1);
        assert_eq!(screen_rows("", 10), 1);
        assert_eq!(screen_rows("01234567890", 10), 2);
    }
}
