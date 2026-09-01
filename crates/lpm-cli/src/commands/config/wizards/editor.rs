use console::{Term, measure_text_width};
use std::io::{self, Write};

pub(super) fn run<T>(
    term: &mut Term,
    interact: impl FnOnce(&mut Term) -> io::Result<T>,
) -> io::Result<T> {
    if !term.is_term() {
        return Err(io::ErrorKind::NotConnected.into());
    }

    term.hide_cursor()?;
    let result = interact(term);
    let show_cursor_result = term.show_cursor();
    match (result, show_cursor_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

pub(super) fn draw_frame(
    term: &mut Term,
    frame: &str,
    previous_line_count: &mut usize,
) -> io::Result<()> {
    if *previous_line_count > 0 {
        term.clear_last_lines(*previous_line_count)?;
    }
    term.write_all(frame.as_bytes())?;
    term.flush()?;
    *previous_line_count = rendered_line_count(frame, usize::from(term.size().1).max(1));
    Ok(())
}

fn rendered_line_count(frame: &str, terminal_width: usize) -> usize {
    let terminal_width = terminal_width.max(1);
    frame
        .lines()
        .map(|line| {
            let width = measure_text_width(line);
            width.saturating_sub(1) / terminal_width + 1
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_line_count_accounts_for_wrapped_terminal_rows() {
        assert_eq!(rendered_line_count("12345\n123456", 5), 3);
    }
}
