use console::{Key, Term, measure_text_width};
use lpm_common::color::Painted;
use std::io::{self, Write};

/// One on/off setting of a [`run_toggles`] editor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Toggle {
    pub(super) title: &'static str,
    pub(super) detail: &'static str,
    pub(super) enabled: bool,
}

/// Runs an editor over `toggles`: arrows move, left, right or space flip,
/// Enter saves and Esc cancels. Returns the toggles as saved.
pub(super) fn run_toggles(
    term: &mut Term,
    prompt: &str,
    help: &str,
    mut toggles: Vec<Toggle>,
) -> io::Result<Vec<Toggle>> {
    run(term, |term| {
        let count = toggles.len().max(1);
        let mut cursor = 0;
        let mut previous_line_count = 0;
        loop {
            let frame = format_toggle_frame(prompt, help, &toggles, cursor);
            draw_frame(term, &frame, &mut previous_line_count)?;
            match term.read_key()? {
                Key::ArrowUp | Key::Char('k') => cursor = (cursor + count - 1) % count,
                Key::ArrowDown | Key::Char('j') => cursor = (cursor + 1) % count,
                Key::ArrowLeft
                | Key::ArrowRight
                | Key::Char('h')
                | Key::Char('l')
                | Key::Char(' ') => {
                    if let Some(toggle) = toggles.get_mut(cursor) {
                        toggle.enabled = !toggle.enabled;
                    }
                }
                Key::Enter => return Ok(toggles),
                Key::Escape | Key::CtrlC => return Err(io::ErrorKind::Interrupted.into()),
                _ => {}
            }
        }
    })
}

pub(super) fn format_toggle_frame(
    prompt: &str,
    help: &str,
    toggles: &[Toggle],
    cursor: usize,
) -> String {
    let mut frame = String::with_capacity(360 * toggles.len().max(1));
    frame.push_str(&format!("◆  {}\n", prompt.cyan().bold()));
    frame.push_str(&format!("│  {}\n", help.dimmed()));
    frame.push_str("│\n");
    for (index, toggle) in toggles.iter().enumerate() {
        let active = index == cursor;
        let marker = if active {
            "›".cyan().bold()
        } else {
            " ".to_string()
        };
        let title = if active {
            toggle.title.bold()
        } else {
            toggle.title.to_string()
        };
        frame.push_str(&format!("│  {marker} {title}\n"));
        frame.push_str(&format!("│    {}\n", toggle.detail.dimmed()));
        frame.push_str(&format!("│    {}\n", format_bool_options(toggle.enabled)));
        if index + 1 < toggles.len() {
            frame.push_str("│\n");
        }
    }
    frame.push_str("└\n");
    frame
}

fn format_bool_options(enabled: bool) -> String {
    if enabled {
        format!("{} {}  ○ Disabled", "●".cyan(), "Enabled".bold())
    } else {
        format!("○ Enabled  {} {}", "●".cyan(), "Disabled".bold())
    }
}

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
