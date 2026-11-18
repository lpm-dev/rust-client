//! Reading colored terminal output the way a person sees it.

/// `output` without its escape sequences: SGR colors (`ESC [ … m`) and
/// OSC hyperlinks (`ESC ] … ESC \` or `… BEL`).
pub fn visible_text(output: &str) -> String {
    let mut visible = String::with_capacity(output.len());
    let mut chars = output.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\u{1b}' {
            visible.push(character);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for code in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&code) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(code) = chars.next() {
                    if code == '\u{7}' || (code == '\u{1b}' && chars.next_if_eq(&'\\').is_some()) {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    visible
}

/// The screen column where `needle` starts in a line of visible text.
pub fn column_of(line: &str, needle: &str) -> usize {
    let start = line
        .find(needle)
        .unwrap_or_else(|| panic!("{needle:?} not in {line:?}"));
    line[..start].chars().count()
}

/// The visible line that contains `needle`.
pub fn line_with<'a>(visible: &'a str, needle: &str) -> &'a str {
    visible
        .lines()
        .find(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("no line contains {needle:?} in:\n{visible}"))
}
