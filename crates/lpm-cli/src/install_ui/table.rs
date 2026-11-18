//! Aligned columns for human-readable tables.
//!
//! Every column is as wide as its widest cell, measured in screen columns,
//! so styled cells line up with plain ones and a long name widens its column
//! instead of pushing the rest of its row out of line. A row's last cell is
//! never padded, so no line ends in spaces.

use std::io::IsTerminal;

use super::{TerminalFragment, TerminalLine, dim};

/// How a column places text narrower than the column.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Align {
    #[default]
    Left,
    Right,
}

/// Rows of cells laid out in aligned columns, with full-width lines (such
/// as a sub-heading) between them that take no part in the column widths.
#[derive(Debug)]
pub struct Table {
    indent: usize,
    gap: usize,
    alignments: Vec<Align>,
    rows: Vec<Row>,
}

#[derive(Debug)]
enum Row {
    Cells(Vec<Cell>),
    Line(TerminalLine),
}

#[derive(Debug)]
struct Layout {
    widths: Vec<usize>,
    occupied: Vec<bool>,
}

#[derive(Debug)]
struct Cell {
    text: TerminalFragment,
    width: usize,
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    /// A table indented by two columns, with two columns between cells.
    pub fn new() -> Self {
        Self {
            indent: 2,
            gap: 2,
            alignments: Vec::new(),
            rows: Vec::new(),
        }
    }

    /// Sets the columns before each row.
    pub fn indent(mut self, indent: usize) -> Self {
        self.indent = indent;
        self
    }

    /// Sets the columns between two cells of a row.
    pub fn gap(mut self, gap: usize) -> Self {
        self.gap = gap;
        self
    }

    /// Right-aligns `column` (counted from zero). Columns are left-aligned
    /// by default.
    pub fn align_right(mut self, column: usize) -> Self {
        if self.alignments.len() <= column {
            self.alignments.resize(column + 1, Align::Left);
        }
        self.alignments[column] = Align::Right;
        self
    }

    /// Appends a dimmed header row.
    pub fn header(&mut self, labels: &[&'static str]) {
        self.row(labels.iter().map(|label| dim(label)));
    }

    /// Appends a row of cells. A row may have fewer cells than the table has
    /// columns, and empty cells at its end are dropped; its last cell then
    /// ends the line.
    pub fn row(&mut self, cells: impl IntoIterator<Item = TerminalFragment>) {
        let mut cells: Vec<Cell> = cells
            .into_iter()
            .map(|text| Cell {
                width: text.visible_width(),
                text,
            })
            .collect();
        while cells.last().is_some_and(|cell| cell.width == 0) {
            cells.pop();
        }
        self.rows.push(Row::Cells(cells));
    }

    /// Appends a line printed as it is, at no indent, outside the columns.
    pub fn line(&mut self, line: TerminalLine) {
        self.rows.push(Row::Line(line));
    }

    /// Lays the rows out in aligned columns.
    ///
    /// With `max_width` (the terminal's width), the rows that fit it set the
    /// column widths, as long as at least half of them do. A row that can't
    /// fit then sets only its first column, so one long value doesn't push
    /// every other row past the edge. A row too wide to fit moves its last
    /// cell to the next line: under the rightmost earlier column it fits
    /// under, or else ending at the right edge, so it reads as the end of the
    /// row above rather than a row of its own. Only a cell wider than the
    /// terminal still wraps; it starts just inside the row.
    pub fn render(&self, max_width: Option<usize>) -> Vec<TerminalLine> {
        let layout = self.layout(max_width);
        let mut lines = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            match row {
                Row::Line(line) => lines.push(line.clone()),
                Row::Cells(cells) => self.render_cells(cells, &layout, max_width, &mut lines),
            }
        }
        lines
    }

    /// Prints the table to stdout, fitted to the terminal when stdout is one.
    pub fn print_stdout(&self) {
        for line in self.render(stdout_columns()) {
            println!("{line}");
        }
    }

    /// Prints the table as slim-UI detail rows on stderr, fitted to the
    /// terminal when stderr is one.
    pub fn print_stderr(&self) {
        for line in self.render(stderr_columns()) {
            super::detail_line(line);
        }
    }

    fn alignment(&self, column: usize) -> Align {
        self.alignments.get(column).copied().unwrap_or_default()
    }

    /// The width of each column and whether any row holds something in it.
    ///
    /// A cell sets its column's width unless it ends its row in a
    /// left-aligned column, where nothing after it needs to line up. When the
    /// rows are fitted to `max_width` and at least half of them fit, a row
    /// that doesn't sets only its first column.
    fn layout(&self, max_width: Option<usize>) -> Layout {
        let rows: Vec<&[Cell]> = self
            .rows
            .iter()
            .filter_map(|row| match row {
                Row::Cells(cells) => Some(cells.as_slice()),
                Row::Line(_) => None,
            })
            .collect();
        let columns = rows.iter().map(|cells| cells.len()).max().unwrap_or(0);
        let mut occupied = vec![false; columns];
        for cells in &rows {
            for (column, cell) in cells.iter().enumerate() {
                occupied[column] |= cell.width > 0;
            }
        }

        let fits = |cells: &[Cell]| max_width.is_none_or(|max| self.own_width(cells) <= max);
        let fitting = rows.iter().filter(|cells| fits(cells)).count();
        let fitted = max_width.is_some() && fitting * 2 >= rows.len();
        let mut widths = vec![0; columns];
        for cells in &rows {
            let sets_every_column = !fitted || fits(cells);
            let last = cells.len().saturating_sub(1);
            for (column, cell) in cells.iter().enumerate() {
                if column == last && self.alignment(column) == Align::Left {
                    continue;
                }
                if !sets_every_column
                    && (column > 0 || max_width.is_some_and(|max| self.indent + cell.width > max))
                {
                    continue;
                }
                widths[column] = widths[column].max(cell.width);
            }
        }
        Layout { widths, occupied }
    }

    /// The columns a row takes with no padding at all.
    fn own_width(&self, cells: &[Cell]) -> usize {
        self.indent
            + cells.iter().map(|cell| cell.width).sum::<usize>()
            + self.gap * cells.len().saturating_sub(1)
    }

    fn render_cells(
        &self,
        cells: &[Cell],
        layout: &Layout,
        max_width: Option<usize>,
        lines: &mut Vec<TerminalLine>,
    ) {
        let widths = layout.widths.as_slice();
        let Some((last, leading)) = cells.split_last() else {
            lines.push(TerminalLine::new(""));
            return;
        };
        let mut rendered = String::with_capacity(
            self.indent
                + cells
                    .iter()
                    .map(|cell| cell.text.len() + self.gap)
                    .sum::<usize>(),
        );
        push_spaces(&mut rendered, self.indent);
        let mut column_starts = Vec::with_capacity(cells.len());
        let mut column_start = self.indent;
        let mut position = self.indent;
        for (column, cell) in leading.iter().enumerate() {
            column_starts.push(column_start);
            if !layout.occupied[column] {
                continue;
            }
            let width = widths[column];
            self.push_cell(&mut rendered, column, cell, width);
            push_spaces(&mut rendered, self.gap);
            column_start += width + self.gap;
            position += width.max(cell.width) + self.gap;
        }

        let last_column = leading.len();
        let last_width = if self.alignment(last_column) == Align::Right {
            widths.get(last_column).copied().unwrap_or(last.width)
        } else {
            last.width
        };
        let Some(max) = max_width.filter(|max| position + last_width > *max) else {
            self.push_cell(&mut rendered, last_column, last, last_width);
            lines.push(TerminalLine::from_rendered(rendered));
            return;
        };
        if leading.is_empty() {
            self.push_cell(&mut rendered, last_column, last, last_width);
            lines.push(TerminalLine::from_rendered(rendered));
            return;
        }

        rendered.truncate(rendered.trim_end_matches(' ').len());
        lines.push(TerminalLine::from_rendered(rendered));
        let start = column_starts[1..]
            .iter()
            .rev()
            .copied()
            .find(|start| start + last_width <= max)
            .unwrap_or(match max.checked_sub(last_width) {
                Some(flush_right) => flush_right,
                None => self.indent + self.gap,
            });
        let mut continuation = String::with_capacity(start + last.text.len());
        push_spaces(&mut continuation, start);
        self.push_cell(&mut continuation, last_column, last, last_width);
        lines.push(TerminalLine::from_rendered(continuation));
    }

    fn push_cell(&self, rendered: &mut String, column: usize, cell: &Cell, width: usize) {
        let padding = width.saturating_sub(cell.width);
        match self.alignment(column) {
            Align::Left => {
                rendered.push_str(&cell.text);
                push_spaces(rendered, padding);
            }
            Align::Right => {
                push_spaces(rendered, padding);
                rendered.push_str(&cell.text);
            }
        }
    }
}

#[inline]
fn push_spaces(rendered: &mut String, count: usize) {
    rendered.extend(std::iter::repeat_n(' ', count));
}

/// The terminal's width when stdout is a terminal. Output piped elsewhere
/// isn't fitted to any width.
pub fn stdout_columns() -> Option<usize> {
    std::io::stdout()
        .is_terminal()
        .then(|| usize::from(crate::live_region::terminal_size().0))
}

/// The terminal's width when stderr is a terminal.
pub fn stderr_columns() -> Option<usize> {
    std::io::stderr()
        .is_terminal()
        .then(|| usize::from(crate::live_region::terminal_size().0))
}

#[cfg(test)]
mod tests {
    use super::{Table, TerminalFragment, TerminalLine};

    fn styled(text: &str) -> TerminalFragment {
        TerminalFragment(format!("\x1b[36m{text}\x1b[39m"))
    }

    fn plain(text: &str) -> TerminalFragment {
        TerminalFragment(text.to_owned())
    }

    fn visible(lines: &[TerminalLine]) -> Vec<String> {
        lines
            .iter()
            .map(|line| console::strip_ansi_codes(line).into_owned())
            .collect()
    }

    #[test]
    fn columns_take_the_width_of_their_widest_cell() {
        let mut table = Table::new();
        table.row([plain("save-prefix"), plain("^"), plain("default")]);
        table.row([plain("save-exact"), plain("false"), plain("default")]);

        assert_eq!(
            visible(&table.render(None)),
            [
                "  save-prefix  ^      default",
                "  save-exact   false  default",
            ]
        );
    }

    #[test]
    fn styled_cells_line_up_with_plain_cells() {
        let mut table = Table::new().indent(0);
        table.row([styled("lpm_ai_telemetry"), plain("warn")]);
        table.row([plain("critical_vulnerability"), styled("warn")]);

        assert_eq!(
            visible(&table.render(None)),
            [
                "lpm_ai_telemetry        warn",
                "critical_vulnerability  warn",
            ]
        );
    }

    #[test]
    fn last_cells_end_lines_without_trailing_spaces() {
        let mut table = Table::new().indent(0);
        table.row([plain("a"), plain("short")]);
        table.row([plain("b"), plain("much longer")]);

        for line in visible(&table.render(None)) {
            assert_eq!(line, line.trim_end(), "line {line:?} ends in spaces");
        }
    }

    #[test]
    fn empty_cells_at_the_end_of_a_row_leave_no_trailing_spaces() {
        let mut table = Table::new().indent(0);
        table.row([plain("react"), plain("patch"), plain("")]);
        table.row([plain("zod"), plain("major"), plain("install scripts")]);

        assert_eq!(
            visible(&table.render(None)),
            ["react  patch", "zod    major  install scripts"]
        );
    }

    #[test]
    fn a_column_empty_in_every_row_takes_no_space() {
        let mut table = Table::new().indent(0);
        table.row([plain("ok"), plain(""), plain("command found")]);
        table.row([plain("warn"), plain(""), plain("slow")]);

        assert_eq!(
            visible(&table.render(None)),
            ["ok    command found", "warn  slow"]
        );
    }

    #[test]
    fn a_row_too_wide_to_fit_does_not_widen_the_columns_of_rows_that_fit() {
        let long_value = "x".repeat(70);
        let mut table = Table::new();
        table.row([
            plain("release-age-policy"),
            plain("direct"),
            plain("default"),
        ]);
        table.row([
            plain("minimum-release-age-exclude"),
            plain(&long_value),
            plain("~/.lpm/config.toml"),
        ]);
        table.row([plain("sigstore.verify"), plain("deny"), plain("default")]);

        assert_eq!(
            visible(&table.render(Some(60))),
            [
                "  release-age-policy           direct  default".to_owned(),
                format!("  minimum-release-age-exclude  {long_value}"),
                format!("{}~/.lpm/config.toml", " ".repeat(31)),
                "  sigstore.verify              deny    default".to_owned(),
            ]
        );
    }

    #[test]
    fn rows_that_mostly_overflow_keep_every_column_at_its_widest_cell() {
        let mut table = Table::new();
        table.row([plain("a"), plain(&"x".repeat(30)), plain("s")]);
        table.row([plain("b"), plain(&"y".repeat(30)), plain("s")]);
        table.row([plain("c"), plain("z"), plain("s")]);

        let lines = visible(&table.render(Some(30)));

        assert_eq!(
            lines[4..],
            ["  c  z".to_owned(), format!("{}s", " ".repeat(5))]
        );
    }

    #[test]
    fn a_column_holding_only_a_shorter_rows_last_cell_keeps_its_place() {
        let mut table = Table::new();
        table.row([plain("a"), plain(""), plain("c")]);
        table.row([plain("d"), plain("b")]);

        assert_eq!(visible(&table.render(None)), ["  a    c", "  d  b"]);
    }

    #[test]
    fn a_shorter_row_does_not_widen_the_column_it_ends_in() {
        let mut table = Table::new().indent(0);
        table.row([plain("firewall.npm.policies")]);
        table.row([plain("  mode"), plain("block")]);

        assert_eq!(
            visible(&table.render(None)),
            ["firewall.npm.policies", "  mode  block"]
        );
    }

    #[test]
    fn right_aligned_columns_pad_on_the_left() {
        let mut table = Table::new().indent(0).align_right(1);
        table.header(&["Environment", "Variables"]);
        table.row([plain("production"), plain("7")]);
        table.row([plain("dev"), plain("12")]);

        assert_eq!(
            visible(&table.render(None)),
            [
                "Environment  Variables",
                "production           7",
                "dev                 12",
            ]
        );
    }

    #[test]
    fn full_width_lines_take_no_part_in_column_widths() {
        let mut table = Table::new();
        table.line(TerminalLine::new(
            "a very long heading that is wider than every row",
        ));
        table.row([plain("a"), plain("1")]);
        table.row([plain("bb"), plain("2")]);

        assert_eq!(
            visible(&table.render(None)),
            [
                "a very long heading that is wider than every row",
                "  a   1",
                "  bb  2",
            ]
        );
    }

    #[test]
    fn a_row_too_wide_for_the_terminal_moves_its_last_cell_under_an_earlier_column() {
        let mut table = Table::new();
        table.row([plain("lpm_ai_telemetry"), plain("warn"), plain("config")]);
        table.row([
            plain("critical"),
            plain("warn"),
            plain("~/.lpm/config.toml via lpm_ai_suspicious"),
        ]);

        assert_eq!(
            visible(&table.render(Some(64))),
            [
                "  lpm_ai_telemetry  warn  config",
                "  critical          warn",
                "                    ~/.lpm/config.toml via lpm_ai_suspicious",
            ]
        );
    }

    #[test]
    fn a_wrapped_cell_that_fits_under_no_column_ends_at_the_right_edge() {
        let mut table = Table::new();
        table.row([
            plain("install-time-source-analysis"),
            plain("false"),
            plain("approved security posture"),
        ]);

        assert_eq!(
            visible(&table.render(Some(40))),
            [
                "  install-time-source-analysis  false",
                "               approved security posture",
            ]
        );
    }

    #[test]
    fn a_wrapped_cell_that_fits_the_terminal_never_overflows_it() {
        let mut table = Table::new();
        table.row([plain("key"), plain(&"x".repeat(38))]);

        assert_eq!(
            visible(&table.render(Some(40))),
            ["  key".to_owned(), format!("  {}", "x".repeat(38))]
        );
    }

    #[test]
    fn a_wrapped_right_aligned_cell_keeps_its_column_width() {
        let mut table = Table::new().align_right(1);
        table.row([plain("installed packages"), plain("7")]);
        table.row([plain("cached"), plain("1234")]);

        assert_eq!(
            visible(&table.render(Some(25))),
            [
                "  installed packages".to_owned(),
                format!("{}7", " ".repeat(24)),
                "  cached".to_owned(),
                format!("{}1234", " ".repeat(21)),
            ]
        );
    }

    #[test]
    fn a_wrapped_cell_wider_than_the_terminal_starts_just_inside_the_row() {
        let mut table = Table::new();
        table.row([plain("key"), plain("value"), plain(&"x".repeat(50))]);

        assert_eq!(
            visible(&table.render(Some(20))),
            ["  key  value".to_owned(), format!("    {}", "x".repeat(50))]
        );
    }

    #[test]
    fn rows_that_fit_are_not_wrapped() {
        let mut table = Table::new();
        table.row([plain("key"), plain("value"), plain("source")]);

        assert_eq!(visible(&table.render(Some(24))), ["  key  value  source"]);
    }

    #[test]
    fn wide_characters_take_two_columns() {
        let mut table = Table::new().indent(0);
        table.row([plain("日本"), plain("x")]);
        table.row([plain("abcde"), plain("y")]);

        assert_eq!(visible(&table.render(None)), ["日本   x", "abcde  y"]);
    }
}
