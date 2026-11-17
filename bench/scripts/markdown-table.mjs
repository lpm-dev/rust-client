/**
 * `value` as the text of one cell in a GitHub-flavoured markdown table.
 * Backslashes are escaped before pipes, so every backslash in the value,
 * including one before a pipe or at the end of a line, renders as itself.
 * Each line break, `\r\n`, `\n` or a lone `\r`, becomes `lineBreak`.
 */
export function markdownTableCell(value, lineBreak = ' ') {
  return String(value).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r\n?|\n/g, lineBreak);
}
