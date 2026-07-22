use crate::prompt::prompt_err;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use std::path::Path;

/// Result of handling a file conflict.
pub(super) enum ConflictAction {
    Skip,
    Overwrite,
}

/// Handle a file conflict when the destination already exists.
///
/// Compares content and prompts the user with diff preview when interactive.
pub(super) fn handle_file_conflict(
    _source_path: &Path,
    target_path: &Path,
    new_content: Option<&str>,
    force: bool,
    yes: bool,
    json_output: bool,
) -> Result<ConflictAction, LpmError> {
    if force {
        return Ok(ConflictAction::Overwrite);
    }

    // Read existing content
    let existing_bytes = std::fs::read(target_path)?;

    // Compare: if new_content is Some, compare as text; otherwise compare bytes
    if let Some(new_text) = new_content {
        let existing_text = String::from_utf8_lossy(&existing_bytes);
        if existing_text.as_ref() == new_text {
            return Ok(ConflictAction::Skip); // Identical
        }
    }

    // Non-interactive: skip conflicts
    if yes || json_output || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Ok(ConflictAction::Skip);
    }

    // Show diff preview
    let rel_display = target_path.file_name().map_or_else(
        || target_path.display().to_string(),
        |n| n.to_string_lossy().to_string(),
    );

    eprintln!("{}", format_file_conflict_header(&rel_display));

    // Show a brief line-count diff summary
    if let Some(new_text) = new_content {
        let existing_text = String::from_utf8_lossy(&existing_bytes);
        let old_lines: Vec<&str> = existing_text.lines().collect();
        let new_lines: Vec<&str> = new_text.lines().collect();

        let mut added = 0usize;
        let mut removed = 0usize;
        let max_compare = old_lines.len().max(new_lines.len());
        for i in 0..max_compare {
            let old_line = old_lines.get(i).copied();
            let new_line = new_lines.get(i).copied();
            if old_line != new_line {
                if old_line.is_some() {
                    removed += 1;
                }
                if new_line.is_some() {
                    added += 1;
                }
            }
        }
        eprintln!(
            "    {} lines added, {} lines removed",
            format!("+{added}").green(),
            format!("-{removed}").red()
        );
    }

    let action: &str = cliclack::select("How to handle?")
        .item("skip", "Skip (keep existing)", "")
        .item("overwrite", "Overwrite", "")
        .item("diff", "View full diff", "")
        .initial_value("skip")
        .interact()
        .map_err(prompt_err)?;

    match action {
        "skip" => Ok(ConflictAction::Skip),
        "overwrite" => Ok(ConflictAction::Overwrite),
        "diff" => {
            // Print full diff then re-prompt
            if let Some(new_text) = new_content {
                let existing_text = String::from_utf8_lossy(&existing_bytes);
                eprintln!("\n  --- existing");
                eprintln!("  +++ incoming\n");
                for (i, (old, new)) in existing_text.lines().zip(new_text.lines()).enumerate() {
                    if old != new {
                        eprintln!(
                            "  {:>4} {} {}",
                            i + 1,
                            "-".red(),
                            lpm_common::sanitize_terminal_inline(old).red()
                        );
                        eprintln!(
                            "  {:>4} {} {}",
                            i + 1,
                            "+".green(),
                            lpm_common::sanitize_terminal_inline(new).green()
                        );
                    }
                }
                eprintln!();
            }

            // Re-prompt after showing diff
            let re_action: &str = cliclack::select("How to handle?")
                .item("skip", "Skip (keep existing)", "")
                .item("overwrite", "Overwrite", "")
                .initial_value("skip")
                .interact()
                .map_err(prompt_err)?;

            match re_action {
                "overwrite" => Ok(ConflictAction::Overwrite),
                _ => Ok(ConflictAction::Skip),
            }
        }
        _ => Ok(ConflictAction::Skip),
    }
}

fn format_file_conflict_header(rel_display: &str) -> String {
    format!(
        "\n  {} File exists: {}",
        "!".yellow(),
        lpm_common::sanitize_terminal_inline(rel_display)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_conflict_header_uses_slim_warning_glyph() {
        lpm_common::color::set_enabled(false);

        assert_eq!(
            format_file_conflict_header("button.tsx"),
            "\n  ! File exists: button.tsx"
        );
    }
}
