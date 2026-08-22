use crate::prompt::prompt_err;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use std::io::Read;
use std::path::Path;

/// Result of handling a file conflict.
pub(super) enum ConflictAction {
    Skip,
    Overwrite,
}

fn read_existing_conflict_bytes(
    target_path: &Path,
    new_content: Option<&str>,
) -> Result<Vec<u8>, LpmError> {
    if new_content.is_some() {
        std::fs::read(target_path).map_err(LpmError::Io)
    } else {
        Ok(Vec::new())
    }
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

    if let Some(new_text) = new_content {
        let expected = new_text.as_bytes();
        if target_path.metadata()?.len() == expected.len() as u64 {
            let mut file = std::fs::File::open(target_path)?;
            let mut offset = 0;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    return Ok(ConflictAction::Skip);
                }
                if buffer[..read] != expected[offset..offset + read] {
                    break;
                }
                offset += read;
            }
        }
    }

    if yes || json_output || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Ok(ConflictAction::Skip);
    }

    let existing_bytes = read_existing_conflict_bytes(target_path, new_content)?;

    // Show diff preview
    let rel_display = target_path.file_name().map_or_else(
        || target_path.display().to_string(),
        |n| n.to_string_lossy().to_string(),
    );

    eprintln!("{}", format_file_conflict_header(&rel_display));

    // Show a brief line-count diff summary
    if let Some(new_text) = new_content {
        let existing_text = String::from_utf8_lossy(&existing_bytes);
        let mut old_lines = existing_text.lines();
        let mut new_lines = new_text.lines();
        let mut added = 0usize;
        let mut removed = 0usize;
        loop {
            let old_line = old_lines.next();
            let new_line = new_lines.next();
            if old_line.is_none() && new_line.is_none() {
                break;
            }
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
    fn conflict_preview_reads_the_existing_destination_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("Source.ts");
        std::fs::write(&target, b"existing destination").unwrap();

        let bytes = read_existing_conflict_bytes(&target, Some("incoming source text")).unwrap();

        assert_eq!(bytes, b"existing destination");
    }

    #[test]
    fn file_conflict_header_uses_slim_warning_glyph() {
        lpm_common::color::set_enabled(false);

        assert_eq!(
            format_file_conflict_header("button.tsx"),
            "\n  ! File exists: button.tsx"
        );
    }
}
