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

const COMPARE_CHUNK_BYTES: usize = 64 * 1024;

/// Whether the destination already holds exactly what `lpm add` would write:
/// the rewritten text of a JavaScript or TypeScript file, or the bytes of
/// any other source file.
fn destination_matches_incoming(
    source_path: &Path,
    target_path: &Path,
    new_content: Option<&str>,
) -> Result<bool, LpmError> {
    let target_len = target_path.metadata()?.len();
    match new_content {
        Some(text) => {
            if target_len != text.len() as u64 {
                return Ok(false);
            }
            Ok(same_contents(
                std::fs::File::open(target_path)?,
                text.as_bytes(),
            )?)
        }
        None => {
            if target_len != source_path.metadata()?.len() {
                return Ok(false);
            }
            Ok(same_contents(
                std::fs::File::open(target_path)?,
                std::fs::File::open(source_path)?,
            )?)
        }
    }
}

fn same_contents(mut left: impl Read, mut right: impl Read) -> std::io::Result<bool> {
    let mut left_chunk = vec![0_u8; COMPARE_CHUNK_BYTES];
    let mut right_chunk = vec![0_u8; COMPARE_CHUNK_BYTES];
    loop {
        let left_read = read_chunk(&mut left, &mut left_chunk)?;
        let right_read = read_chunk(&mut right, &mut right_chunk)?;
        if left_chunk[..left_read] != right_chunk[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

/// Fills `chunk` unless the reader ends first, so two readers of the same
/// bytes yield chunks of the same length.
fn read_chunk(reader: &mut impl Read, chunk: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < chunk.len() {
        match reader.read(&mut chunk[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Handle a file conflict when the destination already exists.
///
/// Compares content and prompts the user with diff preview when interactive.
pub(super) fn handle_file_conflict(
    source_path: &Path,
    target_path: &Path,
    new_content: Option<&str>,
    force: bool,
    yes: bool,
    json_output: bool,
) -> Result<ConflictAction, LpmError> {
    if force {
        return Ok(ConflictAction::Overwrite);
    }

    if destination_matches_incoming(source_path, target_path, new_content)? {
        return Ok(ConflictAction::Skip);
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
    use std::path::PathBuf;

    fn files(source: &[u8], target: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("incoming.css");
        let target_path = directory.path().join("existing.css");
        std::fs::write(&source_path, source).unwrap();
        std::fs::write(&target_path, target).unwrap();
        (directory, source_path, target_path)
    }

    #[test]
    fn an_identical_file_that_is_not_rewritten_matches() {
        let contents = b".card { color: red }\n".repeat(10_000);
        let (_directory, source, target) = files(&contents, &contents);

        assert!(destination_matches_incoming(&source, &target, None).unwrap());
    }

    #[test]
    fn a_file_that_is_not_rewritten_and_differs_does_not_match() {
        let (_directory, source, target) = files(b".card { color: red }", b".card { color: tan }");
        assert!(!destination_matches_incoming(&source, &target, None).unwrap());

        let (_directory, source, target) = files(b".card {}", b".card {}\n.extra {}");
        assert!(!destination_matches_incoming(&source, &target, None).unwrap());
    }

    #[test]
    fn rewritten_text_is_compared_instead_of_the_source_file() {
        let (_directory, source, target) = files(b"import x from '~/x'", b"import x from '@/x'");

        assert!(
            destination_matches_incoming(&source, &target, Some("import x from '@/x'")).unwrap()
        );
        assert!(
            !destination_matches_incoming(&source, &target, Some("import x from '#/x'")).unwrap()
        );
    }

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
