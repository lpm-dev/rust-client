//! Parse an advisor's free-form output into an [`AdvisorVerdict`].
//!
//! The prompt asks for EXACTLY ONE WORD on the final line, but in
//! practice LLMs sometimes prepend explanation or wrap the verdict in
//! markdown. The parser is permissive enough to tolerate that without
//! being so permissive that drifting outputs silently degrade to a
//! safer verdict.
//!
//! Strategy:
//! 1. Scan output lines from the end to the start.
//! 2. For each non-empty trimmed line, strip common markdown/punctuation,
//!    upper-case, look for the first verdict-keyword match.
//! 3. Return the verdict; if no line contains a recognised keyword,
//!    return `IntegrationFailure`.
//!
//! Fail-closed on ambiguity: a line containing both APPROVE and MANUAL
//! returns the worse outcome (Manual) because conflating the two would
//! silently auto-run a script the advisor was uncertain about.

use crate::{AdvisorFailure, AdvisorVerdict};

/// Parse the advisor's stdout into a structured verdict. Returns
/// [`AdvisorFailure::IntegrationFailure`] when no verdict keyword can
/// be recovered.
pub fn parse_verdict(output: &str) -> Result<AdvisorVerdict, AdvisorFailure> {
    for line in output.lines().rev() {
        let cleaned = clean_line(line);
        if cleaned.is_empty() {
            continue;
        }
        if let Some(v) = scan_line(&cleaned) {
            return Ok(v);
        }
    }
    Err(AdvisorFailure::IntegrationFailure(format!(
        "advisor output contained no recognised verdict keyword (APPROVE / MANUAL / ABSTAIN); raw output: {output:?}"
    )))
}

fn clean_line(line: &str) -> String {
    // Strip common markdown bullets / code-fence backticks / leading
    // verdict labels ("Verdict:"). Upper-case the rest for the
    // keyword scan.
    let trimmed = line.trim().trim_matches(|c: char| {
        matches!(
            c,
            '`' | '*' | '_' | '#' | '>' | '-' | '.' | ':' | ' ' | '\t'
        )
    });
    trimmed.to_ascii_uppercase()
}

/// Scan a cleaned uppercase line for verdict keywords. Returns the
/// worst-outcome keyword if multiple appear (Manual > Abstain >
/// Approve), so a contradictory line never silently downgrades.
fn scan_line(upper: &str) -> Option<AdvisorVerdict> {
    let has_approve = contains_keyword(upper, "APPROVE");
    let has_manual = contains_keyword(upper, "MANUAL");
    let has_abstain = contains_keyword(upper, "ABSTAIN");
    if has_manual {
        Some(AdvisorVerdict::Manual)
    } else if has_abstain {
        Some(AdvisorVerdict::Abstain)
    } else if has_approve {
        Some(AdvisorVerdict::Approve)
    } else {
        None
    }
}

/// Whole-word-ish containment: requires the keyword to be present and
/// surrounded by non-letter chars (or string boundary). Avoids
/// matching `DISAPPROVE` as `APPROVE`.
fn contains_keyword(haystack: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(idx) = haystack[start..].find(needle) {
        let pos = start + idx;
        let before_ok = pos == 0
            || !haystack
                .as_bytes()
                .get(pos - 1)
                .is_some_and(u8::is_ascii_alphabetic);
        let end = pos + needle.len();
        let after_ok = end >= haystack.len()
            || !haystack
                .as_bytes()
                .get(end)
                .is_some_and(u8::is_ascii_alphabetic);
        if before_ok && after_ok {
            return true;
        }
        start = pos + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_verdict() {
        assert_eq!(parse_verdict("APPROVE").unwrap(), AdvisorVerdict::Approve);
        assert_eq!(parse_verdict("MANUAL").unwrap(), AdvisorVerdict::Manual);
        assert_eq!(parse_verdict("ABSTAIN").unwrap(), AdvisorVerdict::Abstain);
    }

    #[test]
    fn parses_lowercased_verdict() {
        assert_eq!(parse_verdict("approve").unwrap(), AdvisorVerdict::Approve);
    }

    #[test]
    fn parses_verdict_in_last_line_after_explanation() {
        let output = "The script wraps a require in try/catch and swallows errors.\n\
                      Nothing networked.\n\
                      \n\
                      APPROVE";
        assert_eq!(parse_verdict(output).unwrap(), AdvisorVerdict::Approve);
    }

    #[test]
    fn parses_verdict_with_markdown_decoration() {
        assert_eq!(parse_verdict("**MANUAL**").unwrap(), AdvisorVerdict::Manual);
        assert_eq!(parse_verdict("`APPROVE`").unwrap(), AdvisorVerdict::Approve);
        assert_eq!(
            parse_verdict("Verdict: ABSTAIN").unwrap(),
            AdvisorVerdict::Abstain
        );
    }

    #[test]
    fn scans_from_last_line_back() {
        let output = "Initial thought: APPROVE\n\
                      \n\
                      Wait — it downloads a binary. MANUAL.";
        assert_eq!(parse_verdict(output).unwrap(), AdvisorVerdict::Manual);
    }

    #[test]
    fn returns_manual_when_line_contains_both_keywords() {
        // Contradictory line — fail to worst outcome rather than
        // silently approve.
        assert_eq!(
            parse_verdict("APPROVE or MANUAL").unwrap(),
            AdvisorVerdict::Manual
        );
    }

    #[test]
    fn word_boundary_keeps_disapprove_from_matching() {
        let output = "I DISAPPROVE of this kind of script.";
        assert!(matches!(
            parse_verdict(output),
            Err(AdvisorFailure::IntegrationFailure(_))
        ));
    }

    #[test]
    fn empty_output_is_integration_failure() {
        assert!(matches!(
            parse_verdict(""),
            Err(AdvisorFailure::IntegrationFailure(_))
        ));
        assert!(matches!(
            parse_verdict("\n\n   \n"),
            Err(AdvisorFailure::IntegrationFailure(_))
        ));
    }

    #[test]
    fn unknown_verdict_is_integration_failure() {
        assert!(matches!(
            parse_verdict("MAYBE"),
            Err(AdvisorFailure::IntegrationFailure(_))
        ));
        assert!(matches!(
            parse_verdict("I think it's fine"),
            Err(AdvisorFailure::IntegrationFailure(_))
        ));
    }
}
