use std::fmt::Write as _;
use std::path::Path;

use crate::compare::ComparisonReport;
use crate::error::{Result, VerifierError};

const MARKDOWN_DISCREPANCY_LIMIT: usize = 100;

pub fn write_markdown(path: &Path, report: &ComparisonReport) -> Result<()> {
    let mut output = String::with_capacity(16 * 1024);
    writeln!(output, "# Ecosystem correction verification").expect("write string");
    writeln!(output).expect("write string");
    writeln!(
        output,
        "- Reference: {}",
        code_span(&report.reference_manager)
    )
    .expect("write string");
    writeln!(
        output,
        "- Candidate: {}",
        code_span(&report.candidate_manager)
    )
    .expect("write string");
    writeln!(
        output,
        "- Result: **{}**",
        if report.passed { "PASS" } else { "FAIL" }
    )
    .expect("write string");
    writeln!(
        output,
        "- Errors: {}; warnings: {}",
        report.summary.errors, report.summary.warnings
    )
    .expect("write string");
    writeln!(output).expect("write string");

    writeln!(output, "## Comparison summary").expect("write string");
    writeln!(output).expect("write string");
    writeln!(output, "| Gate | Match | Missing | Extra / mismatch |").expect("write string");
    writeln!(output, "|---|---:|---:|---:|").expect("write string");
    writeln!(
        output,
        "| Importers | {} | {} | {} |",
        report.summary.importer_matches,
        report.summary.importer_missing,
        report.summary.importer_extra
    )
    .expect("write string");
    writeln!(
        output,
        "| Package identities | {} | {} | {} |",
        report.summary.package_identity_matches,
        report.summary.package_identity_missing,
        report.summary.package_identity_extra
    )
    .expect("write string");
    writeln!(
        output,
        "| Direct edge sets | — | — | {} |",
        report.summary.direct_edge_mismatches
    )
    .expect("write string");
    writeln!(
        output,
        "| Dependency edge sets | — | — | {} |",
        report.summary.dependency_edge_mismatches
    )
    .expect("write string");
    writeln!(
        output,
        "| Peer contexts | — | — | {} |",
        report.summary.peer_binding_mismatches
    )
    .expect("write string");
    writeln!(
        output,
        "| Required peers | — | — | {} |",
        report.summary.required_peer_violations
    )
    .expect("write string");
    writeln!(output).expect("write string");

    writeln!(output, "## Peer amplification").expect("write string");
    writeln!(output).expect("write string");
    writeln!(
        output,
        "| Manager | Unique identities | Unique instances | Extra instances | Amplification | Peer bindings |"
    )
    .expect("write string");
    writeln!(output, "|---|---:|---:|---:|---:|---:|").expect("write string");
    for (manager, telemetry) in [
        (
            &report.reference_manager,
            &report.peer_amplification.reference,
        ),
        (
            &report.candidate_manager,
            &report.peer_amplification.candidate,
        ),
    ] {
        writeln!(
            output,
            "| {} | {} | {} | {} | {:.2}× | {} |",
            table_text(manager),
            telemetry.unique_identities,
            telemetry.unique_instances,
            telemetry.additional_peer_instances,
            telemetry.amplification_basis_points as f64 / 10_000.0,
            telemetry.peer_binding_count
        )
        .expect("write string");
    }
    writeln!(output).expect("write string");

    if !report.capability_gaps.is_empty() {
        writeln!(output, "## Candidate evidence gaps").expect("write string");
        writeln!(output).expect("write string");
        for capability in &report.capability_gaps {
            writeln!(output, "- {}", code_span(capability)).expect("write string");
        }
        writeln!(output).expect("write string");
    }

    if !report.compatibility_gaps.is_empty() {
        writeln!(output, "## Unsupported reference policy").expect("write string");
        writeln!(output).expect("write string");
        for gap in &report.compatibility_gaps {
            writeln!(output, "- {}", code_span(gap)).expect("write string");
        }
        writeln!(output).expect("write string");
    }

    writeln!(output, "## Discrepancies").expect("write string");
    writeln!(output).expect("write string");
    if report.discrepancies.is_empty() {
        writeln!(output, "None.").expect("write string");
    } else {
        writeln!(
            output,
            "| Severity | Category | Importer | Subject | Message |"
        )
        .expect("write string");
        writeln!(output, "|---|---|---|---|---|").expect("write string");
        for discrepancy in report.discrepancies.iter().take(MARKDOWN_DISCREPANCY_LIMIT) {
            writeln!(
                output,
                "| {:?} | {} | {} | {} | {} |",
                discrepancy.severity,
                table_code_span(&discrepancy.category),
                table_code_span(discrepancy.importer.as_deref().unwrap_or("—")),
                table_code_span(discrepancy.subject.as_deref().unwrap_or("—")),
                table_text(&discrepancy.message)
            )
            .expect("write string");
        }
        if report.discrepancies.len() > MARKDOWN_DISCREPANCY_LIMIT {
            writeln!(output).expect("write string");
            writeln!(
                output,
                "The Markdown view shows the first {MARKDOWN_DISCREPANCY_LIMIT} discrepancies; the JSON report contains all {}.",
                report.discrepancies.len()
            )
            .expect("write string");
        }
    }

    let parent = path
        .parent()
        .ok_or_else(|| VerifierError::InvalidOutputPath {
            path: path.to_path_buf(),
        })?;
    std::fs::create_dir_all(parent).map_err(|source| VerifierError::Write {
        path: parent.to_path_buf(),
        source,
    })?;
    std::fs::write(path, output).map_err(|source| VerifierError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// `value` as inline code. A backslash can't escape a backtick inside a
/// code span, so the fence is one backtick longer than the value's longest
/// run of them, with a space inside each fence where the value starts or
/// ends with a backtick, or starts and ends with a space. Line breaks become
/// spaces.
fn code_span(value: &str) -> String {
    let value = value.replace(['\r', '\n'], " ");
    let longest_run = value.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest_run + 1);
    let pad = value.starts_with('`')
        || value.ends_with('`')
        || (value.starts_with(' ') && value.ends_with(' ') && !value.trim().is_empty());
    let pad = if pad { " " } else { "" };
    format!("{fence}{pad}{value}{pad}{fence}")
}

/// [`code_span`] in a table cell. GFM splits a row into cells before it
/// parses code spans, so a pipe needs its backslash there too.
fn table_code_span(value: &str) -> String {
    code_span(value).replace('|', "\\|")
}

/// `value` as text in a table cell: backslashes escaped first, so each one
/// renders as itself, then pipes and backticks. Line breaks become spaces.
fn table_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('`', "\\`")
        .replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use crate::canonical::GraphTelemetry;
    use crate::compare::{ComparisonSummary, PeerAmplification, PeerAmplificationComparison};

    use super::*;

    #[test]
    fn markdown_report_is_deterministic_and_escapes_table_cells() {
        let report = ComparisonReport {
            schema_version: 1,
            reference_manager: "pnpm".into(),
            candidate_manager: "lpm".into(),
            passed: false,
            summary: ComparisonSummary {
                errors: 1,
                ..ComparisonSummary::default()
            },
            reference_telemetry: GraphTelemetry::default(),
            candidate_telemetry: GraphTelemetry::default(),
            peer_amplification: PeerAmplificationComparison {
                reference: empty_peer_amplification(),
                candidate: empty_peer_amplification(),
            },
            capability_gaps: vec!["declared_peer_ranges".into()],
            compatibility_gaps: vec!["override debug => npm:obug@^1".into()],
            discrepancies: vec![crate::compare::Discrepancy {
                severity: crate::canonical::DiagnosticSeverity::Error,
                category: "edge|mismatch".into(),
                importer: Some("packages/app".into()),
                subject: Some("a`b".into()),
                message: "first\nsecond C:\\tmp\\".into(),
                expected: None,
                actual: None,
            }],
        };
        let directory = tempfile::tempdir().expect("create output directory");
        let output = directory.path().join("report.md");

        write_markdown(&output, &report).expect("write report");
        let rendered = std::fs::read_to_string(output).expect("read report");

        assert!(rendered.contains("- Reference: `pnpm`"));
        assert!(rendered.contains(
            "| Error | `edge\\|mismatch` | `packages/app` | ``a`b`` | first second C:\\\\tmp\\\\ |"
        ));
        assert!(rendered.contains("- `override debug => npm:obug@^1`"));
    }

    #[test]
    fn code_spans_fence_past_the_longest_backtick_run_and_pad_edge_backticks() {
        assert_eq!(code_span("plain"), "`plain`");
        assert_eq!(code_span("a``b"), "```a``b```");
        assert_eq!(code_span("`a"), "`` `a ``");
        assert_eq!(code_span(" a "), "`  a  `");
        assert_eq!(code_span("two\nlines"), "`two lines`");
    }

    fn empty_peer_amplification() -> PeerAmplification {
        PeerAmplification {
            unique_identities: 0,
            unique_instances: 0,
            additional_peer_instances: 0,
            amplification_basis_points: 0,
            peer_context_instances: 0,
            peer_binding_count: 0,
        }
    }
}
