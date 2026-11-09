//! The quality checks `lpm publish` runs on the tarball it uploads to
//! LPM.dev Registry: the archive checks the registry runs on every
//! release, from the same code, and the registry's own checks, which only
//! run after the publish.

use super::types::PublishQualityGateInput;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_security::behavioral::release::analyze_release_quality;
use lpm_security::quality::{
    Category, CheckResult, CheckSpec, CheckStatus, Decider, QualityEcosystem, QualityReport, spec,
};

pub(crate) fn run_publish_quality_gate(
    input: PublishQualityGateInput<'_>,
) -> Result<QualityReport, LpmError> {
    let ecosystem = quality_ecosystem(input.detected_ecosystem);
    let report = analyze_release_quality(input.tarball, ecosystem, input.swift_manifest)?;
    if !input.json_output {
        if input.check_only {
            print_quality_checks(&report);
        } else {
            print_quality_summary(&report);
        }
    }
    if let Some(minimum) = input.min_score {
        enforce_minimum_score(&report, minimum)?;
    }
    Ok(report)
}

fn quality_ecosystem(detected: &str) -> QualityEcosystem {
    match detected {
        "swift" => QualityEcosystem::Swift,
        _ => QualityEcosystem::Js,
    }
}

/// The archive points as a share of the points the archive checks are
/// worth, out of 100 and rounded down: what the publish knows before the
/// registry scores the rest. Rounding down keeps a release from showing, or
/// passing `--min-score` with, a share it didn't reach.
pub(crate) fn preflight_score(report: &QualityReport) -> u32 {
    let (earned, max) = report.archive_points();
    if max == 0 {
        return 0;
    }
    earned.saturating_mul(100) / max
}

fn registry_points(ecosystem: QualityEcosystem) -> u32 {
    spec::checks(ecosystem)
        .filter(|spec| spec.decider == Decider::Registry)
        .map(|spec| spec.max_points)
        .sum()
}

fn enforce_minimum_score(report: &QualityReport, minimum: u32) -> Result<(), LpmError> {
    let score = preflight_score(report);
    if score < minimum {
        let (earned, max) = report.archive_points();
        return Err(LpmError::Registry(format!(
            "local preflight quality score {score} is below minimum {minimum} ({earned} of {max} archive points; LPM.dev Registry checks {} more after publish; use --min-score to adjust)",
            registry_points(report.ecosystem)
        )));
    }
    Ok(())
}

fn headline(report: &QualityReport) -> String {
    let (earned, max) = report.archive_points();
    format!(
        "Quality score: {earned}/{max} archive points; LPM.dev Registry checks {} more after publish",
        registry_points(report.ecosystem)
    )
}

/// The headline, then a warning for each archive check that lost points.
pub(crate) fn print_quality_summary(report: &QualityReport) {
    install_ui::done_untrusted(&headline(report));
    for check in report
        .checks
        .iter()
        .filter(|check| check.status != CheckStatus::Passed)
    {
        let label = spec::check(report.ecosystem, check.id).map_or(check.id, |spec| spec.label);
        install_ui::warn_line(crate::install_ui::terminal_line!(
            "{}  {}",
            label,
            install_ui::dim(&format!(
                "{}/{} · {}",
                check.points, check.max_points, check.detail
            ))
        ));
    }
}

/// Every check by category: archive results with how to earn missing
/// points, and the registry's checks with what earns them.
pub(crate) fn print_quality_checks(report: &QualityReport) {
    install_ui::done_untrusted(&headline(report));
    let label_width = spec::checks(report.ecosystem)
        .map(|spec| spec.label.chars().count())
        .max()
        .unwrap_or(0);
    for category in Category::ALL {
        let specs: Vec<&CheckSpec> = spec::checks(report.ecosystem)
            .filter(|spec| spec.category == category)
            .collect();
        let earned: u32 = report
            .checks
            .iter()
            .filter(|check| check.category == category)
            .map(|check| check.points)
            .sum();
        let archive_max: u32 = specs
            .iter()
            .filter(|spec| spec.decider == Decider::Archive)
            .map(|spec| spec.max_points)
            .sum();
        let registry_max: u32 = specs
            .iter()
            .filter(|spec| spec.decider == Decider::Registry)
            .map(|spec| spec.max_points)
            .sum();
        let totals = match (archive_max, registry_max) {
            (0, registry) => format!("{registry} checked after publish"),
            (archive, 0) => format!("{earned}/{archive}"),
            (archive, registry) => {
                format!("{earned}/{archive} (+{registry} checked after publish)")
            }
        };
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::section(category.label()),
            install_ui::dim(&totals)
        ));
        for spec in specs {
            let label = format!("{:<label_width$}", spec.label);
            match report.checks.iter().find(|check| check.id == spec.id) {
                Some(check) => print_archive_check(&label, spec, check),
                None => {
                    install_ui::detail_line(crate::install_ui::terminal_line!(
                        "    {} {}  {}",
                        install_ui::dim("◦"),
                        label,
                        install_ui::dim(&format!(
                            "{:>5}  checked by LPM.dev Registry after publish",
                            format!("–/{}", spec.max_points)
                        ))
                    ));
                    print_tip(spec.tip);
                }
            }
        }
    }
}

fn print_archive_check(label: &str, spec: &CheckSpec, check: &CheckResult) {
    let points = format!("{:>5}", format!("{}/{}", check.points, check.max_points));
    let (icon, points) = match check.status {
        CheckStatus::Passed => (install_ui::green("✓"), install_ui::green(&points)),
        CheckStatus::Partial => (install_ui::yellow("◐"), install_ui::yellow(&points)),
        CheckStatus::Failed => (install_ui::red("✗"), install_ui::dim(&points)),
        CheckStatus::Pending => (install_ui::dim("◦"), install_ui::dim(&points)),
    };
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "    {} {}  {}  {}",
        icon,
        label,
        points,
        install_ui::dim(&check.detail)
    ));
    if check.status != CheckStatus::Passed {
        print_tip(spec.tip);
    }
}

fn print_tip(tip: &str) {
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "        {}",
        install_ui::dim(tip)
    ));
}

/// The report for `--json`: every check in order, the registry's marked
/// `after_publish`, with the tip of each that lost points.
pub(crate) fn quality_json(report: &QualityReport) -> serde_json::Value {
    let (earned, max) = report.archive_points();
    let checks: Vec<serde_json::Value> = spec::checks(report.ecosystem)
        .map(|spec| match report.checks.iter().find(|check| check.id == spec.id) {
            Some(check) => {
                let mut value = serde_json::json!({
                    "id": check.id,
                    "category": check.category,
                    "label": spec.label,
                    "points": check.points,
                    "maxPoints": check.max_points,
                    "status": check.status,
                    "detail": check.detail,
                });
                if check.status != CheckStatus::Passed {
                    value["tip"] = serde_json::Value::from(spec.tip);
                }
                value
            }
            None => serde_json::json!({
                "id": spec.id,
                "category": spec.category,
                "label": spec.label,
                "points": serde_json::Value::Null,
                "maxPoints": spec.max_points,
                "status": if spec.decider == Decider::Registry { "after_publish" } else { "pending" },
                "tip": spec.tip,
            }),
        })
        .collect();
    serde_json::json!({
        "schemaVersion": report.schema_version,
        "rulesVersion": report.rules_version,
        "ecosystem": report.ecosystem,
        "preflightScore": preflight_score(report),
        "archivePoints": earned,
        "archiveMaxPoints": max,
        "registryMaxPoints": registry_points(report.ecosystem),
        "checks": checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(points: u32) -> QualityReport {
        report_of(points, 100)
    }

    fn report_of(points: u32, max_points: u32) -> QualityReport {
        QualityReport {
            schema_version: 1,
            rules_version: 1,
            ecosystem: QualityEcosystem::Js,
            facts: lpm_security::quality::QualityFacts::default(),
            checks: vec![CheckResult {
                id: "readme",
                category: Category::Documentation,
                points,
                max_points,
                status: CheckStatus::Partial,
                detail: String::new(),
            }],
        }
    }

    #[test]
    fn score_immediately_below_80_fails_an_explicit_threshold_of_80() {
        assert!(enforce_minimum_score(&report(79), 80).is_err());
    }

    #[test]
    fn score_at_80_passes_an_explicit_threshold_of_80() {
        enforce_minimum_score(&report(80), 80).unwrap();
    }

    #[test]
    fn score_immediately_above_80_passes_an_explicit_threshold_of_80() {
        enforce_minimum_score(&report(81), 80).unwrap();
    }

    #[test]
    fn a_share_just_below_the_threshold_doesnt_round_up_to_pass() {
        let report = report_of(66, 83);
        assert_eq!(preflight_score(&report), 79);
        assert!(enforce_minimum_score(&report, 80).is_err());
        enforce_minimum_score(&report_of(67, 83), 80).unwrap();
    }

    #[test]
    fn json_lists_every_check_with_registry_checks_after_publish() {
        let value = quality_json(&report(50));
        let checks = value["checks"].as_array().unwrap();
        assert_eq!(checks.len(), spec::checks(QualityEcosystem::Js).count());
        let skills = checks
            .iter()
            .find(|check| check["id"] == "agent-skills")
            .unwrap();
        assert_eq!(skills["status"], "after_publish");
        assert!(skills["points"].is_null());
        assert_eq!(value["registryMaxPoints"], 17);
        assert_eq!(value["preflightScore"], 50);
    }
}
