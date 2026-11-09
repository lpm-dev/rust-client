use crate::install_ui;
use lpm_common::LpmError;
use lpm_registry::{QualityCheck, RegistryClient};
use lpm_security::quality::Category;

pub async fn run(
    client: &RegistryClient,
    package: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let report = client.get_quality(package).await?;
    let state = ReportState::of(&report);
    let available = report
        .available
        .unwrap_or(report.score.is_some() || state != ReportState::Complete);
    // Only a complete report adds its checks up; a registry's totals for any
    // other would add points that checks still waiting have.
    let categories = if state == ReportState::Complete {
        report.categories.as_ref()
    } else {
        None
    };

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "name": report.name,
            "available": available,
            "message": report.message,
            "status": report.status,
            "unavailableReason": report.unavailable_reason,
            "rulesVersion": report.rules_version,
            "score": report.score.filter(|_| state == ReportState::Complete),
            "maxScore": report.max_score,
            "tier": report.tier.as_ref().filter(|_| state == ReportState::Complete),
            "ecosystem": report.ecosystem,
            "categories": categories,
            "published_at": report.published_at,
            "checks": report.checks,
            "count": report.checks.len(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("{}", install_ui::cyan(&report.name));

    if !available {
        println!(
            "{}",
            install_ui::field(
                report
                    .message
                    .as_deref()
                    .unwrap_or("No quality data available.")
            )
        );
        return Ok(());
    }

    match state {
        ReportState::Complete => {
            if let Some(score) = report.score {
                let max = report.max_score.unwrap_or(100);
                let tier = report.tier.as_deref().unwrap_or_else(|| tier_for(score));
                print_field("score", tier_colored(&format!("{score}/{max}"), score));
                print_field("tier", tier_colored(tier_label(tier), score));
            }
        }
        ReportState::Pending => print_field("score", install_ui::dim("Scoring…")),
        ReportState::Unavailable => {
            print_field("score", install_ui::yellow("Score unavailable"));
            if let Some(reason) = report
                .unavailable_reason
                .as_deref()
                .filter(|r| !r.is_empty())
            {
                print_field("reason", install_ui::field(reason));
            }
        }
    }
    if let Some(status) = &report.status {
        print_field("status", install_ui::field(status));
    }
    if let Some(rules) = report.rules_version {
        print_field("rules", install_ui::field(&format!("v{rules}")));
    }
    if let Some(eco) = &report.ecosystem {
        print_field("ecosystem", eco);
    }

    if !report.checks.is_empty() {
        let label_width = report
            .checks
            .iter()
            .map(|check| check.label.as_deref().unwrap_or(&check.id).chars().count())
            .max()
            .unwrap_or(0);
        let groups = category_groups(&report);
        if groups.len() == 1 && groups[0].0.is_none() {
            println!();
            println!("{}", install_ui::section("checks"));
            for check in &report.checks {
                print_check(check, label_width);
            }
        } else {
            for (category, checks) in groups {
                println!();
                let label = category.as_deref().map_or("Other", category_label);
                let totals = category
                    .as_deref()
                    .and_then(|category| category_totals(categories, category));
                match totals {
                    Some((score, max)) => println!(
                        "{}",
                        crate::install_ui::terminal_line!(
                            "{} {}",
                            install_ui::section(label),
                            install_ui::dim(&format!("{score}/{max}"))
                        )
                    ),
                    None => println!("{}", install_ui::section(label)),
                }
                for check in checks {
                    print_check(check, label_width);
                }
            }
        }
    }

    println!();
    install_ui::done("Quality report ready");
    Ok(())
}

/// Where a report stands. A registry from before the four-bar score sends
/// no status, and its reports are complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReportState {
    Complete,
    Pending,
    Unavailable,
}

impl ReportState {
    fn of(report: &lpm_registry::QualityResponse) -> Self {
        match report.status.as_deref() {
            Some("pending") => Self::Pending,
            Some("unavailable") => Self::Unavailable,
            _ => Self::Complete,
        }
    }
}

const CATEGORY_ORDER: &[&str] = &["documentation", "api", "provenance", "health"];

/// A category's name as `lpm publish --check` and the package page show it.
fn category_label(category: &str) -> &str {
    match Category::ALL
        .into_iter()
        .find(|known| known.as_str() == category)
    {
        Some(known) => known.label(),
        None => category,
    }
}

/// The checks grouped by category, the four bars first in their order,
/// then any other category in report order.
fn category_groups(
    report: &lpm_registry::QualityResponse,
) -> Vec<(Option<String>, Vec<&QualityCheck>)> {
    let mut groups: Vec<(Option<String>, Vec<&QualityCheck>)> = Vec::new();
    for check in &report.checks {
        match groups
            .iter_mut()
            .find(|(category, _)| category.as_deref() == check.category.as_deref())
        {
            Some((_, checks)) => checks.push(check),
            None => groups.push((check.category.clone(), vec![check])),
        }
    }
    let rank = |category: &Option<String>| {
        category
            .as_deref()
            .and_then(|name| CATEGORY_ORDER.iter().position(|known| *known == name))
            .unwrap_or(CATEGORY_ORDER.len())
    };
    groups.sort_by_key(|(category, _)| rank(category));
    groups
}

fn category_totals(categories: Option<&serde_json::Value>, category: &str) -> Option<(u64, u64)> {
    let entry = categories?.get(category)?;
    Some((entry.get("score")?.as_u64()?, entry.get("max")?.as_u64()?))
}

fn check_status(check: &QualityCheck) -> &str {
    match check.status.as_deref() {
        Some(status) => status,
        None if check.passed == Some(true) => "passed",
        None => "failed",
    }
}

fn print_check(check: &QualityCheck, label_width: usize) {
    let status = check_status(check);
    let label = format!(
        "{:<label_width$}",
        check.label.as_deref().unwrap_or(&check.id)
    );
    let earned = check.points.unwrap_or(0);
    let points = match check.max_points {
        Some(max) if max > 0 => format!("{earned}/{max}"),
        _ => earned.to_string(),
    };
    let (icon, points) = match status {
        "passed" => (install_ui::green("✓"), install_ui::green(&points)),
        "partial" => (install_ui::yellow("◐"), install_ui::yellow(&points)),
        "pending" => (install_ui::dim("◦"), install_ui::dim("…")),
        "unavailable" => (install_ui::dim("–"), install_ui::dim("not checked")),
        _ => (install_ui::red("✗"), install_ui::dim(&points)),
    };
    println!(
        "{}",
        crate::install_ui::terminal_line!("  {} {}  {}", icon, label, points)
    );
    if !matches!(status, "passed" | "unavailable")
        && let Some(detail) = &check.detail
        && !detail.is_empty()
    {
        println!("    {}", install_ui::dim(detail));
    }
}

fn print_field<T: install_ui::TerminalValue>(label: &'static str, value: T) {
    println!(
        "{}",
        crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim(&format!("{label:<10}")),
            value
        )
    );
}

fn tier_for(score: u32) -> &'static str {
    match score {
        90.. => "excellent",
        70..=89 => "good",
        50..=69 => "fair",
        _ => "needs-work",
    }
}

fn tier_label(tier: &str) -> &str {
    match tier {
        "excellent" => "Excellent",
        "good" => "Good",
        "fair" => "Fair",
        "needs-work" => "Needs work",
        other => other,
    }
}

/// Green for an excellent score, plain for a good one, amber below, as the
/// package page colors its ring.
fn tier_colored(text: &str, score: u32) -> install_ui::TerminalFragment {
    match tier_for(score) {
        "excellent" => install_ui::green(text),
        "good" => install_ui::field(text),
        _ => install_ui::yellow(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_follow_the_registry_thresholds() {
        assert_eq!(tier_for(90), "excellent");
        assert_eq!(tier_for(89), "good");
        assert_eq!(tier_for(70), "good");
        assert_eq!(tier_for(69), "fair");
        assert_eq!(tier_for(50), "fair");
        assert_eq!(tier_for(49), "needs-work");
    }

    #[test]
    fn categories_read_as_publish_check_shows_them() {
        assert_eq!(category_label("documentation"), "Docs");
        assert_eq!(category_label("api"), "API");
        assert_eq!(category_label("health"), "Health");
        assert_eq!(category_label("legacy"), "legacy");
    }

    #[test]
    fn checks_without_a_status_fall_back_to_passed() {
        let check = |passed: Option<bool>, status: Option<&str>| QualityCheck {
            id: "readme".into(),
            category: None,
            label: None,
            passed,
            status: status.map(str::to_string),
            points: None,
            max_points: None,
            detail: None,
        };
        assert_eq!(check_status(&check(Some(true), None)), "passed");
        assert_eq!(check_status(&check(Some(false), None)), "failed");
        assert_eq!(
            check_status(&check(Some(false), Some("pending"))),
            "pending"
        );
    }
}
