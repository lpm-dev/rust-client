use lpm_common::color::Painted;

use crate::install_ui;

pub(super) fn format_severity(severity: &str) -> String {
    let severity = lpm_common::sanitize_terminal_inline(severity);
    match severity.to_lowercase().as_str() {
        "critical" => " CRITICAL ".on_red().white().bold(),
        "high" => severity.red().bold(),
        "moderate" | "medium" => severity.yellow(),
        "low" => severity.blue(),
        "info" => severity.dimmed(),
        _ => severity.to_string(),
    }
}

pub(super) fn format_osv_severity(severity: &str) -> String {
    let severity = lpm_common::sanitize_terminal_inline(severity);
    install_ui::dim(&format!("severity {}", severity.to_lowercase())).to_string()
}

pub(super) fn package_name_without_version(pkg_id: &str) -> String {
    pkg_id
        .rsplit_once('@')
        .filter(|(name, _)| !name.is_empty())
        .map_or_else(|| pkg_id.to_string(), |(name, _)| name.to_string())
}

pub(super) fn preview_versioned_packages(packages: &[String], limit: usize) -> String {
    let mut preview: Vec<String> = packages
        .iter()
        .take(limit)
        .map(|pkg| lpm_common::sanitize_for_terminal(pkg))
        .collect();
    if packages.len() > limit {
        preview.push(format!("+{}", packages.len() - limit));
    }
    install_ui::dim(&preview.join(", ")).to_string()
}

pub(super) fn preview_package_names(packages: &[String], limit: usize) -> String {
    let mut preview: Vec<String> = packages
        .iter()
        .take(limit)
        .map(|pkg| lpm_common::sanitize_for_terminal(&package_name_without_version(pkg)))
        .collect();
    if packages.len() > limit {
        preview.push(format!("+{}", packages.len() - limit));
    }
    install_ui::dim(&preview.join(", ")).to_string()
}

pub(super) fn behavior_token_label(token: &str) -> &str {
    match token {
        "dynamic require" => "dyn-require",
        other => other,
    }
}

pub(super) fn format_behavior_message(message: &str) -> String {
    let body = message.strip_prefix("uses ").unwrap_or(message);
    let tokens: Vec<String> = body
        .split(", ")
        .filter(|part| !part.is_empty())
        .map(|part| lpm_common::sanitize_terminal_inline(behavior_token_label(part)).into_owned())
        .collect();
    if tokens.len() == 2 && tokens[0] == "eval()" && tokens[1] == "dyn-require" {
        return "eval() / dynamic require (misc)".to_string();
    }
    if tokens.is_empty() {
        lpm_common::sanitize_for_terminal(message)
    } else {
        let separator = format!(" {} ", install_ui::dim("·"));
        tokens.join(&separator)
    }
}

pub(super) fn info_tag_label(tag: &str, count: usize) -> String {
    match tag {
        "high-entropy strings detected" => "high-entropy strings".to_string(),
        "wildcard dep" if count != 1 => "wildcard deps".to_string(),
        "native bindings" if count == 1 => "native binding".to_string(),
        other => lpm_common::sanitize_terminal_inline(other).into_owned(),
    }
}

pub(super) fn count_phrase(count: usize, singular: &str, plural: &str) -> String {
    let noun = if count == 1 { singular } else { plural };
    format!("{} {noun}", install_ui::yellow(&count.to_string()))
}

pub(super) fn info_tag_phrase(tag: &str, count: usize) -> String {
    format!(
        "{} {}",
        install_ui::yellow(&count.to_string()),
        info_tag_label(tag, count)
    )
}
