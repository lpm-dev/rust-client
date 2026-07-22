use crate::install_ui;
use lpm_common::LpmError;
use lpm_security::behavioral::secrets::SecretScanResult;
use std::path::Path;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum SecretScanLine {
    Warn(install_ui::TerminalLine),
    Failed(install_ui::TerminalLine),
    Detail(install_ui::TerminalLine),
}

pub(crate) fn run_publish_secret_scan(
    project_dir: &Path,
    json_output: bool,
    allow_secrets: bool,
) -> Result<(), LpmError> {
    if allow_secrets {
        return Ok(());
    }

    let secret_scan = lpm_security::behavioral::secrets::scan_directory(project_dir);
    if secret_scan.has_secrets() {
        if json_output {
            println!("{}", secret_scan_json(&secret_scan));
        } else {
            emit_secret_scan_human(&secret_scan);
        }
        return Err(LpmError::ExitCode(1));
    }
    if !json_output {
        install_ui::done("Secret scan passed");
    }
    Ok(())
}

pub(super) fn secret_scan_json(scan: &SecretScanResult) -> serde_json::Value {
    let matches_json: Vec<serde_json::Value> = scan
        .matches
        .iter()
        .map(|m| {
            serde_json::json!({
                "pattern": m.pattern_name,
                "description": m.description,
                "line": m.line,
                "severity": m.severity,
            })
        })
        .collect();

    serde_json::json!({
        "success": false,
        "error": "secret_scan_failed",
        "matches": matches_json,
        "hint": "Use --allow-secrets to bypass (not recommended)",
    })
}

pub(super) fn emit_secret_scan_human(scan: &SecretScanResult) {
    for line in format_secret_scan_human(scan) {
        match line {
            SecretScanLine::Warn(message) => install_ui::warn_line(message),
            SecretScanLine::Failed(message) => install_ui::failed_line(message),
            SecretScanLine::Detail(message) => install_ui::detail_line(message),
        }
    }
}

pub(super) fn format_secret_scan_human(scan: &SecretScanResult) -> Vec<SecretScanLine> {
    let mut lines = Vec::with_capacity(scan.matches.len() + 3);
    lines.push(SecretScanLine::Warn(crate::install_ui::terminal_line!(
        "Secret scan found {} potential {}",
        install_ui::status_ok(&scan.matches.len().to_string()),
        if scan.matches.len() == 1 {
            "leak"
        } else {
            "leaks"
        }
    )));

    for secret_match in &scan.matches {
        lines.push(SecretScanLine::Detail(format_secret_match(secret_match)));
    }

    lines.push(SecretScanLine::Failed(install_ui::TerminalLine::new(
        "Publish blocked. Remove secrets before publishing.",
    )));
    lines.push(SecretScanLine::Detail(crate::install_ui::terminal_line!(
        "  {} If these are false positives, use {}.",
        install_ui::dim("hint"),
        install_ui::yellow("--allow-secrets")
    )));
    lines
}

pub(super) fn format_secret_match(
    secret_match: &lpm_security::behavioral::secrets::SecretMatch,
) -> install_ui::TerminalLine {
    let location = if secret_match.line > 0 {
        install_ui::dim(&format!(":{}", secret_match.line))
    } else {
        install_ui::field("")
    };

    crate::install_ui::terminal_line!(
        "  {} {}{}  {}  {}",
        format_secret_severity(&secret_match.severity),
        install_ui::red(&secret_match.matched_text),
        location,
        install_ui::cyan(&secret_match.pattern_name),
        &secret_match.description
    )
}

pub(super) fn format_secret_severity(severity: &str) -> install_ui::TerminalFragment {
    match severity {
        "critical" => install_ui::red("critical"),
        "high" => install_ui::yellow("high"),
        _ => install_ui::dim(severity),
    }
}
