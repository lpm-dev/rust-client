use crate::{install_ui, output};

/// Print security warnings for a single package version.
pub fn print_security_warnings(
    name: &str,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
) {
    let mut warnings: Vec<String> = Vec::new();

    if let Some(findings) = &ver_meta.security_findings {
        for finding in findings {
            let severity = finding.severity.as_deref().unwrap_or("info");
            let desc = finding
                .description
                .as_deref()
                .unwrap_or("security concern detected");
            warnings.push(format!("[{}] {}", severity, desc));
        }
    }

    if let Some(tags) = &ver_meta.behavioral_tags {
        let mut dangerous = Vec::new();
        if tags.eval {
            dangerous.push("eval()");
        }
        if tags.child_process {
            dangerous.push("child_process");
        }
        if tags.shell {
            dangerous.push("shell exec");
        }
        if tags.dynamic_require {
            dangerous.push("dynamic require");
        }
        if !dangerous.is_empty() {
            warnings.push(format!("uses {}", dangerous.join(", ")));
        }
    }

    if let Some(scripts) = &ver_meta.lifecycle_scripts {
        let script_names: Vec<&str> = scripts.keys().map(|s| s.as_str()).collect();
        if !script_names.is_empty() {
            warnings.push(format!(
                "has lifecycle scripts: {}",
                script_names.join(", ")
            ));
        }
    }

    if warnings.is_empty() {
        return;
    }

    println!();
    output::warn_line(crate::install_ui::terminal_line!(
        "{} ({}) has {} issue(s):",
        install_ui::bold(name),
        version,
        warnings.len()
    ));
    for warning in &warnings {
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "    {} {}",
            install_ui::yellow("\u{26a0}"),
            warning
        ));
    }
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  Run {} for details",
        install_ui::bold("lpm audit")
    ));
}
