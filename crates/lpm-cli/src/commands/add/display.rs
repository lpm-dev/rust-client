use super::target::AddTarget;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

#[derive(Serialize)]
struct DryRunFile<'a> {
    path: &'a str,
    action: &'static str,
}

#[derive(Serialize)]
struct DryRunOutput<'a> {
    success: bool,
    dry_run: bool,
    package: String,
    version: &'a str,
    target: String,
    files: Vec<DryRunFile<'a>>,
    dependencies_count: usize,
}

// ---------------------------------------------------------------------------
// Dry-run mode
// ---------------------------------------------------------------------------

/// Show what would happen without writing any files.
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_dry_run(
    project_dir: &Path,
    target_dir: &Path,
    files: &[(String, String)],
    force: bool,
    add_target: &AddTarget,
    version: &str,
    lpm_config: &Option<serde_json::Value>,
    inline_config: &HashMap<String, String>,
    _ecosystem: &str,
    json_output: bool,
    no_install_deps: bool,
    planned_dependency_count: usize,
) -> Result<(), LpmError> {
    let mut file_actions = Vec::with_capacity(files.len());
    let state = crate::added_sources_state::load_state_with_snapshot(project_dir)?.0;
    let package_name = add_target.json_name();
    let previous = state.package(&package_name);

    for (_src_rel, dest_rel) in files {
        let dest_target = target_dir.join(dest_rel);
        let exists = dest_target.exists();
        let manifest_path =
            crate::added_sources_state::manifest_path_for_file(project_dir, &dest_target);
        let managed = if exists {
            previous
                .and_then(|record| record.files.get(&manifest_path))
                .filter(|file| file.action.is_some())
                .is_some_and(|file| {
                    file.installed_digest.as_deref()
                        == crate::added_sources_state::digest_file(&dest_target)
                            .ok()
                            .as_deref()
                })
        } else {
            false
        };
        let action = if exists {
            if managed || force {
                "overwrite"
            } else {
                "skip"
            }
        } else {
            "create"
        };
        file_actions.push((dest_rel.as_str(), action));
    }

    // Count dependencies that would be installed
    let dep_count = if no_install_deps || lpm_config.is_none() {
        0
    } else {
        planned_dependency_count
    };

    if json_output {
        let files = file_actions
            .iter()
            .map(|(path, action)| DryRunFile { path, action })
            .collect();
        let output = DryRunOutput {
            success: true,
            dry_run: true,
            package: add_target.json_name(),
            version,
            target: target_dir
                .strip_prefix(project_dir)
                .unwrap_or(target_dir)
                .display()
                .to_string(),
            files,
            dependencies_count: dep_count,
        };
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        serde_json::to_writer_pretty(&mut stdout, &output).map_err(|error| {
            LpmError::Registry(format!("failed to serialize add dry-run output: {error}"))
        })?;
        stdout.write_all(b"\n").map_err(LpmError::Io)?;
    } else {
        eprintln!("\n  Dry run -- no files will be modified.\n");
        let target = target_dir
            .strip_prefix(project_dir)
            .unwrap_or(target_dir)
            .display()
            .to_string();
        eprintln!(
            "  Would install to: {}",
            lpm_common::sanitize_terminal_inline(&target)
        );
        eprintln!("  Files:");
        for (path, action) in &file_actions {
            let icon = if *action == "create" {
                "+".green().to_string()
            } else if *action == "overwrite" {
                "~".yellow().to_string()
            } else {
                "-".dimmed().to_string()
            };
            eprintln!(
                "    {} {} ({})",
                icon,
                lpm_common::sanitize_terminal_inline(path),
                action
            );
        }
        if dep_count > 0 {
            eprintln!("\n  Dependencies to install: {dep_count}");

            // Show individual dep names if available
            if let Some(config) = lpm_config
                && let Some(dep_config) = config.get("dependencies").and_then(|d| d.as_object())
            {
                for (config_key, dep_map) in dep_config {
                    let config_value = inline_config.get(config_key).map_or("", |s| s.as_str());
                    if config_value.is_empty() {
                        continue;
                    }
                    if let Some(deps) = dep_map.get(config_value).and_then(|d| d.as_array()) {
                        for dep in deps {
                            if let Some(dep_name) = dep.as_str() {
                                eprintln!("    {}", lpm_common::sanitize_terminal_inline(dep_name));
                            }
                        }
                    }
                }
            }
        }
        eprintln!();
    }

    Ok(())
}

pub(super) fn print_add_project_structure(
    project_dir: &Path,
    target_dir: &Path,
    buyer_alias: &Option<String>,
    ecosystem: &str,
    framework: &str,
) {
    install_ui::phase("Detecting project structure");
    add_detail("Framework:", &framework_label(ecosystem, framework));
    let install_path = target_dir
        .strip_prefix(project_dir)
        .unwrap_or(target_dir)
        .display()
        .to_string();
    add_detail("Install path:", &install_ui::dim(&install_path));
    let alias = buyer_alias.as_ref().map_or_else(
        || install_ui::dim("relative imports"),
        |value| install_ui::cyan(value),
    );
    add_detail("Import alias:", &alias);
}

fn add_detail(label: &str, value: &str) {
    let label = format!("{label:<13}");
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "    {} {}",
        install_ui::dim(&label),
        value
    ));
}

fn framework_label(ecosystem: &str, framework: &str) -> String {
    if ecosystem == "swift" {
        return "Swift".to_string();
    }

    match framework {
        "next-app" => "Next.js app router",
        "next-pages" => "Next.js pages router",
        "vite" => "Vite",
        "remix" => "Remix",
        _ => "unknown",
    }
    .to_string()
}

pub(super) fn print_add_file(path: &str) {
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "{} {}",
        install_ui::green("+"),
        install_ui::dim(path)
    ));
}

pub(super) fn files_word(count: usize) -> &'static str {
    if count == 1 { "file" } else { "files" }
}

pub(super) fn dependencies_word(count: usize) -> &'static str {
    if count == 1 {
        "dependency"
    } else {
        "dependencies"
    }
}
