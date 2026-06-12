use super::dependencies::count_dependencies;
use super::project::detect_framework;
use super::target::AddTarget;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use std::collections::HashMap;
use std::path::Path;

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
    extract_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let mut file_actions = Vec::new();

    for (_src_rel, dest_rel) in files {
        let dest_target = target_dir.join(dest_rel);
        let exists = dest_target.exists();
        let action = if exists {
            if force { "overwrite" } else { "skip" }
        } else {
            "create"
        };
        file_actions.push((dest_rel.clone(), action));
    }

    // Count dependencies that would be installed
    let dep_count = count_dependencies(lpm_config, inline_config, extract_dir)?;

    if json_output {
        let files_json: Vec<serde_json::Value> = file_actions
            .iter()
            .map(|(path, action)| {
                serde_json::json!({
                    "path": path,
                    "action": action,
                })
            })
            .collect();

        let json = serde_json::json!({
            "success": true,
            "dry_run": true,
            "package": add_target.json_name(),
            "version": version,
            "target": target_dir.strip_prefix(project_dir).unwrap_or(target_dir).display().to_string(),
            "files": files_json,
            "dependencies_count": dep_count,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        eprintln!("\n  Dry run -- no files will be modified.\n");
        eprintln!(
            "  Would install to: {}",
            target_dir
                .strip_prefix(project_dir)
                .unwrap_or(target_dir)
                .display()
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
            eprintln!("    {} {} ({})", icon, path, action);
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
                                eprintln!("    {dep_name}");
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
) {
    install_ui::phase("Detecting project structure");
    add_detail("Framework:", &framework_label(project_dir, ecosystem));
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
    install_ui::detail(&format!("    {} {}", install_ui::dim(&label), value));
}

fn framework_label(project_dir: &Path, ecosystem: &str) -> String {
    if ecosystem == "swift" {
        return "Swift".to_string();
    }

    match detect_framework(project_dir).as_str() {
        "next-app" => "Next.js app router",
        "next-pages" => "Next.js pages router",
        "vite" => "Vite",
        "remix" => "Remix",
        _ => "unknown",
    }
    .to_string()
}

pub(super) fn print_add_file(path: &str) {
    install_ui::detail(&format!(
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
