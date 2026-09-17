use crate::install_ui;
use lpm_common::LpmError;
use std::io::Write;
use std::path::Path;

pub(super) fn print_dry_run(
    packages: &mut Vec<super::preview::PackagePreview>,
    json_output: bool,
) -> Result<(), LpmError> {
    let mut previews = std::mem::take(packages).into_iter();
    let Some(mut root) = previews.next() else {
        return Ok(());
    };
    root.source_dependencies.extend(previews);
    if json_output {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        serde_json::to_writer_pretty(&mut stdout, &root).map_err(|error| {
            LpmError::Registry(format!("failed to serialize add dry-run output: {error}"))
        })?;
        stdout.write_all(b"\n")?;
    } else {
        eprintln!("\n  Dry run -- no project files will be modified.\n");
        for package in std::iter::once(&root).chain(root.source_dependencies.iter()) {
            eprintln!(
                "  {}@{} -> {}",
                lpm_common::sanitize_terminal_inline(&package.package),
                lpm_common::sanitize_terminal_inline(&package.version),
                lpm_common::sanitize_terminal_inline(&package.target)
            );
            for file in &package.files {
                eprintln!(
                    "    {} ({})",
                    lpm_common::sanitize_terminal_inline(&file.path),
                    file.action
                );
            }
            for file in &package.stale_files {
                eprintln!(
                    "    {} ({}, project-relative)",
                    lpm_common::sanitize_terminal_inline(&file.path),
                    file.action
                );
            }
            for dependency in &package.dependencies_removed {
                eprintln!(
                    "    Remove dependency {} from {}",
                    lpm_common::sanitize_terminal_inline(&dependency.name),
                    lpm_common::sanitize_terminal_inline(&dependency.section)
                );
            }
            if package.dependencies_count > 0 {
                eprintln!("  Dependencies to install: {}", package.dependencies_count);
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
