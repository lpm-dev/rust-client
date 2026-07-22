use crate::install_ui;
use lpm_common::LpmError;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn manifest_lookup_keys(package: &str) -> Vec<String> {
    let mut keys = vec![package.to_string()];
    if let Ok(name) = lpm_common::PackageName::parse(package) {
        let scoped = name.scoped();
        if scoped != package {
            keys.push(scoped);
        }
    }
    keys
}

fn package_skill_short(package: &str) -> Option<String> {
    lpm_common::PackageName::parse(package)
        .ok()
        .map(|name| name.short())
}

fn legacy_candidate_dir_hints(package: &str) -> Vec<String> {
    if let Ok(name) = lpm_common::PackageName::parse(package) {
        return vec![
            name.short()
                .split('.')
                .next_back()
                .unwrap_or(package)
                .to_string(),
        ];
    }

    let mut hints = Vec::new();
    let tail = package.rsplit('/').next().unwrap_or(package);
    hints.push(tail.to_string());

    let last_dot = tail.rsplit('.').next().unwrap_or(tail);
    if last_dot != tail {
        hints.push(last_dot.to_string());
    }

    hints.sort();
    hints.dedup();
    hints
}

fn prune_empty_parent_dirs(project_dir: &Path, start: &Path) -> Result<usize, LpmError> {
    let mut current = start.to_path_buf();
    let mut removed = 0;
    while current.starts_with(project_dir) && current != project_dir {
        match std::fs::remove_dir(&current) {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => break,
            Err(error) => return Err(LpmError::Io(error)),
        }

        let Some(parent) = current.parent() else {
            break;
        };
        current = parent.to_path_buf();
    }

    Ok(removed)
}

/// Remove a source-delivered package (reverse of `lpm add`).
///
/// Removes files that were copied by `lpm add` and cleans up the target directory.
pub async fn run(project_dir: &Path, package: &str, json_output: bool) -> Result<(), LpmError> {
    let start = Instant::now();
    let mut removed_paths = Vec::new();
    let mut cleaned_dirs = 0;

    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Removing tracked source files for {}",
            install_ui::yellow(package)
        ));
    }

    let mut added_sources_state = crate::added_sources_state::load_state(project_dir)?;
    let manifest_key = manifest_lookup_keys(package)
        .into_iter()
        .find(|key| added_sources_state.package(key).is_some());

    if let Some(package_key) = manifest_key {
        let record = added_sources_state
            .take_package(&package_key)
            .expect("manifest key must exist after lookup");

        if let Some(short) = record.skill_package_short.as_deref() {
            let skills_dir = project_dir.join(".lpm").join("skills").join(short);
            if std::fs::symlink_metadata(&skills_dir).is_ok() {
                crate::commands::skills::package::remove(project_dir, short)?;
                removed_paths.push(format!(".lpm/skills/{short}/"));
            }
            crate::editor_skills::remove_editor_skills(project_dir, short);
        }

        let tracked_files: Vec<PathBuf> = record.files.into_iter().collect();
        for tracked_path in &tracked_files {
            let absolute_path =
                crate::added_sources_state::resolve_manifest_path(project_dir, tracked_path);
            if absolute_path.exists() {
                std::fs::remove_file(&absolute_path)?;
                removed_paths.push(crate::added_sources_state::display_manifest_path(
                    tracked_path,
                ));
            }
        }
        for tracked_path in &tracked_files {
            let absolute_path =
                crate::added_sources_state::resolve_manifest_path(project_dir, tracked_path);
            if let Some(parent) = absolute_path.parent() {
                cleaned_dirs += prune_empty_parent_dirs(project_dir, parent)?;
            }
        }

        crate::added_sources_state::write_state(project_dir, &added_sources_state)?;
    } else {
        if let Some(short) = package_skill_short(package) {
            let skills_dir = project_dir.join(".lpm").join("skills").join(&short);
            if std::fs::symlink_metadata(&skills_dir).is_ok() {
                crate::commands::skills::package::remove(project_dir, &short)?;
                removed_paths.push(format!(".lpm/skills/{short}/"));
            }
            crate::editor_skills::remove_editor_skills(project_dir, &short);
        }

        for pkg_short_name in legacy_candidate_dir_hints(package) {
            for candidate in [
                "components",
                "src/components",
                "lib",
                "src/lib",
                "Packages/LPMComponents/Sources",
                "Sources",
            ] {
                let candidate_dir = project_dir.join(candidate).join(&pkg_short_name);
                if candidate_dir.exists() && candidate_dir.is_dir() {
                    std::fs::remove_dir_all(&candidate_dir)?;
                    removed_paths.push(format!("{candidate}/{pkg_short_name}/"));
                }
            }
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "package": package,
                "removed": removed_paths,
            }))
            .unwrap()
        );
    } else if removed_paths.is_empty() {
        install_ui::warn_line(crate::install_ui::terminal_line!(
            "No files found for {} — it may not have been added, or was added to a custom path",
            install_ui::yellow(package)
        ));
    } else {
        for path in &removed_paths {
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "  {} {}",
                install_ui::red("-"),
                install_ui::dim(path)
            ));
        }
        if cleaned_dirs > 0 || removed_paths.iter().any(|path| path.ends_with('/')) {
            install_ui::done("Cleaned empty directories");
        }
        let duration = install_ui::format_duration(start.elapsed());
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · removed {} files in {}",
            install_ui::green(&removed_paths.len().to_string()),
            install_ui::green(&duration)
        ));
    }

    Ok(())
}
