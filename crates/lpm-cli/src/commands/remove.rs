use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use std::path::{Path, PathBuf};

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

fn legacy_skill_short(package: &str) -> Option<String> {
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

fn prune_empty_parent_dirs(project_dir: &Path, start: &Path) -> Result<(), LpmError> {
    let mut current = start.to_path_buf();
    while current.starts_with(project_dir) && current != project_dir {
        match std::fs::remove_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => break,
            Err(error) => return Err(LpmError::Io(error)),
        }

        let Some(parent) = current.parent() else {
            break;
        };
        current = parent.to_path_buf();
    }

    Ok(())
}

/// Remove a source-delivered package (reverse of `lpm add`).
///
/// Removes files that were copied by `lpm add` and cleans up the target directory.
pub async fn run(project_dir: &Path, package: &str, json_output: bool) -> Result<(), LpmError> {
    let mut removed_paths = Vec::new();

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
            if skills_dir.exists() {
                std::fs::remove_dir_all(&skills_dir)?;
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
                prune_empty_parent_dirs(project_dir, parent)?;
            }
        }

        crate::added_sources_state::write_state(project_dir, &added_sources_state)?;
    } else {
        if let Some(short) = legacy_skill_short(package) {
            let skills_dir = project_dir.join(".lpm").join("skills").join(&short);
            if skills_dir.exists() {
                std::fs::remove_dir_all(&skills_dir)?;
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
        install_ui::warn(&format!(
            "No files found for {} — it may not have been added, or was added to a custom path",
            package.bold()
        ));
    } else {
        install_ui::done(&format!("Removed {}", package.bold()));
        for path in &removed_paths {
            eprintln!("  {}", path.dimmed());
        }
    }

    Ok(())
}
