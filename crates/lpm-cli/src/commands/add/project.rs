use std::path::{Path, PathBuf};

/// Detect a reasonable default install directory based on project framework.
///
/// Mirrors the JS CLI's `detectFramework()` + `getDefaultPath()`:
///   - Next.js (app router): `components/` if it exists, else `src/components`
///   - Next.js (pages router): `src/components`
///   - Vite / Remix: `src/components`
///   - Unknown: `components/` if it exists, else `src/components` if `src/` exists
pub(super) fn detect_default_install_dir(project_dir: &Path, framework: &str) -> PathBuf {
    match framework {
        "next-app" => {
            // Next.js app router: components/ if it exists, else src/components
            if project_dir.join("components").is_dir() {
                project_dir.join("components")
            } else {
                project_dir.join("src/components")
            }
        }
        "next-pages" | "vite" | "remix" => project_dir.join("src/components"),
        _ => {
            // Generic: check existing directories
            if project_dir.join("src/components").is_dir() {
                project_dir.join("src/components")
            } else if project_dir.join("components").is_dir() {
                project_dir.join("components")
            } else if project_dir.join("src").is_dir() {
                project_dir.join("src/components")
            } else {
                project_dir.join("components")
            }
        }
    }
}

/// Detect the JS framework from package.json dependencies.
///
/// Returns: "next-app", "next-pages", "vite", "remix", or "unknown".
pub(super) fn detect_framework(project_dir: &Path) -> String {
    let pkg_json_path = project_dir.join("package.json");
    let doc = match lpm_common::read_text_file_capped(
        &pkg_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .ok()
    .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
    {
        Some(d) => d,
        None => return "unknown".to_string(),
    };

    let has_dep = |name: &str| -> bool {
        doc.get("dependencies").and_then(|d| d.get(name)).is_some()
            || doc
                .get("devDependencies")
                .and_then(|d| d.get(name))
                .is_some()
    };

    if has_dep("next") {
        // Distinguish app router from pages router
        if project_dir.join("app").is_dir() {
            return "next-app".to_string();
        }
        return "next-pages".to_string();
    }

    if has_dep("@remix-run/react") {
        return "remix".to_string();
    }

    if has_dep("vite") {
        return "vite".to_string();
    }

    "unknown".to_string()
}

// ---------------------------------------------------------------------------
// Package manager detection (for --pm=auto)
// ---------------------------------------------------------------------------

/// Detect the package manager from lockfile presence in the project directory.
pub(super) fn detect_package_manager(project_dir: &Path) -> String {
    if project_dir.join("pnpm-lock.yaml").exists() {
        "pnpm"
    } else if project_dir.join("yarn.lock").exists() {
        "yarn"
    } else if project_dir.join("bun.lockb").exists() || project_dir.join("bun.lock").exists() {
        "bun"
    } else if project_dir.join("package-lock.json").exists()
        || project_dir.join("npm-shrinkwrap.json").exists()
    {
        "npm"
    } else {
        "lpm"
    }
    .to_string()
}

pub(super) fn detect_buyer_alias(project_dir: &Path, target_dir: &Path) -> Option<String> {
    let target_relative = target_dir.strip_prefix(project_dir).ok()?;
    for config_name in ["tsconfig.json", "jsconfig.json"] {
        let path = project_dir.join(config_name);
        let content = match lpm_common::read_text_file_capped(
            &path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => continue,
            Err(_) => return None,
        };
        // Strip comments (// and /* */) for JSON parsing
        let stripped = strip_json_comments(&content);
        let Some(config) = serde_json::from_str::<serde_json::Value>(&stripped).ok() else {
            continue;
        };
        let Some(paths) = config
            .get("compilerOptions")
            .and_then(|co| co.get("paths"))
            .and_then(|p| p.as_object())
        else {
            continue;
        };
        let base_url = config
            .get("compilerOptions")
            .and_then(|options| options.get("baseUrl"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or(".");
        let mut best: Option<(usize, String)> = None;
        for (key, targets) in paths {
            let Some(alias_prefix) = key.strip_suffix('*') else {
                continue;
            };
            let Some(targets) = targets.as_array() else {
                continue;
            };
            for mapped in targets.iter().filter_map(serde_json::Value::as_str) {
                let Some(mapped_prefix) = mapped.strip_suffix('*') else {
                    continue;
                };
                let Some(mapped_base) = normalize_relative_mapping(base_url, mapped_prefix) else {
                    continue;
                };
                let Ok(alias_suffix) = target_relative.strip_prefix(&mapped_base) else {
                    continue;
                };
                let mut alias = alias_prefix.to_string();
                for component in alias_suffix.components() {
                    let std::path::Component::Normal(segment) = component else {
                        continue;
                    };
                    if !alias.ends_with('/') {
                        alias.push('/');
                    }
                    alias.push_str(&segment.to_string_lossy());
                }
                if !alias.ends_with('/') {
                    alias.push('/');
                }
                let depth = mapped_base.components().count();
                if best
                    .as_ref()
                    .is_none_or(|(best_depth, _)| depth > *best_depth)
                {
                    best = Some((depth, alias));
                }
            }
        }
        if let Some((_, alias)) = best {
            return Some(alias);
        }
    }
    None
}

fn normalize_relative_mapping(base_url: &str, mapped_prefix: &str) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in Path::new(base_url)
        .components()
        .chain(Path::new(mapped_prefix).components())
    {
        match component {
            std::path::Component::Normal(segment) => normalized.push(segment),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

/// Strip single-line (//) and block (/* */) comments from JSON-like content.
fn strip_json_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;

    while let Some(c) = chars.next() {
        if in_string {
            result.push(c);
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    result.push(next);
                    chars.next();
                }
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            result.push(c);
        } else if c == '/' {
            match chars.peek() {
                Some('/') => {
                    // Skip until end of line
                    for ch in chars.by_ref() {
                        if ch == '\n' {
                            result.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next(); // consume *
                    while let Some(ch) = chars.next() {
                        if ch == '*' && chars.peek() == Some(&'/') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => result.push(c),
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Determine target directory for file installation.
pub(super) fn resolve_target_dir(
    project_dir: &Path,
    explicit_path: Option<&str>,
    ecosystem: &str,
    framework: &str,
    swift_target: Option<&str>,
) -> PathBuf {
    if let Some(path) = explicit_path {
        return project_dir.join(path);
    }

    match ecosystem {
        "swift" => {
            let xcode_exists = std::fs::read_dir(project_dir).is_ok_and(|entries| {
                entries.flatten().any(|e| {
                    e.path()
                        .extension()
                        .is_some_and(|ext| ext == "xcodeproj" || ext == "xcworkspace")
                })
            });

            if xcode_exists {
                // Swift Xcode: Packages/LPMComponents/Sources/{target}
                let mut path = project_dir
                    .join("Packages")
                    .join("LPMComponents")
                    .join("Sources");
                if let Some(t) = swift_target {
                    path = path.join(t);
                }
                path
            } else {
                // SPM project: Sources/{target}
                let mut path = project_dir.join("Sources");
                if let Some(t) = swift_target {
                    path = path.join(t);
                }
                path
            }
        }
        _ => {
            // JS: detect framework for smart defaults
            detect_default_install_dir(project_dir, framework)
        }
    }
}

pub(super) fn validate_target_dir(
    project_dir: &Path,
    target_dir: &Path,
) -> Result<(), lpm_common::LpmError> {
    let relative = target_dir.strip_prefix(project_dir).map_err(|_| {
        lpm_common::LpmError::Registry(format!(
            "target path '{}' is outside project '{}'",
            target_dir.display(),
            project_dir.display()
        ))
    })?;
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err(lpm_common::LpmError::Registry(format!(
            "target path '{}' must stay inside the project",
            target_dir.display()
        )));
    }

    let project_canonical = project_dir
        .canonicalize()
        .map_err(lpm_common::LpmError::Io)?;
    let mut existing = target_dir;
    while !existing.exists() {
        existing = existing.parent().ok_or_else(|| {
            lpm_common::LpmError::Registry(format!(
                "target path '{}' has no existing ancestor",
                target_dir.display()
            ))
        })?;
    }
    let existing_canonical = existing.canonicalize().map_err(lpm_common::LpmError::Io)?;
    if !std::fs::metadata(existing)
        .map_err(lpm_common::LpmError::Io)?
        .is_dir()
    {
        return Err(lpm_common::LpmError::Registry(format!(
            "target path '{}' has a non-directory ancestor '{}'",
            target_dir.display(),
            existing.display()
        )));
    }
    if !existing_canonical.starts_with(&project_canonical) {
        return Err(lpm_common::LpmError::Registry(format!(
            "target path '{}' resolves outside project '{}'",
            target_dir.display(),
            project_dir.display()
        )));
    }
    Ok(())
}

pub(super) fn planned_target_root(target_dir: &Path) -> Result<PathBuf, lpm_common::LpmError> {
    let mut existing = target_dir;
    let mut missing = Vec::new();
    while !existing.exists() {
        let name = existing.file_name().ok_or_else(|| {
            lpm_common::LpmError::Registry(format!(
                "target path '{}' has no existing ancestor",
                target_dir.display()
            ))
        })?;
        missing.push(name.to_os_string());
        existing = existing.parent().ok_or_else(|| {
            lpm_common::LpmError::Registry(format!(
                "target path '{}' has no existing ancestor",
                target_dir.display()
            ))
        })?;
    }
    let mut planned = existing.canonicalize().map_err(lpm_common::LpmError::Io)?;
    for component in missing.iter().rev() {
        planned.push(component);
    }
    Ok(planned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_shrinkwrap_selects_npm_in_auto_mode() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("npm-shrinkwrap.json"), "{}").unwrap();

        assert_eq!(detect_package_manager(project.path()), "npm");
    }

    #[test]
    fn buyer_alias_is_derived_from_the_mapped_base() {
        let project = tempfile::tempdir().unwrap();
        for (mapping, target, expected) in [
            ("./*", "src/components", "@/src/components/"),
            ("./src/*", "src/components", "@/components/"),
        ] {
            std::fs::write(
                project.path().join("tsconfig.json"),
                format!(r#"{{"compilerOptions":{{"paths":{{"@/*":["{mapping}"]}}}}}}"#),
            )
            .unwrap();
            assert_eq!(
                detect_buyer_alias(project.path(), &project.path().join(target)).as_deref(),
                Some(expected)
            );
        }
        assert!(detect_buyer_alias(project.path(), &project.path().join("components")).is_none());
    }

    #[test]
    fn buyer_alias_prefers_the_most_specific_compatible_mapping() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("tsconfig.json"),
            r#"{"compilerOptions":{"paths":{"root/*":["./*"],"@/*":["./src/*"]}}}"#,
        )
        .unwrap();

        assert_eq!(
            detect_buyer_alias(project.path(), &project.path().join("src/components")).as_deref(),
            Some("@/components/")
        );
        assert!(
            detect_buyer_alias(project.path(), &project.path().join("outside"))
                .is_some_and(|alias| alias == "root/outside/")
        );
    }
}
