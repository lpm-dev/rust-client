use std::path::{Path, PathBuf};

/// Detect a reasonable default install directory based on project framework.
///
/// Mirrors the JS CLI's `detectFramework()` + `getDefaultPath()`:
///   - Next.js (app router): `components/` if it exists, else `src/components`
///   - Next.js (pages router): `src/components`
///   - Vite / Remix: `src/components`
///   - Unknown: `components/` if it exists, else `src/components` if `src/` exists
pub(super) fn detect_default_install_dir(project_dir: &Path, _ecosystem: &str) -> PathBuf {
    let framework = detect_framework(project_dir);

    match framework.as_str() {
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
    let doc = match std::fs::read_to_string(&pkg_json_path)
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
    } else if project_dir.join("package-lock.json").exists() {
        "npm"
    } else {
        "lpm"
    }
    .to_string()
}

pub(super) fn detect_buyer_alias(project_dir: &Path) -> Option<String> {
    for config_name in ["tsconfig.json", "jsconfig.json"] {
        let path = project_dir.join(config_name);
        if !path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&path).ok()?;
        // Strip comments (// and /* */) for JSON parsing
        let stripped = strip_json_comments(&content);
        let config: serde_json::Value = serde_json::from_str(&stripped).ok()?;
        let paths = config
            .get("compilerOptions")
            .and_then(|co| co.get("paths"))
            .and_then(|p| p.as_object())?;

        for key in paths.keys() {
            if key.ends_with("/*") {
                // "@/*" -> "@/"
                return Some(key[..key.len() - 1].to_string());
            }
        }
    }
    None
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
            detect_default_install_dir(project_dir, ecosystem)
        }
    }
}
