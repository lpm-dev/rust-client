//! LPM-Native Intelligence: features only possible because we own both client and registry.
//!
//! - **Phantom dependency detection**: Scan source code for imports, cross-reference
//!   against declared deps. Warn about undeclared transitive deps.
//! - **Install-time import verification**: After linking, verify all imports in source
//!   code resolve to installed packages. Catch missing deps before runtime.
//! - **Quality/security warnings**: Surface registry-side analysis during install.
//!
//! These features are the marketing differentiator. npm/yarn/pnpm can't do this
//! because they don't own the registry data.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ─── Source Scanner ────────────────────────────────────────────────

/// An import found in source code.
#[derive(Debug, Clone)]
pub struct SourceImport {
    /// The import specifier (e.g., "react", "@types/node", "./utils")
    pub specifier: String,
    /// The file that contains this import
    pub file: PathBuf,
    /// Line number (1-based)
    pub line: usize,
    /// The package name extracted from the specifier (bare specifier only)
    pub package_name: Option<String>,
}

/// Scan all source files in a project for import/require statements.
///
/// Returns all external package imports (not relative imports).
/// Target: < 100ms for a typical project (~500 source files).
pub fn scan_source_imports(project_dir: &Path) -> Vec<SourceImport> {
    let mut imports = Vec::new();
    let src_dirs = find_source_dirs(project_dir);

    for dir in &src_dirs {
        scan_dir(dir, project_dir, &mut imports);
    }

    imports
}

/// Find directories likely to contain source code.
fn find_source_dirs(project_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // Check common source directories
    for candidate in ["src", "app", "pages", "components", "lib"] {
        let path = project_dir.join(candidate);
        if path.is_dir() {
            dirs.push(path);
        }
    }

    // If no common dirs found, scan the root (but skip node_modules etc.)
    if dirs.is_empty() {
        dirs.push(project_dir.to_path_buf());
    }

    dirs
}

/// Recursively scan a directory for source files.
#[allow(clippy::only_used_in_recursion)]
fn scan_dir(dir: &Path, project_root: &Path, imports: &mut Vec<SourceImport>) {
    static SKIP_DIRS: &[&str] = &[
        "node_modules",
        ".lpm",
        ".git",
        ".next",
        ".nuxt",
        "dist",
        "build",
        "coverage",
        ".cache",
        "__pycache__",
        ".svn",
    ];

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if path.is_dir() {
            if SKIP_DIRS.contains(&name_str.as_ref()) || name_str.starts_with('.') {
                continue;
            }
            scan_dir(&path, project_root, imports);
        } else if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
                scan_file(&path, imports);
            }
        }
    }
}

/// Extract import specifiers from a single source file.
///
/// Handles:
/// - `import ... from "specifier"`
/// - `import "specifier"` (side-effect imports)
/// - `require("specifier")`
/// - `import("specifier")` (dynamic imports)
fn scan_file(path: &Path, imports: &mut Vec<SourceImport>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut in_block_comment = false;

    for (line_idx, line) in content.lines().enumerate() {
        // Track block comments
        if in_block_comment {
            if line.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if line.trim_start().starts_with("/*") {
            if !line.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }

        let trimmed = line.trim();

        // Skip single-line comments
        if trimmed.starts_with("//") {
            continue;
        }

        // Extract specifiers from this line
        for specifier in extract_specifiers(trimmed) {
            // Only track external packages (not relative imports)
            if specifier.starts_with('.') || specifier.starts_with('/') {
                continue;
            }

            let package_name = extract_package_name(&specifier);

            imports.push(SourceImport {
                specifier: specifier.clone(),
                file: path.to_path_buf(),
                line: line_idx + 1,
                package_name: Some(package_name),
            });
        }
    }
}

/// Extract import/require specifiers from a line of code.
fn extract_specifiers(line: &str) -> Vec<String> {
    let mut specifiers = Vec::new();

    // Patterns: from "X", import("X"), require("X"), import "X"
    for keyword in ["from ", "import(", "require(", "import "] {
        if !line.contains(keyword) {
            continue;
        }

        let after_keyword = match line.find(keyword) {
            Some(pos) => &line[pos + keyword.len()..],
            None => continue,
        };

        // Find quoted string
        for quote in ['"', '\'', '`'] {
            if let Some(q1) = after_keyword.find(quote) {
                let after_q1 = &after_keyword[q1 + 1..];
                if let Some(q2) = after_q1.find(quote) {
                    let spec = &after_q1[..q2];
                    if !spec.is_empty() && !spec.contains(' ') {
                        specifiers.push(spec.to_string());
                    }
                }
            }
        }
    }

    specifiers
}

/// Extract the package name from an import specifier.
///
/// `react` → `react`
/// `react/jsx-runtime` → `react`
/// `@types/node` → `@types/node`
/// `@lpm.dev/neo.highlight/utils` → `@lpm.dev/neo.highlight`
fn extract_package_name(specifier: &str) -> String {
    if specifier.starts_with('@') {
        // Scoped: @scope/name or @scope/name/path
        let parts: Vec<&str> = specifier.splitn(3, '/').collect();
        if parts.len() >= 2 {
            format!("{}/{}", parts[0], parts[1])
        } else {
            specifier.to_string()
        }
    } else {
        // Unscoped: name or name/path
        specifier.split('/').next().unwrap_or(specifier).to_string()
    }
}

// ─── Phantom Dependency Detection ──────────────────────────────────

/// Result of phantom dependency analysis.
#[derive(Debug)]
pub struct PhantomDepResult {
    /// Imports that reference packages not in declared dependencies.
    pub phantom_imports: Vec<PhantomImport>,
    /// Total number of unique external packages imported.
    pub total_packages_imported: usize,
    /// Number of unique declared dependencies.
    pub declared_dep_count: usize,
}

#[derive(Debug)]
pub struct PhantomImport {
    /// The package name that was imported but not declared.
    pub package_name: String,
    /// Where it was imported from (first occurrence).
    pub file: PathBuf,
    /// Line number of first occurrence.
    pub line: usize,
    /// How many files import this package.
    pub import_count: usize,
    /// Why it's importable (which declared dep depends on it).
    pub available_via: Option<String>,
}

/// Detect phantom dependencies: packages imported in source code but not declared
/// in package.json dependencies.
pub fn detect_phantom_deps(
    project_dir: &Path,
    declared_deps: &HashMap<String, String>,
    installed_packages: &HashSet<String>,
) -> PhantomDepResult {
    let imports = scan_source_imports(project_dir);

    // Collect unique package names and their import locations
    let mut package_imports: HashMap<String, Vec<&SourceImport>> = HashMap::new();
    for import in &imports {
        if let Some(ref pkg) = import.package_name {
            package_imports.entry(pkg.clone()).or_default().push(import);
        }
    }

    // Filter to packages that are imported but not declared
    let declared_set: HashSet<&str> = declared_deps.keys().map(|k| k.as_str()).collect();

    // Also exclude Node.js built-in modules
    let builtins: HashSet<&str> = [
        "fs",
        "path",
        "os",
        "url",
        "http",
        "https",
        "crypto",
        "stream",
        "util",
        "events",
        "buffer",
        "child_process",
        "cluster",
        "dgram",
        "dns",
        "domain",
        "net",
        "querystring",
        "readline",
        "repl",
        "string_decoder",
        "tls",
        "tty",
        "v8",
        "vm",
        "zlib",
        "assert",
        "console",
        "constants",
        "module",
        "process",
        "punycode",
        "timers",
        "worker_threads",
        "perf_hooks",
        "async_hooks",
        "diagnostics_channel",
        // Node: prefixed
        "node:fs",
        "node:path",
        "node:os",
        "node:url",
        "node:http",
        "node:https",
        "node:crypto",
        "node:stream",
        "node:util",
        "node:events",
        "node:buffer",
        "node:child_process",
        "node:net",
        "node:test",
        "node:assert",
    ]
    .into_iter()
    .collect();

    let mut phantoms = Vec::new();

    for (pkg_name, occurrences) in &package_imports {
        // Skip declared deps, builtins, and type-only imports
        if declared_set.contains(pkg_name.as_str()) || builtins.contains(pkg_name.as_str()) {
            continue;
        }

        // It's a phantom dep — it's imported but not in package.json
        let is_installed = installed_packages.contains(pkg_name);

        let available_via = if is_installed {
            // Find which declared dep provides this transitively
            // (simplified: just note it's available as a transitive dep)
            Some("transitive dependency (available but undeclared)".to_string())
        } else {
            None
        };

        phantoms.push(PhantomImport {
            package_name: pkg_name.clone(),
            file: occurrences[0].file.clone(),
            line: occurrences[0].line,
            import_count: occurrences.len(),
            available_via,
        });
    }

    // Sort by import count (most-imported phantoms first)
    phantoms.sort_by(|a, b| b.import_count.cmp(&a.import_count));

    PhantomDepResult {
        phantom_imports: phantoms,
        total_packages_imported: package_imports.len(),
        declared_dep_count: declared_deps.len(),
    }
}

// ─── Import Verification ───────────────────────────────────────────

/// Result of import verification.
#[derive(Debug)]
pub struct ImportVerification {
    /// Imports that won't resolve at runtime.
    pub unresolved: Vec<UnresolvedImport>,
    /// Total imports checked.
    pub total_checked: usize,
}

#[derive(Debug)]
pub struct UnresolvedImport {
    pub specifier: String,
    pub package_name: String,
    pub file: PathBuf,
    pub line: usize,
    pub suggestion: String,
}

/// Verify that all external imports in source code resolve to installed packages.
///
/// This catches missing deps BEFORE the app runs.
pub fn verify_imports(
    project_dir: &Path,
    installed_packages: &HashSet<String>,
    declared_deps: &HashMap<String, String>,
) -> ImportVerification {
    let imports = scan_source_imports(project_dir);

    let builtins: HashSet<&str> = [
        "fs",
        "path",
        "os",
        "url",
        "http",
        "https",
        "crypto",
        "stream",
        "util",
        "events",
        "buffer",
        "child_process",
        "net",
        "querystring",
        "readline",
        "assert",
        "console",
        "module",
        "process",
        "timers",
        "worker_threads",
        "perf_hooks",
        "async_hooks",
        "diagnostics_channel",
        "node:fs",
        "node:path",
        "node:os",
        "node:url",
        "node:http",
        "node:https",
        "node:crypto",
        "node:stream",
        "node:util",
        "node:events",
        "node:buffer",
        "node:child_process",
        "node:net",
        "node:test",
        "node:assert",
    ]
    .into_iter()
    .collect();

    let mut unresolved = Vec::new();
    let mut seen_packages = HashSet::new();

    for import in &imports {
        let pkg_name = match &import.package_name {
            Some(n) => n,
            None => continue,
        };

        if builtins.contains(pkg_name.as_str()) {
            continue;
        }

        // Check if the package is installed
        if !installed_packages.contains(pkg_name) && !seen_packages.contains(pkg_name) {
            seen_packages.insert(pkg_name.clone());

            let suggestion = if declared_deps.contains_key(pkg_name) {
                "Declared but not installed. Run: lpm-rs install".to_string()
            } else {
                format!("Not installed. Run: lpm-rs install {pkg_name}")
            };

            unresolved.push(UnresolvedImport {
                specifier: import.specifier.clone(),
                package_name: pkg_name.clone(),
                file: import.file.clone(),
                line: import.line,
                suggestion,
            });
        }
    }

    ImportVerification {
        unresolved,
        total_checked: imports.len(),
    }
}

// ─── Quality & Security Warnings ───────────────────────────────────

/// Warning about a package's quality or security during install.
#[derive(Debug)]
pub struct InstallWarning {
    pub package_name: String,
    pub version: String,
    pub severity: WarningSeverity,
    pub message: String,
}

#[derive(Debug)]
pub enum WarningSeverity {
    Info,
    Warning,
    Critical,
}

/// Generate quality/security warnings for installed packages.
///
/// Queries the registry for quality scores and surfaces any issues.
pub async fn check_install_quality(
    client: &lpm_registry::RegistryClient,
    packages: &[(String, String)], // (name, version) pairs
    quality_threshold: u32,
) -> Vec<InstallWarning> {
    let mut warnings = Vec::new();

    for (name, version) in packages {
        if !name.starts_with("@lpm.dev/") {
            continue; // Only check LPM packages
        }

        let short = name.trim_start_matches("@lpm.dev/");
        if let Ok(quality) = client.get_quality(short).await {
            let score = quality.score.unwrap_or(0);
            if score < quality_threshold {
                let severity = if score < 25 {
                    WarningSeverity::Critical
                } else if score < 50 {
                    WarningSeverity::Warning
                } else {
                    WarningSeverity::Info
                };

                warnings.push(InstallWarning {
                    package_name: name.clone(),
                    version: version.clone(),
                    severity,
                    message: format!("Quality score: {score}/100"),
                });
            }
        }
    }

    warnings
}
