//! LPM-Native Intelligence: features only possible because we own both client and registry.
//!
//! - **Phantom dependency detection**: Scan source code for imports, cross-reference
//!   against declared deps. Warn about undeclared transitive deps.
//! - **Install-time import verification**: After linking, verify all imports in source
//!   code resolve to installed packages. Catch missing deps before runtime.
//! - **Quality/security warnings**: Surface registry-side analysis during install.

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
/// Returns all external package imports. Path-relative specifiers
/// (`./foo`, `/abs/path`) and user-declared bundler/TS path aliases
/// (e.g., `@/components`, `~/lib`, anything in `tsconfig.json` `paths`
/// or `lpm.config.json` `importAlias`) are skipped — those resolve to
/// local source files, not packages.
///
/// **Nested-package boundaries are opaque.** Descent stops at any
/// subdirectory containing its own `package.json` — that directory is
/// its own package and its imports are checked against its own manifest,
/// not the parent's.
///
/// Target: < 100ms for a typical project (~500 source files).
pub fn scan_source_imports(project_dir: &Path) -> Vec<SourceImport> {
    let aliases = ProjectAliases::load(project_dir);
    let mut imports = Vec::new();
    let src_dirs = find_source_dirs(project_dir);

    for dir in &src_dirs {
        let is_root = dir == project_dir;
        scan_dir(dir, &aliases, is_root, &mut imports);
    }

    imports
}

/// Find directories likely to contain source code.
///
/// Returns the conventional source-tree roots if they exist
/// (`src/`, `app/`, `pages/`, `components/`, `lib/`). When none exist,
/// falls back to the project root itself; the boundary check in
/// [`scan_dir`] keeps descent inside the current package.
fn find_source_dirs(project_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    for candidate in ["src", "app", "pages", "components", "lib"] {
        let path = project_dir.join(candidate);
        if path.is_dir() {
            dirs.push(path);
        }
    }

    if dirs.is_empty() {
        dirs.push(project_dir.to_path_buf());
    }

    dirs
}

/// Recursively scan a directory for source files.
///
/// `is_root` is true only for the initial entry into the project — at
/// the root we ignore the project's own `package.json` (it's the manifest
/// we're checking *against*, not a boundary). Every subdirectory that
/// contains its own `package.json` is treated as a separate package and
/// skipped: descent never crosses a package boundary.
fn scan_dir(dir: &Path, aliases: &ProjectAliases, is_root: bool, imports: &mut Vec<SourceImport>) {
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

    // Boundary: a subdirectory with its own package.json is its own
    // package — don't scan it as part of the parent.
    if !is_root && dir.join("package.json").is_file() {
        return;
    }

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
            scan_dir(&path, aliases, false, imports);
        } else if path.is_file() && is_runtime_source_file(&path) {
            scan_file(&path, aliases, imports);
        }
    }
}

fn is_runtime_source_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if file_name.ends_with(".d.ts")
        || file_name.ends_with(".d.cts")
        || file_name.ends_with(".d.mts")
    {
        return false;
    }

    matches!(
        path.extension().and_then(|e| e.to_str()).unwrap_or(""),
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs"
    )
}

/// Extract import specifiers from a single source file.
///
/// Handles:
/// - `import ... from "specifier"`
/// - `import "specifier"` (side-effect imports)
/// - `require("specifier")`
/// - `import("specifier")` (dynamic imports)
fn scan_file(path: &Path, aliases: &ProjectAliases, imports: &mut Vec<SourceImport>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut in_block_comment = false;

    for (line_idx, line) in content.lines().enumerate() {
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

        if trimmed.starts_with("//") {
            continue;
        }

        for specifier in extract_specifiers(trimmed) {
            // Relative / absolute file paths — always local.
            if specifier.starts_with('.') || specifier.starts_with('/') {
                continue;
            }
            // User-declared bundler/TS path aliases — local files.
            if aliases.matches(&specifier) {
                continue;
            }
            // Structurally-invalid package shapes (empty scope, URL
            // schemes, leading `~`/`#`, etc.) — skip silently.
            let Some(package_name) = extract_package_name(&specifier) else {
                continue;
            };

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

    for keyword in ["from ", "import(", "require(", "import "] {
        if !line.contains(keyword) {
            continue;
        }

        let after_keyword = match line.find(keyword) {
            Some(pos) => &line[pos + keyword.len()..],
            None => continue,
        };

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

/// Extract the package name from an import specifier, returning `None`
/// when the specifier cannot possibly be a valid npm package name.
///
/// Rejects (returns `None`):
/// - URL schemes / protocols (`bun:test`, `node:fs`, `npm:lodash`, `data:...`)
/// - Empty-scope path aliases (`@/components`)
/// - Bare `@scope` with no `/name`
/// - Aliases starting with `~`, `#`, `.`, `/` (path-relative or subpath imports)
/// - Segments containing whitespace or characters that npm names never have
///
/// Returns `Some(name)` for valid shapes:
/// - `react` → `react`
/// - `react/jsx-runtime` → `react`
/// - `@types/node` → `@types/node`
/// - `@scope/pkg/sub/path` → `@scope/pkg`
fn extract_package_name(specifier: &str) -> Option<String> {
    // Reject protocol schemes — `bun:test`, `node:fs`, `npm:lodash`,
    // `data:...`, etc. Detected as a `:` before any `/`.
    if let Some(colon) = specifier.find(':') {
        let slash = specifier.find('/').unwrap_or(usize::MAX);
        if colon < slash {
            return None;
        }
    }

    let first = specifier.chars().next()?;
    // Path-relative, subpath-import, and tilde-alias prefixes.
    if matches!(first, '~' | '#' | '.' | '/') {
        return None;
    }

    if first == '@' {
        // Scoped: `@<scope>/<name>` (with optional `/subpath`).
        let parts: Vec<&str> = specifier.splitn(3, '/').collect();
        if parts.len() < 2 {
            return None;
        }
        let scope = parts[0].strip_prefix('@')?;
        let name = parts[1];
        if !is_valid_npm_segment(scope) || !is_valid_npm_segment(name) {
            return None;
        }
        Some(format!("@{scope}/{name}"))
    } else {
        let name = specifier.split('/').next()?;
        if !is_valid_npm_segment(name) {
            return None;
        }
        Some(name.to_string())
    }
}

/// Conservative npm-name segment validator. Rejects shapes that
/// cannot be valid npm names without over-rejecting legacy uppercase
/// packages (`JSONStream`, `Base64`, etc.).
///
/// Rules:
/// - Non-empty
/// - First character isn't `.` or `_` (npm forbids both)
/// - Every character is ASCII-alphanumeric, `-`, `_`, or `.`
fn is_valid_npm_segment(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if first == '.' || first == '_' {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

// ─── Project-Local Import Aliases ──────────────────────────────────

/// User-declared import alias prefixes that resolve to local source
/// files, not packages.
///
/// Populated from (in order; first present wins for TS-style paths):
/// 1. `tsconfig.json` `compilerOptions.paths`
/// 2. `jsconfig.json` `compilerOptions.paths`
/// 3. `lpm.config.json` `importAlias` (additive — shadcn-style)
///
/// Patterns ending in `/*` or `*` are stored as prefix matches; bare
/// keys are stored as exact matches. Prefixes are sorted longest-first
/// so more-specific patterns shadow generic ones at match time.
#[derive(Debug, Default)]
pub struct ProjectAliases {
    prefixes: Vec<String>,
    exact: HashSet<String>,
    base_url_roots: Vec<PathBuf>,
}

impl ProjectAliases {
    /// Load aliases from the project's TS/JS config files. Missing or
    /// malformed files are silently ignored — the scanner still works,
    /// it just won't filter aliases.
    pub fn load(project_dir: &Path) -> Self {
        let mut aliases = ProjectAliases::default();

        for cfg in ["tsconfig.json", "jsconfig.json"] {
            let path = project_dir.join(cfg);
            if let Ok(content) = std::fs::read_to_string(&path)
                && absorb_ts_config(&content, project_dir, &mut aliases)
            {
                break;
            }
        }

        if let Ok(content) = std::fs::read_to_string(project_dir.join("lpm.config.json")) {
            absorb_lpm_import_alias(&content, &mut aliases);
        }

        aliases.prefixes.sort_by_key(|p| std::cmp::Reverse(p.len()));
        aliases
    }

    /// Does this specifier match a user-declared alias?
    pub fn matches(&self, specifier: &str) -> bool {
        if self.exact.contains(specifier) {
            return true;
        }
        self.prefixes
            .iter()
            .any(|p| specifier.starts_with(p) || specifier == p.trim_end_matches('/'))
            || self
                .base_url_roots
                .iter()
                .any(|root| specifier_resolves_under_base_url(root, specifier))
    }
}

/// Parse the input as JSONC (JSON + `//` / `/* */` comments + trailing
/// commas) and absorb `compilerOptions.paths` aliases plus a `baseUrl`
/// root when present. Returns true when the config contributed at least
/// one aliasing rule.
fn absorb_ts_config(content: &str, project_dir: &Path, aliases: &mut ProjectAliases) -> bool {
    let stripped = strip_trailing_commas(&strip_jsonc_comments(content));
    let value: serde_json::Value = match serde_json::from_str(&stripped) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let compiler_options = match value.get("compilerOptions") {
        Some(options) => options,
        None => return false,
    };

    let mut found = false;

    if let Some(paths) = compiler_options.get("paths").and_then(|p| p.as_object()) {
        for key in paths.keys() {
            absorb_alias_key(key, aliases);
        }
        found = found || !paths.is_empty();
    }

    if let Some(base_url) = compiler_options.get("baseUrl").and_then(|v| v.as_str()) {
        let trimmed = base_url.trim();
        if !trimmed.is_empty() {
            aliases.base_url_roots.push(project_dir.join(trimmed));
            found = true;
        }
    }

    found
}

/// Absorb the `importAlias` field from an `lpm.config.json`.
fn absorb_lpm_import_alias(content: &str, aliases: &mut ProjectAliases) {
    let value: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return,
    };
    if let Some(prefix) = value.get("importAlias").and_then(|v| v.as_str())
        && !prefix.is_empty()
    {
        absorb_import_alias_prefix(prefix, aliases);
    }
}

fn absorb_alias_key(key: &str, aliases: &mut ProjectAliases) {
    if let Some(prefix) = key.strip_suffix("/*") {
        // `@/*` → prefix `@/`
        aliases.prefixes.push(format!("{prefix}/"));
    } else if let Some(prefix) = key.strip_suffix('*') {
        // `@components*` → prefix `@components`
        aliases.prefixes.push(prefix.to_string());
    } else if key.ends_with('/') {
        // Already a prefix: `@/`
        aliases.prefixes.push(key.to_string());
    } else {
        aliases.exact.insert(key.to_string());
    }
}

fn absorb_import_alias_prefix(alias: &str, aliases: &mut ProjectAliases) {
    let trimmed = alias.trim_end_matches('/');
    if trimmed.is_empty() {
        return;
    }
    aliases.prefixes.push(format!("{trimmed}/"));
}

fn specifier_resolves_under_base_url(base_url_root: &Path, specifier: &str) -> bool {
    if specifier.is_empty() {
        return false;
    }

    let candidate = base_url_root.join(specifier);
    if candidate.is_file() || candidate.is_dir() {
        return true;
    }

    static LOCAL_IMPORT_EXTENSIONS: &[&str] = &[
        "js", "jsx", "ts", "tsx", "mjs", "cjs", "json", "css", "scss", "sass", "less", "md", "mdx",
    ];

    for extension in LOCAL_IMPORT_EXTENSIONS {
        if candidate.with_extension(extension).is_file() {
            return true;
        }
        if candidate.join(format!("index.{extension}")).is_file() {
            return true;
        }
    }

    false
}

/// Strip `//` line comments and `/* … */` block comments from JSONC
/// input, preserving string contents. Quote-state aware so `"//"` and
/// `"/*"` inside string literals survive untouched.
fn strip_jsonc_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escape = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escape {
                escape = false;
                continue;
            }
            if c == '\\' {
                escape = true;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push(c);
            continue;
        }
        if c == '/' {
            match chars.peek() {
                Some('/') => {
                    while let Some(&n) = chars.peek() {
                        chars.next();
                        if n == '\n' {
                            out.push('\n');
                            break;
                        }
                    }
                    continue;
                }
                Some('*') => {
                    chars.next();
                    let mut prev = '\0';
                    for n in chars.by_ref() {
                        if prev == '*' && n == '/' {
                            break;
                        }
                        prev = n;
                    }
                    continue;
                }
                _ => {}
            }
        }
        out.push(c);
    }
    out
}

/// Replace trailing commas before `}` / `]` with nothing — JSONC
/// tolerates them, strict JSON doesn't. Quote-state aware so commas
/// inside string literals are left alone.
fn strip_trailing_commas(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    let mut escape = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_string {
            out.push(c);
            if escape {
                escape = false;
                i += 1;
                continue;
            }
            if c == '\\' {
                escape = true;
                i += 1;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == ',' {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                j += 1;
            }
            if j < bytes.len() {
                let next = bytes[j] as char;
                if next == '}' || next == ']' {
                    i += 1;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
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
    /// Non-`None` when the phantom is already installed (reachable as a
    /// transitive dependency). We don't currently attribute *which*
    /// declared dep pulls it in — that would need the resolved edge
    /// graph — so the value is a stable advisory string.
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

    let mut package_imports: HashMap<String, Vec<&SourceImport>> = HashMap::new();
    for import in &imports {
        if let Some(ref pkg) = import.package_name {
            package_imports.entry(pkg.clone()).or_default().push(import);
        }
    }

    let declared_set: HashSet<&str> = declared_deps.keys().map(|k| k.as_str()).collect();
    let builtins = node_builtins();

    let mut phantoms = Vec::new();

    for (pkg_name, occurrences) in &package_imports {
        if declared_set.contains(pkg_name.as_str()) || builtins.contains(pkg_name.as_str()) {
            continue;
        }

        let is_installed = installed_packages.contains(pkg_name);
        let available_via =
            is_installed.then(|| "available as a transitive dependency".to_string());

        phantoms.push(PhantomImport {
            package_name: pkg_name.clone(),
            file: occurrences[0].file.clone(),
            line: occurrences[0].line,
            import_count: occurrences.len(),
            available_via,
        });
    }

    phantoms.sort_by_key(|phantom| std::cmp::Reverse(phantom.import_count));

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
    let builtins = node_builtins();

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

        if !installed_packages.contains(pkg_name) && !seen_packages.contains(pkg_name) {
            seen_packages.insert(pkg_name.clone());

            let suggestion = if declared_deps.contains_key(pkg_name) {
                "Declared but not installed. Run: lpm install".to_string()
            } else {
                format!("Not installed. Run: lpm install {pkg_name}")
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

/// Node.js built-in module names — both bare and `node:`-prefixed.
/// Shared by phantom detection and import verification.
fn node_builtins() -> HashSet<&'static str> {
    [
        // Bare
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
        // node:-prefixed
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
    .collect()
}

pub(crate) fn node_builtin_package_names() -> HashSet<&'static str> {
    node_builtins()
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
    packages: &[(String, String)],
    quality_threshold: u32,
) -> Vec<InstallWarning> {
    let mut warnings = Vec::new();

    for (name, version) in packages {
        if !name.starts_with("@lpm.dev/") {
            continue;
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

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_package_name_plain() {
        assert_eq!(extract_package_name("react"), Some("react".to_string()));
        assert_eq!(
            extract_package_name("react/jsx-runtime"),
            Some("react".to_string())
        );
    }

    #[test]
    fn extract_package_name_scoped() {
        assert_eq!(
            extract_package_name("@types/node"),
            Some("@types/node".to_string())
        );
        assert_eq!(
            extract_package_name("@scope/pkg/sub/path"),
            Some("@scope/pkg".to_string())
        );
        assert_eq!(
            extract_package_name("@lpm.dev/owner.tool"),
            Some("@lpm.dev/owner.tool".to_string())
        );
    }

    #[test]
    fn extract_package_name_rejects_empty_scope() {
        // `@/foo` is a TS path alias — empty scope is never valid npm.
        assert_eq!(extract_package_name("@/components"), None);
        assert_eq!(extract_package_name("@/components/Button"), None);
    }

    #[test]
    fn extract_package_name_rejects_bare_scope() {
        // `@scope` with no `/name` — incomplete.
        assert_eq!(extract_package_name("@scope"), None);
    }

    #[test]
    fn extract_package_name_rejects_alias_prefixes() {
        assert_eq!(extract_package_name("~/lib"), None);
        assert_eq!(extract_package_name("#imports/foo"), None);
        assert_eq!(extract_package_name("#foo"), None);
    }

    #[test]
    fn extract_package_name_rejects_protocol_schemes() {
        assert_eq!(extract_package_name("bun:test"), None);
        assert_eq!(extract_package_name("node:fs"), None);
        assert_eq!(extract_package_name("npm:lodash"), None);
        assert_eq!(extract_package_name("data:text/plain,foo"), None);
        assert_eq!(extract_package_name("jsr:@foo/bar"), None);
    }

    #[test]
    fn extract_package_name_rejects_invalid_segments() {
        assert_eq!(extract_package_name(".hidden"), None);
        assert_eq!(extract_package_name("_underscore"), None);
        assert_eq!(extract_package_name("foo!bar"), None);
    }

    #[test]
    fn is_valid_npm_segment_rules() {
        assert!(is_valid_npm_segment("react"));
        assert!(is_valid_npm_segment("react-dom"));
        assert!(is_valid_npm_segment("lodash.merge"));
        assert!(is_valid_npm_segment("JSONStream")); // legacy uppercase
        assert!(!is_valid_npm_segment(""));
        assert!(!is_valid_npm_segment(".hidden"));
        assert!(!is_valid_npm_segment("_under"));
        assert!(!is_valid_npm_segment("has space"));
        assert!(!is_valid_npm_segment("has!bang"));
    }

    #[test]
    fn strip_jsonc_handles_comments_and_strings() {
        let input = r#"{
            // line comment
            "key": "value", /* block */
            "url": "https://example.com/path", // trailing
            "blob": "// not a comment"
        }"#;
        let out = strip_jsonc_comments(input);
        // Comments removed, strings preserved including embedded `//`.
        assert!(!out.contains("// line comment"));
        assert!(!out.contains("/* block */"));
        assert!(out.contains("https://example.com/path"));
        assert!(out.contains("// not a comment"));
    }

    #[test]
    fn strip_trailing_commas_basic() {
        let input = r#"{"a": 1, "b": [1, 2, 3,], "c": {"d": "e",},}"#;
        let out = strip_trailing_commas(input);
        assert_eq!(out, r#"{"a": 1, "b": [1, 2, 3], "c": {"d": "e"}}"#);
    }

    #[test]
    fn strip_trailing_commas_preserves_string_commas() {
        let input = r#"{"k": "a,b,c,"}"#;
        let out = strip_trailing_commas(input);
        assert_eq!(out, r#"{"k": "a,b,c,"}"#);
    }

    #[test]
    fn project_aliases_load_tsconfig_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("tsconfig.json"),
            r#"{
                "compilerOptions": {
                    "baseUrl": ".",
                    "paths": {
                        "@/*": ["./*"],
                        "internal/*": ["./internal/*"],
                        "~/lib": ["./src/lib"]
                    }
                }
            }"#,
        )
        .unwrap();

        let aliases = ProjectAliases::load(dir.path());

        assert!(aliases.matches("@/components/Button"));
        assert!(aliases.matches("@/components"));
        assert!(aliases.matches("internal/foo"));
        assert!(aliases.matches("~/lib"));
        assert!(!aliases.matches("react"));
        assert!(!aliases.matches("@types/node"));
    }

    #[test]
    fn project_aliases_load_jsconfig_when_no_tsconfig() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("jsconfig.json"),
            r#"{ "compilerOptions": { "paths": { "@/*": ["./*"] } } }"#,
        )
        .unwrap();

        let aliases = ProjectAliases::load(dir.path());
        assert!(aliases.matches("@/foo"));
    }

    #[test]
    fn project_aliases_load_lpm_import_alias() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.config.json"),
            r#"{ "importAlias": "@/" }"#,
        )
        .unwrap();

        let aliases = ProjectAliases::load(dir.path());
        assert!(aliases.matches("@/components"));
    }

    #[test]
    fn project_aliases_treat_baseurl_only_root_imports_as_local() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("components")).unwrap();
        std::fs::create_dir_all(dir.path().join("src/lib")).unwrap();
        std::fs::write(dir.path().join("components/Button.js"), "export default 1;").unwrap();
        std::fs::write(dir.path().join("src/lib/foo.ts"), "export default 1;").unwrap();
        std::fs::write(
            dir.path().join("tsconfig.json"),
            r#"{
                "compilerOptions": {
                    "baseUrl": "."
                }
            }"#,
        )
        .unwrap();

        let aliases = ProjectAliases::load(dir.path());

        assert!(aliases.matches("components/Button"));
        assert!(aliases.matches("src/lib/foo"));
        assert!(!aliases.matches("react"));
        assert!(!aliases.matches("@types/node"));
    }

    #[test]
    fn project_aliases_treat_bare_import_alias_as_prefix() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.config.json"),
            r#"{ "importAlias": "components" }"#,
        )
        .unwrap();

        let aliases = ProjectAliases::load(dir.path());

        assert!(aliases.matches("components/Button"));
        assert!(aliases.matches("components/forms/input"));
        assert!(!aliases.matches("component-kit/Button"));
    }

    #[test]
    fn project_aliases_tolerates_jsonc_comments_and_trailing_commas() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("tsconfig.json"),
            r#"{
                // Project paths
                "compilerOptions": {
                    "paths": {
                        "@/*": ["./*"], // trailing comment
                    },
                },
            }"#,
        )
        .unwrap();

        let aliases = ProjectAliases::load(dir.path());
        assert!(aliases.matches("@/components"));
    }

    #[test]
    fn project_aliases_missing_config_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let aliases = ProjectAliases::load(dir.path());
        assert!(!aliases.matches("@/anything"));
    }

    #[test]
    fn scan_dir_stops_at_nested_package_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("package.json"), r#"{"name":"root"}"#).unwrap();
        std::fs::write(root.join("root.js"), r#"import "root-pkg""#).unwrap();

        let child = root.join("child");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(child.join("package.json"), r#"{"name":"child"}"#).unwrap();
        std::fs::write(child.join("child.js"), r#"import "child-pkg""#).unwrap();

        let imports = scan_source_imports(root);
        let specifiers: HashSet<&str> = imports.iter().map(|i| i.specifier.as_str()).collect();
        assert!(specifiers.contains("root-pkg"));
        assert!(!specifiers.contains("child-pkg"));
    }

    #[test]
    fn scan_file_filters_aliased_imports() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{ "compilerOptions": { "paths": { "@/*": ["./*"] } } }"#,
        )
        .unwrap();
        std::fs::write(root.join("package.json"), r#"{"name":"root"}"#).unwrap();
        std::fs::write(
            root.join("app.js"),
            r#"
            import { Button } from "@/components/Button";
            import React from "react";
            "#,
        )
        .unwrap();

        let imports = scan_source_imports(root);
        let specifiers: HashSet<&str> = imports.iter().map(|i| i.specifier.as_str()).collect();
        assert!(specifiers.contains("react"));
        assert!(!specifiers.contains("@/components/Button"));
    }

    #[test]
    fn scan_file_filters_baseurl_only_imports() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{ "compilerOptions": { "baseUrl": "." } }"#,
        )
        .unwrap();
        std::fs::write(root.join("package.json"), r#"{"name":"root"}"#).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("components")).unwrap();
        std::fs::write(root.join("components/Button.js"), "export default 1;").unwrap();
        std::fs::write(
            root.join("src/app.js"),
            r#"
            import { Button } from "components/Button";
            import React from "react";
            "#,
        )
        .unwrap();

        let imports = scan_source_imports(root);
        let specifiers: HashSet<&str> = imports.iter().map(|i| i.specifier.as_str()).collect();
        assert!(specifiers.contains("react"));
        assert!(!specifiers.contains("components/Button"));
    }

    #[test]
    fn scan_file_filters_bare_import_alias_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("lpm.config.json"),
            r#"{ "importAlias": "components" }"#,
        )
        .unwrap();
        std::fs::write(root.join("package.json"), r#"{"name":"root"}"#).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("components")).unwrap();
        std::fs::write(
            root.join("src/app.js"),
            r#"
            import { Button } from "components/Button";
            import React from "react";
            "#,
        )
        .unwrap();

        let imports = scan_source_imports(root);
        let specifiers: HashSet<&str> = imports.iter().map(|i| i.specifier.as_str()).collect();
        assert!(specifiers.contains("react"));
        assert!(!specifiers.contains("components/Button"));
    }

    #[test]
    fn scan_source_imports_skips_declaration_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("package.json"), r#"{"name":"root"}"#).unwrap();
        std::fs::create_dir_all(root.join("components/dialog")).unwrap();
        std::fs::write(
            root.join("components/dialog/Dialog.d.ts"),
            r#"
            import { ReactNode } from "react";
            export interface DialogProps {
                children?: ReactNode;
            }
            "#,
        )
        .unwrap();

        let imports = scan_source_imports(root);
        let specifiers: HashSet<&str> = imports.iter().map(|i| i.specifier.as_str()).collect();
        assert!(
            !specifiers.contains("react"),
            "declaration files are type-only and must not contribute runtime import warnings"
        );
    }

    #[test]
    fn detect_phantom_deps_skips_aliases_and_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("package.json"), r#"{"name":"root"}"#).unwrap();
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{ "compilerOptions": { "paths": { "@/*": ["./*"] } } }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("app.js"),
            r#"
            import { Button } from "@/components/Button";
            import { defineConfig } from "@pandacss/dev";
            "#,
        )
        .unwrap();

        // Nested child package — its imports must not pollute the parent's
        // phantom set, even though the parent doesn't declare `child-only-dep`.
        let child = root.join("child");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(child.join("package.json"), r#"{"name":"child"}"#).unwrap();
        std::fs::write(child.join("c.js"), r#"import "child-only-dep""#).unwrap();

        let declared = HashMap::new();
        let installed = HashSet::new();
        let result = detect_phantom_deps(root, &declared, &installed);

        let names: HashSet<&str> = result
            .phantom_imports
            .iter()
            .map(|p| p.package_name.as_str())
            .collect();
        assert!(names.contains("@pandacss/dev")); // real phantom
        assert!(!names.contains("@/components")); // alias — skipped
        assert!(!names.contains("child-only-dep")); // child boundary
    }
}
