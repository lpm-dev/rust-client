use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

use glob::Pattern;
use lpm_common::{LpmError, write_file_atomic};
use lpm_registry::RegistryClient;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::commands::install::{FrozenLockfileMode, InstallOmitPolicy};
use crate::install_ui;
use crate::intelligence::{SourceImport, node_builtin_package_names, scan_source_imports};

const DEPENDENCY_SECTIONS: [DependencySection; 4] = [
    DependencySection {
        key: "dependencies",
        label: "dependencies",
        fixable: true,
    },
    DependencySection {
        key: "devDependencies",
        label: "devDependencies",
        fixable: true,
    },
    DependencySection {
        key: "optionalDependencies",
        label: "optionalDependencies",
        fixable: true,
    },
    DependencySection {
        key: "peerDependencies",
        label: "peerDependencies",
        fixable: false,
    },
];

#[derive(Clone, Copy)]
struct DependencySection {
    key: &'static str,
    label: &'static str,
    fixable: bool,
}

#[derive(Debug, Clone, Serialize)]
struct UnusedDependency {
    name: String,
    section: &'static str,
    spec: String,
    fixable: bool,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
struct PhantomDependency {
    name: String,
    file: String,
    line: usize,
    import_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    available_via: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct IgnoredFinding {
    kind: &'static str,
    name: String,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
struct RemovedDependency {
    name: String,
    section: &'static str,
    spec: String,
}

#[derive(Debug, Clone, Serialize)]
struct TidyCounts {
    declared: usize,
    imported: usize,
    unused: usize,
    phantoms: usize,
    ignored: usize,
    removed: usize,
    remaining: usize,
}

#[derive(Debug, Clone, Serialize)]
struct TidyReport {
    success: bool,
    fixed: bool,
    manifest: String,
    counts: TidyCounts,
    unused: Vec<UnusedDependency>,
    phantoms: Vec<PhantomDependency>,
    removed: Vec<RemovedDependency>,
    ignored: Vec<IgnoredFinding>,
    elapsed_ms: u128,
}

#[derive(Default)]
struct TidyConfig {
    ignore_unused: Vec<CompiledPattern>,
    ignore_phantom: Vec<CompiledPattern>,
    ignore_paths: Vec<CompiledPattern>,
}

struct CompiledPattern {
    raw: String,
    pattern: Pattern,
}

impl CompiledPattern {
    fn new(raw: String, path: &Path, key: &str) -> Result<Self, LpmError> {
        let pattern = Pattern::new(&raw).map_err(|error| {
            LpmError::Registry(format!(
                "invalid [tidy] {key} pattern `{raw}` in {}: {error}",
                path.display()
            ))
        })?;
        Ok(Self { raw, pattern })
    }

    fn matches(&self, value: &str) -> bool {
        self.raw == value || self.pattern.matches(value)
    }
}

enum FileSnapshot {
    Present(Vec<u8>),
    Absent,
}

impl FileSnapshot {
    fn read(path: &Path) -> Result<Self, LpmError> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Self::Present(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::Absent),
            Err(error) => Err(LpmError::Io(error)),
        }
    }

    fn restore(&self, path: &Path) -> Result<(), LpmError> {
        match self {
            Self::Present(bytes) => write_file_atomic(path, bytes).map_err(LpmError::Io),
            Self::Absent => match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(LpmError::Io(error)),
            },
        }
    }
}

pub async fn run(
    client: &RegistryClient,
    cwd: &Path,
    fix: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let start = Instant::now();
    let project_dir = cwd;
    let manifest_path = project_dir.join("package.json");
    if !manifest_path.is_file() {
        return Err(LpmError::NotFound(format!(
            "no package.json found at {}",
            manifest_path.display()
        )));
    }

    let manifest_bytes = std::fs::read(&manifest_path).map_err(LpmError::Io)?;
    let manifest_text = String::from_utf8(manifest_bytes.clone()).map_err(|error| {
        LpmError::Registry(format!(
            "package.json at {} is not valid UTF-8: {error}",
            manifest_path.display()
        ))
    })?;
    let mut manifest: Value = serde_json::from_str(&manifest_text).map_err(|error| {
        LpmError::Registry(format!(
            "failed to parse package.json at {}: {error}",
            manifest_path.display()
        ))
    })?;
    let config = TidyConfig::load(project_dir)?;

    let mut analysis = analyze_project(project_dir, &manifest, &config)?;
    let mut removed = Vec::new();

    if fix {
        removed = apply_fix(
            client,
            project_dir,
            &manifest_path,
            &manifest_bytes,
            &mut manifest,
            &analysis,
        )
        .await?;
        if !removed.is_empty() {
            let refreshed_text = std::fs::read_to_string(&manifest_path).map_err(LpmError::Io)?;
            manifest = serde_json::from_str(&refreshed_text).map_err(|error| {
                LpmError::Registry(format!(
                    "failed to parse package.json at {} after tidy --fix: {error}",
                    manifest_path.display()
                ))
            })?;
            analysis = analyze_project(project_dir, &manifest, &config)?;
        }
    }

    let elapsed_ms = start.elapsed().as_millis();
    let remaining = analysis.unused.len() + analysis.phantoms.len();
    let report = TidyReport {
        success: remaining == 0,
        fixed: fix,
        manifest: relative_display(project_dir, &manifest_path),
        counts: TidyCounts {
            declared: analysis.declared_count,
            imported: analysis.imported_count,
            unused: analysis.unused.len(),
            phantoms: analysis.phantoms.len(),
            ignored: analysis.ignored.len(),
            removed: removed.len(),
            remaining,
        },
        unused: analysis.unused,
        phantoms: analysis.phantoms,
        removed,
        ignored: analysis.ignored,
        elapsed_ms,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| LpmError::Registry(error.to_string()))?
        );
    } else {
        print_human_report(&report);
    }

    if report.counts.remaining > 0 {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

struct Analysis {
    unused: Vec<UnusedDependency>,
    phantoms: Vec<PhantomDependency>,
    ignored: Vec<IgnoredFinding>,
    declared_count: usize,
    imported_count: usize,
}

fn analyze_project(
    project_dir: &Path,
    manifest: &Value,
    config: &TidyConfig,
) -> Result<Analysis, LpmError> {
    let declared = collect_declared_dependencies(manifest);
    let workspace_names = collect_workspace_member_names(project_dir, manifest)?;
    let imports = filtered_imports(project_dir, config);
    let import_usage = ImportUsage::from_imports(imports);
    let script_tokens = collect_script_tokens(manifest);
    let script_bins =
        collect_installed_bin_names(project_dir, declared.iter().map(|entry| &entry.name));
    let config_text = read_known_config_text(project_dir);
    let installed = collect_installed_packages(project_dir);
    let mut ignored = Vec::new();

    let mut used = import_usage.used_packages.clone();
    absorb_type_package_usage(&mut used, &import_usage);

    let mut unused = Vec::new();
    for entry in &declared {
        let name = &entry.name;
        if dependency_is_used(name, &used, &script_tokens, &script_bins, &config_text) {
            continue;
        }
        if let Some(pattern) = config.match_unused(name) {
            ignored.push(IgnoredFinding {
                kind: "unused",
                name: name.clone(),
                reason: format!("matched [tidy] ignore-unused pattern `{pattern}`"),
            });
            continue;
        }
        unused.push(UnusedDependency {
            name: name.clone(),
            section: entry.section.label,
            spec: entry.spec.clone(),
            fixable: entry.section.fixable,
            reason: if entry.section.fixable {
                "not imported, referenced by scripts, or found in known config files".to_string()
            } else {
                "peerDependencies are report-only because packages may expose peer contracts to consumers".to_string()
            },
        });
    }

    let declared_names: HashSet<&str> = declared.iter().map(|entry| entry.name.as_str()).collect();
    let workspace_names: HashSet<&str> = workspace_names.iter().map(String::as_str).collect();
    let mut phantoms = Vec::new();
    for (name, occurrences) in &import_usage.imports_by_package {
        if import_usage.node_builtins.contains(name.as_str())
            || declared_names.contains(name.as_str())
            || workspace_names.contains(name.as_str())
        {
            continue;
        }
        if let Some(pattern) = config.match_phantom(name) {
            ignored.push(IgnoredFinding {
                kind: "phantom",
                name: name.clone(),
                reason: format!("matched [tidy] ignore-phantom pattern `{pattern}`"),
            });
            continue;
        }

        let first = &occurrences[0];
        phantoms.push(PhantomDependency {
            name: name.clone(),
            file: relative_display(project_dir, &first.file),
            line: first.line,
            import_count: occurrences.len(),
            available_via: installed
                .contains(name)
                .then(|| "available as a transitive dependency".to_string()),
        });
    }

    unused.sort_by(|a, b| a.section.cmp(b.section).then_with(|| a.name.cmp(&b.name)));
    phantoms.sort_by(|a, b| {
        b.import_count
            .cmp(&a.import_count)
            .then_with(|| a.name.cmp(&b.name))
    });
    ignored.sort_by(|a, b| a.kind.cmp(b.kind).then_with(|| a.name.cmp(&b.name)));

    Ok(Analysis {
        unused,
        phantoms,
        ignored,
        declared_count: declared.len(),
        imported_count: import_usage.used_packages.len(),
    })
}

#[derive(Clone)]
struct DeclaredDependency {
    name: String,
    section: DependencySection,
    spec: String,
}

fn collect_declared_dependencies(manifest: &Value) -> Vec<DeclaredDependency> {
    let mut declared = Vec::new();
    for section in DEPENDENCY_SECTIONS {
        let Some(entries) = manifest.get(section.key).and_then(Value::as_object) else {
            continue;
        };
        for (name, spec) in entries {
            let Some(spec) = spec.as_str() else {
                continue;
            };
            declared.push(DeclaredDependency {
                name: name.clone(),
                section,
                spec: spec.to_string(),
            });
        }
    }
    declared.sort_by(|a, b| {
        a.section
            .label
            .cmp(b.section.label)
            .then_with(|| a.name.cmp(&b.name))
    });
    declared
}

struct ImportUsage {
    used_packages: BTreeSet<String>,
    imports_by_package: BTreeMap<String, Vec<SourceImport>>,
    node_builtins: HashSet<&'static str>,
    uses_node_builtin: bool,
}

impl ImportUsage {
    fn from_imports(imports: Vec<SourceImport>) -> Self {
        let node_builtins = node_builtin_package_names();
        let mut used_packages = BTreeSet::new();
        let mut imports_by_package: BTreeMap<String, Vec<SourceImport>> = BTreeMap::new();
        let mut seen = HashSet::new();
        let mut uses_node_builtin = false;

        for import in imports {
            let Some(package_name) = import.package_name.clone() else {
                continue;
            };
            if !seen.insert((package_name.clone(), import.file.clone(), import.line)) {
                continue;
            }
            if node_builtins.contains(package_name.as_str()) {
                uses_node_builtin = true;
            } else {
                used_packages.insert(package_name.clone());
            }
            imports_by_package
                .entry(package_name)
                .or_default()
                .push(import);
        }

        Self {
            used_packages,
            imports_by_package,
            node_builtins,
            uses_node_builtin,
        }
    }
}

fn filtered_imports(project_dir: &Path, config: &TidyConfig) -> Vec<SourceImport> {
    scan_source_imports(project_dir)
        .into_iter()
        .filter(|import| {
            let rel = relative_display(project_dir, &import.file);
            config.match_path(&rel).is_none()
        })
        .collect()
}

fn absorb_type_package_usage(used: &mut BTreeSet<String>, import_usage: &ImportUsage) {
    let imported: Vec<String> = used.iter().cloned().collect();
    for package in imported {
        if let Some(types_package) = runtime_to_types_package(&package) {
            used.insert(types_package);
        }
    }
    if import_usage.uses_node_builtin {
        used.insert("@types/node".to_string());
    }
}

fn runtime_to_types_package(package: &str) -> Option<String> {
    if package.starts_with("@types/") {
        return None;
    }
    if let Some(rest) = package.strip_prefix('@') {
        let (scope, name) = rest.split_once('/')?;
        return Some(format!("@types/{}__{name}", scope));
    }
    Some(format!("@types/{package}"))
}

fn dependency_is_used(
    name: &str,
    imported: &BTreeSet<String>,
    script_tokens: &BTreeSet<String>,
    script_bins: &HashMap<String, BTreeSet<String>>,
    config_text: &str,
) -> bool {
    imported.contains(name)
        || script_mentions_dependency(name, script_tokens, script_bins)
        || config_mentions_dependency(name, config_text)
        || conservative_dev_tool_keep(name, script_tokens, config_text)
}

fn script_mentions_dependency(
    name: &str,
    script_tokens: &BTreeSet<String>,
    script_bins: &HashMap<String, BTreeSet<String>>,
) -> bool {
    if script_tokens.contains(name) {
        return true;
    }
    if let Some(bins) = script_bins.get(name)
        && bins.iter().any(|bin| script_tokens.contains(bin))
    {
        return true;
    }
    fallback_bin_names(name)
        .into_iter()
        .any(|bin| script_tokens.contains(&bin))
}

fn fallback_bin_names(name: &str) -> BTreeSet<String> {
    let mut bins = BTreeSet::new();
    if let Some((_scope, unscoped)) = name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        bins.insert(unscoped.to_string());
    } else {
        bins.insert(name.to_string());
    }

    match name {
        "typescript" => {
            bins.insert("tsc".to_string());
            bins.insert("tsserver".to_string());
        }
        "webpack-cli" => {
            bins.insert("webpack".to_string());
        }
        "@biomejs/biome" => {
            bins.insert("biome".to_string());
        }
        "@angular/cli" => {
            bins.insert("ng".to_string());
        }
        "@nestjs/cli" => {
            bins.insert("nest".to_string());
        }
        "@sveltejs/kit" => {
            bins.insert("svelte-kit".to_string());
        }
        _ => {}
    }

    bins
}

fn config_mentions_dependency(name: &str, config_text: &str) -> bool {
    if config_text.contains(name) {
        return true;
    }
    if let Some((_scope, unscoped)) = name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        return config_text.contains(unscoped);
    }
    false
}

fn conservative_dev_tool_keep(
    name: &str,
    script_tokens: &BTreeSet<String>,
    config_text: &str,
) -> bool {
    if script_tokens.is_empty() && config_text.is_empty() {
        return false;
    }
    name.starts_with("eslint-")
        || name.starts_with("@typescript-eslint/")
        || name.starts_with("@eslint/")
        || name.starts_with("babel-")
        || name.starts_with("@babel/")
        || name.starts_with("postcss-")
        || name.starts_with("tailwindcss")
        || matches!(
            name,
            "eslint"
                | "prettier"
                | "postcss"
                | "typescript"
                | "vite"
                | "vitest"
                | "jest"
                | "ts-jest"
                | "babel-jest"
                | "webpack"
                | "webpack-cli"
                | "rollup"
                | "parcel"
                | "next"
                | "nuxt"
                | "svelte"
        )
}

fn collect_script_tokens(manifest: &Value) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    let Some(scripts) = manifest.get("scripts").and_then(Value::as_object) else {
        return tokens;
    };
    for script in scripts.values().filter_map(Value::as_str) {
        for token in tokenize_script(script) {
            if !token_is_assignment(&token) {
                tokens.insert(token);
            }
        }
    }
    tokens
}

fn tokenize_script(script: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;

    for ch in script.chars() {
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }

        match ch {
            '"' | '\'' | '`' => quote = Some(ch),
            ' ' | '\t' | '\r' | '\n' | '&' | '|' | ';' | '(' | ')' | '<' | '>' => {
                push_script_token(&mut tokens, &mut current);
            }
            _ => current.push(ch),
        }
    }
    push_script_token(&mut tokens, &mut current);
    tokens
}

fn push_script_token(tokens: &mut Vec<String>, current: &mut String) {
    let token = current
        .trim_matches(|ch: char| matches!(ch, ',' | ':' | '"' | '\'' | '`'))
        .trim();
    if !token.is_empty() {
        tokens.push(token.to_string());
    }
    current.clear();
}

fn token_is_assignment(token: &str) -> bool {
    let Some((name, value)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && !value.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn collect_installed_bin_names<'a>(
    project_dir: &Path,
    package_names: impl Iterator<Item = &'a String>,
) -> HashMap<String, BTreeSet<String>> {
    let mut bins = HashMap::new();
    for name in package_names {
        let manifest = project_dir
            .join("node_modules")
            .join(name)
            .join("package.json");
        let Ok(content) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&content) else {
            continue;
        };
        let Some(package_bins) = bin_names_from_manifest(&value, name) else {
            continue;
        };
        bins.insert(name.clone(), package_bins);
    }
    bins
}

fn bin_names_from_manifest(value: &Value, package_name: &str) -> Option<BTreeSet<String>> {
    match value.get("bin")? {
        Value::String(_) => Some(fallback_bin_names(package_name)),
        Value::Object(map) => {
            let bins: BTreeSet<String> = map.keys().cloned().collect();
            (!bins.is_empty()).then_some(bins)
        }
        _ => None,
    }
}

fn read_known_config_text(project_dir: &Path) -> String {
    static CONFIG_FILES: &[&str] = &[
        ".babelrc",
        ".eslintrc",
        ".eslintrc.cjs",
        ".eslintrc.js",
        ".eslintrc.json",
        ".prettierrc",
        ".prettierrc.cjs",
        ".prettierrc.js",
        ".prettierrc.json",
        "babel.config.cjs",
        "babel.config.js",
        "eslint.config.cjs",
        "eslint.config.js",
        "jest.config.cjs",
        "jest.config.js",
        "next.config.js",
        "nuxt.config.js",
        "postcss.config.cjs",
        "postcss.config.js",
        "prettier.config.cjs",
        "prettier.config.js",
        "rollup.config.js",
        "tailwind.config.cjs",
        "tailwind.config.js",
        "tsconfig.json",
        "vite.config.js",
        "vite.config.ts",
        "vitest.config.js",
        "vitest.config.ts",
        "webpack.config.js",
    ];

    let mut text = String::new();
    for file in CONFIG_FILES {
        if let Ok(content) = std::fs::read_to_string(project_dir.join(file)) {
            text.push_str(&content);
            text.push('\n');
        }
    }
    text
}

fn collect_installed_packages(project_dir: &Path) -> HashSet<String> {
    let mut packages = HashSet::new();
    let node_modules = project_dir.join("node_modules");
    let Ok(entries) = std::fs::read_dir(&node_modules) else {
        return packages;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        if name.starts_with('@') {
            let Ok(scoped) = std::fs::read_dir(path) else {
                continue;
            };
            for child in scoped.flatten() {
                if let Some(child_name) = child.file_name().to_str() {
                    packages.insert(format!("{name}/{child_name}"));
                }
            }
        } else {
            packages.insert(name);
        }
    }

    packages
}

fn collect_workspace_member_names(
    project_dir: &Path,
    manifest: &Value,
) -> Result<BTreeSet<String>, LpmError> {
    let mut names = BTreeSet::new();
    let mut patterns = Vec::new();
    match manifest.get("workspaces") {
        Some(Value::Array(items)) => {
            patterns.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
        }
        Some(Value::Object(map)) => {
            if let Some(Value::Array(items)) = map.get("packages") {
                patterns.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
            }
        }
        _ => {}
    }

    for pattern in patterns {
        let absolute = project_dir.join(pattern).join("package.json");
        let glob_pattern = absolute.to_string_lossy().to_string();
        let paths = glob::glob(&glob_pattern).map_err(|error| {
            LpmError::Registry(format!("invalid workspace glob `{glob_pattern}`: {error}"))
        })?;
        for path in paths.flatten() {
            if path == project_dir.join("package.json") {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<Value>(&content) else {
                continue;
            };
            if let Some(name) = value.get("name").and_then(Value::as_str) {
                names.insert(name.to_string());
            }
        }
    }

    Ok(names)
}

async fn apply_fix(
    client: &RegistryClient,
    project_dir: &Path,
    manifest_path: &Path,
    original_manifest: &[u8],
    manifest: &mut Value,
    analysis: &Analysis,
) -> Result<Vec<RemovedDependency>, LpmError> {
    let fixable: Vec<&UnusedDependency> = analysis
        .unused
        .iter()
        .filter(|dependency| dependency.fixable)
        .collect();
    if fixable.is_empty() {
        return Ok(Vec::new());
    }

    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let lockfile_binary_path = project_dir.join(lpm_lockfile::BINARY_LOCKFILE_NAME);
    let manifest_snapshot = FileSnapshot::Present(original_manifest.to_vec());
    let lockfile_snapshot = FileSnapshot::read(&lockfile_path)?;
    let lockfile_binary_snapshot = FileSnapshot::read(&lockfile_binary_path)?;

    let removed = remove_unused_from_manifest(manifest, &fixable);
    let updated = serde_json::to_string_pretty(manifest)
        .map_err(|error| LpmError::Registry(error.to_string()))?;
    write_file_atomic(manifest_path, format!("{updated}\n")).map_err(LpmError::Io)?;

    let cleanup_removed = || {
        let removed_names: Vec<String> = removed.iter().map(|entry| entry.name.clone()).collect();
        crate::commands::uninstall::cleanup_removed_packages(
            project_dir,
            &removed_names,
            &HashMap::new(),
        )
        .map(|_| ())
    };

    if let Err(error) = reconcile_install(client, project_dir)
        .await
        .and_then(|()| cleanup_removed())
    {
        let restore_result = manifest_snapshot
            .restore(manifest_path)
            .and_then(|()| lockfile_snapshot.restore(&lockfile_path))
            .and_then(|()| lockfile_binary_snapshot.restore(&lockfile_binary_path));
        if let Err(restore_error) = restore_result {
            return Err(LpmError::Registry(format!(
                "tidy --fix failed during install ({error}); also failed to restore manifest/lockfile snapshots: {restore_error}"
            )));
        }
        return Err(LpmError::Registry(format!(
            "tidy --fix failed during install and restored package.json/lpm.lock snapshots: {error}"
        )));
    }

    Ok(removed)
}

fn remove_unused_from_manifest(
    manifest: &mut Value,
    fixable: &[&UnusedDependency],
) -> Vec<RemovedDependency> {
    let mut by_section: BTreeMap<&'static str, BTreeSet<&str>> = BTreeMap::new();
    for dependency in fixable {
        by_section
            .entry(dependency.section)
            .or_default()
            .insert(dependency.name.as_str());
    }

    let mut removed = Vec::new();
    for section in DEPENDENCY_SECTIONS.iter().filter(|section| section.fixable) {
        let Some(names) = by_section.get(section.label) else {
            continue;
        };
        let Some(section_value) = manifest.get_mut(section.key) else {
            continue;
        };
        let Some(entries) = section_value.as_object_mut() else {
            continue;
        };

        for name in names {
            if let Some(spec) = entries
                .remove(*name)
                .and_then(|value| value.as_str().map(str::to_owned))
            {
                removed.push(RemovedDependency {
                    name: (*name).to_string(),
                    section: section.label,
                    spec,
                });
            }
        }
    }

    remove_empty_dependency_sections(manifest);
    removed.sort_by(|a, b| a.section.cmp(b.section).then_with(|| a.name.cmp(&b.name)));
    removed
}

fn remove_empty_dependency_sections(manifest: &mut Value) {
    let Some(object) = manifest.as_object_mut() else {
        return;
    };
    for section in DEPENDENCY_SECTIONS.iter().filter(|section| section.fixable) {
        if object
            .get(section.key)
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
        {
            object.remove(section.key);
        }
    }
}

async fn reconcile_install(client: &RegistryClient, project_dir: &Path) -> Result<(), LpmError> {
    crate::commands::install::run_with_options(
        client,
        project_dir,
        false,
        false,
        FrozenLockfileMode::Never,
        false,
        false,
        false,
        None,
        None,
        true,
        true,
        true,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        crate::provenance_fetch::DriftIgnorePolicy::default(),
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
        InstallOmitPolicy::default(),
        false,
        false,
        false,
        false,
    )
    .await
}

impl TidyConfig {
    fn load(project_dir: &Path) -> Result<Self, LpmError> {
        let path = project_dir.join("lpm.toml");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Ok(Self::default());
        };
        let value: toml::Value = toml::from_str(&content).map_err(|error| {
            LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
        })?;
        let Some(table) = value.get("tidy").and_then(toml::Value::as_table) else {
            return Ok(Self::default());
        };

        Ok(Self {
            ignore_unused: read_pattern_list(table, "ignore-unused", &path)?,
            ignore_phantom: read_pattern_list(table, "ignore-phantom", &path)?,
            ignore_paths: read_pattern_list(table, "ignore-paths", &path)?,
        })
    }

    fn match_unused(&self, name: &str) -> Option<&str> {
        self.ignore_unused
            .iter()
            .find(|pattern| pattern.matches(name))
            .map(|pattern| pattern.raw.as_str())
    }

    fn match_phantom(&self, name: &str) -> Option<&str> {
        self.ignore_phantom
            .iter()
            .find(|pattern| pattern.matches(name))
            .map(|pattern| pattern.raw.as_str())
    }

    fn match_path(&self, rel_path: &str) -> Option<&str> {
        self.ignore_paths
            .iter()
            .find(|pattern| pattern.matches(rel_path))
            .map(|pattern| pattern.raw.as_str())
    }
}

fn read_pattern_list(
    table: &toml::value::Table,
    key: &str,
    path: &Path,
) -> Result<Vec<CompiledPattern>, LpmError> {
    let Some(value) = table.get(key) else {
        return Ok(Vec::new());
    };
    let values = match value {
        toml::Value::String(raw) => vec![raw.clone()],
        toml::Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_owned).ok_or_else(|| {
                    LpmError::Registry(format!(
                        "[tidy] {key} in {} must contain only strings",
                        path.display()
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(LpmError::Registry(format!(
                "[tidy] {key} in {} must be a string or array of strings",
                path.display()
            )));
        }
    };

    values
        .into_iter()
        .map(|raw| CompiledPattern::new(raw, path, key))
        .collect()
}

fn print_human_report(report: &TidyReport) {
    if report.unused.is_empty() && report.phantoms.is_empty() {
        if report.removed.is_empty() {
            install_ui::done("package.json is tidy");
        } else {
            install_ui::done(&format!(
                "Removed {} unused dependency declaration(s)",
                report.removed.len()
            ));
        }
        return;
    }

    if !report.removed.is_empty() {
        install_ui::done(&format!(
            "Removed {} unused dependency declaration(s)",
            report.removed.len()
        ));
        for removed in &report.removed {
            install_ui::detail(&format!(
                "  - {} {}",
                install_ui::cyan(&removed.name),
                install_ui::dim(&format!("{} {}", removed.section, removed.spec))
            ));
        }
    }

    if !report.unused.is_empty() {
        install_ui::warn(&format!(
            "{} unused dependency declaration(s)",
            report.unused.len()
        ));
        for dependency in &report.unused {
            let fix = if dependency.fixable {
                "fixable"
            } else {
                "report-only"
            };
            install_ui::detail(&format!(
                "  - {} {}",
                install_ui::cyan(&dependency.name),
                install_ui::dim(&format!("{} {} {fix}", dependency.section, dependency.spec))
            ));
        }
    }

    if !report.phantoms.is_empty() {
        install_ui::warn(&format!("{} phantom import(s)", report.phantoms.len()));
        for phantom in &report.phantoms {
            install_ui::detail(&format!(
                "  - {} {}",
                install_ui::cyan(&phantom.name),
                install_ui::dim(&format!("{}:{}", phantom.file, phantom.line))
            ));
            if let Some(via) = &phantom.available_via {
                install_ui::detail(&format!("    {}", install_ui::dim(via)));
            }
        }
    }

    if !report.ignored.is_empty() {
        install_ui::detail(&format!(
            "  {} ignored by lpm.toml [tidy]",
            install_ui::dim(&report.ignored.len().to_string())
        ));
    }
}

fn relative_display(project_dir: &Path, path: &Path) -> String {
    path.strip_prefix(project_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tokenize_script_extracts_commands_around_shell_operators() {
        let tokens: BTreeSet<String> = tokenize_script("NODE_ENV=test tsc -p . && vite build")
            .into_iter()
            .filter(|token| !token_is_assignment(token))
            .collect();

        assert!(tokens.contains("tsc"));
        assert!(tokens.contains("vite"));
    }

    #[test]
    fn type_package_mapping_handles_scoped_runtime_packages() {
        assert_eq!(
            runtime_to_types_package("@scope/pkg").as_deref(),
            Some("@types/scope__pkg")
        );
    }

    #[test]
    fn fallback_bin_names_include_common_typescript_binary() {
        assert!(fallback_bin_names("typescript").contains("tsc"));
    }

    #[test]
    fn string_bin_manifest_uses_package_name_as_command() {
        let bins = bin_names_from_manifest(&json!({ "bin": "cli.js" }), "@scope/tool")
            .expect("string bin should produce command names");

        assert!(bins.contains("tool"));
        assert!(!bins.contains("cli.js"));
    }

    #[test]
    fn remove_unused_from_manifest_drops_empty_fixable_sections() {
        let mut manifest = json!({
            "dependencies": { "unused": "^1.0.0" },
            "peerDependencies": { "react": "^18.0.0" }
        });
        let unused = UnusedDependency {
            name: "unused".to_string(),
            section: "dependencies",
            spec: "^1.0.0".to_string(),
            fixable: true,
            reason: String::new(),
        };

        let removed = remove_unused_from_manifest(&mut manifest, &[&unused]);

        assert_eq!(removed.len(), 1);
        assert!(manifest.get("dependencies").is_none());
        assert!(manifest.get("peerDependencies").is_some());
    }
}
