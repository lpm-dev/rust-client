use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

use aho_corasick::AhoCorasick;
use glob::Pattern;
use lpm_common::{LpmError, write_file_atomic};
use lpm_registry::RegistryClient;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::commands::install::{FrozenLockfileMode, InstallOmitPolicy};
use crate::install_ui;
use crate::intelligence::{SourceImport, node_builtin_package_names, scan_source_imports_checked};

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

pub async fn run(
    client: &RegistryClient,
    cwd: &Path,
    fix: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let start = Instant::now();
    let project_dir = cwd;
    let manifest_path = project_dir.join("package.json");
    let manifest_bytes = match lpm_common::read_file_capped(
        &manifest_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return Err(LpmError::NotFound(format!(
                "no package.json found at {}",
                manifest_path.display()
            )));
        }
        Err(error) => return Err(error.into()),
    };
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
            analysis.remove_findings_resolved_by(&removed);
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

impl Analysis {
    fn remove_findings_resolved_by(&mut self, removed: &[RemovedDependency]) {
        let removed_keys: HashSet<(&str, &str)> = removed
            .iter()
            .map(|dependency| (dependency.section, dependency.name.as_str()))
            .collect();
        self.unused.retain(|dependency| {
            !removed_keys.contains(&(dependency.section, dependency.name.as_str()))
        });
        self.declared_count -= removed.len();
    }
}

fn analyze_project(
    project_dir: &Path,
    manifest: &Value,
    config: &TidyConfig,
) -> Result<Analysis, LpmError> {
    let declared = collect_declared_dependencies(manifest);
    let workspace_names = collect_workspace_member_names(project_dir, manifest)?;
    let imports = filtered_imports(project_dir, config)?;
    let import_usage = ImportUsage::from_imports(imports);
    let script_tokens = collect_script_tokens(manifest);
    let script_bins =
        collect_installed_bin_names(project_dir, declared.iter().map(|entry| &entry.name))?;
    let config_text = read_known_config_text(project_dir)?;
    let has_config_text = !config_text.is_empty();
    let config_usage = config_dependency_usage(&declared, &config_text)?;
    drop(config_text);
    let installed = collect_installed_packages(project_dir)?;
    let mut ignored = Vec::new();

    let mut used = import_usage.used_packages.clone();
    absorb_type_package_usage(&mut used, &import_usage);

    let mut unused = Vec::new();
    for (index, entry) in declared.iter().enumerate() {
        let name = &entry.name;
        if dependency_is_used(
            name,
            &used,
            &script_tokens,
            &script_bins,
            config_usage[index],
            has_config_text,
        ) {
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

fn filtered_imports(
    project_dir: &Path,
    config: &TidyConfig,
) -> Result<Vec<SourceImport>, LpmError> {
    Ok(scan_source_imports_checked(project_dir)
        .map_err(LpmError::Io)?
        .into_iter()
        .filter(|import| {
            let rel = relative_display(project_dir, &import.file);
            config.match_path(&rel).is_none()
        })
        .collect())
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
    mentioned_in_config: bool,
    has_config_text: bool,
) -> bool {
    imported.contains(name)
        || script_mentions_dependency(name, script_tokens, script_bins)
        || mentioned_in_config
        || conservative_dev_tool_keep(name, script_tokens, has_config_text)
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
    fallback_bin_is_used(name, script_tokens)
}

fn fallback_bin_is_used(name: &str, script_tokens: &BTreeSet<String>) -> bool {
    let unscoped = name
        .strip_prefix('@')
        .and_then(|rest| rest.split_once('/'))
        .map_or(name, |(_, unscoped)| unscoped);
    if script_tokens.contains(unscoped) {
        return true;
    }
    match name {
        "typescript" => script_tokens.contains("tsc") || script_tokens.contains("tsserver"),
        "webpack-cli" => script_tokens.contains("webpack"),
        "@biomejs/biome" => script_tokens.contains("biome"),
        "@angular/cli" => script_tokens.contains("ng"),
        "@nestjs/cli" => script_tokens.contains("nest"),
        "@sveltejs/kit" => script_tokens.contains("svelte-kit"),
        _ => false,
    }
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

fn config_dependency_usage(
    declared: &[DeclaredDependency],
    config_text: &str,
) -> Result<Vec<bool>, LpmError> {
    let mut usage = vec![false; declared.len()];
    if declared.is_empty() || config_text.is_empty() {
        return Ok(usage);
    }

    let mut pattern_indices: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, dependency) in declared.iter().enumerate() {
        if !dependency.name.is_empty() {
            pattern_indices
                .entry(dependency.name.as_str())
                .or_default()
                .push(index);
        }
        if let Some((_, unscoped)) = dependency
            .name
            .strip_prefix('@')
            .and_then(|rest| rest.split_once('/'))
            && !unscoped.is_empty()
        {
            pattern_indices.entry(unscoped).or_default().push(index);
        }
    }
    if pattern_indices.is_empty() {
        return Ok(usage);
    }

    let (patterns, indices): (Vec<&str>, Vec<Vec<usize>>) = pattern_indices.into_iter().unzip();
    let matcher = AhoCorasick::new(patterns.iter().copied()).map_err(|error| {
        LpmError::Registry(format!(
            "failed to prepare tidy config dependency matching: {error}"
        ))
    })?;
    for matched in matcher.find_overlapping_iter(config_text) {
        for index in &indices[matched.pattern().as_usize()] {
            usage[*index] = true;
        }
    }
    Ok(usage)
}

fn conservative_dev_tool_keep(
    name: &str,
    script_tokens: &BTreeSet<String>,
    has_config_text: bool,
) -> bool {
    if script_tokens.is_empty() && !has_config_text {
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
) -> Result<HashMap<String, BTreeSet<String>>, LpmError> {
    let mut bins = HashMap::new();
    for name in package_names {
        let manifest = project_dir
            .join("node_modules")
            .join(name)
            .join("package.json");
        let content = match lpm_common::read_text_file_capped(
            &manifest,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => continue,
            Err(error) => return Err(error.into()),
        };
        let value = serde_json::from_str::<Value>(&content).map_err(|error| {
            LpmError::Registry(format!(
                "failed to parse installed package manifest {} while analyzing scripts: {error}",
                manifest.display()
            ))
        })?;
        let Some(package_bins) = bin_names_from_manifest(&value, name) else {
            continue;
        };
        bins.insert(name.clone(), package_bins);
    }
    Ok(bins)
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

fn read_known_config_text(project_dir: &Path) -> Result<String, LpmError> {
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

    const MAX_TOTAL_CONFIG_BYTES: usize = 64 * 1024 * 1024;

    let mut text = String::with_capacity(8192);
    for file in CONFIG_FILES {
        let path = project_dir.join(file);
        let content = match lpm_common::read_text_file_capped(
            &path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => continue,
            Err(error) => return Err(error.into()),
        };
        let next_len = text
            .len()
            .checked_add(content.len())
            .and_then(|len| len.checked_add(1))
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "known tidy config files exceed the {MAX_TOTAL_CONFIG_BYTES}-byte aggregate limit"
                ))
            })?;
        if next_len > MAX_TOTAL_CONFIG_BYTES {
            return Err(LpmError::Registry(format!(
                "known tidy config files exceed the {MAX_TOTAL_CONFIG_BYTES}-byte aggregate limit at {}",
                path.display()
            )));
        }
        text.push_str(&content);
        text.push('\n');
    }
    Ok(text)
}

fn collect_installed_packages(project_dir: &Path) -> Result<HashSet<String>, LpmError> {
    let mut packages = HashSet::new();
    let node_modules = project_dir.join("node_modules");
    let entries = match std::fs::read_dir(&node_modules) {
        Ok(entries) => entries,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(packages),
        Err(source) => {
            return Err(LpmError::Io(tidy_io_error(
                "read installed package directory",
                &node_modules,
                source,
            )));
        }
    };

    for entry in entries {
        let entry = entry.map_err(|source| {
            LpmError::Io(tidy_io_error(
                "read installed package entry",
                &node_modules,
                source,
            ))
        })?;
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        if name.starts_with('@') {
            let file_type = entry.file_type().map_err(|source| {
                LpmError::Io(tidy_io_error(
                    "inspect installed package scope",
                    &path,
                    source,
                ))
            })?;
            if file_type.is_symlink() || !file_type.is_dir() {
                continue;
            }
            let scoped = std::fs::read_dir(&path).map_err(|source| {
                LpmError::Io(tidy_io_error("read installed package scope", &path, source))
            })?;
            for child in scoped {
                let child = child.map_err(|source| {
                    LpmError::Io(tidy_io_error(
                        "read installed scoped package entry",
                        &path,
                        source,
                    ))
                })?;
                if let Some(child_name) = child.file_name().to_str() {
                    packages.insert(format!("{name}/{child_name}"));
                }
            }
        } else {
            packages.insert(name);
        }
    }

    Ok(packages)
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
        for path in paths {
            let path = path.map_err(|error| {
                LpmError::Registry(format!(
                    "failed to enumerate workspace glob `{glob_pattern}`: {error}"
                ))
            })?;
            if path == project_dir.join("package.json") {
                continue;
            }
            let content =
                lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)?;
            let value = serde_json::from_str::<Value>(&content).map_err(|error| {
                LpmError::Registry(format!(
                    "failed to parse workspace package manifest {} during tidy analysis: {error}",
                    path.display()
                ))
            })?;
            if let Some(name) = value.get("name").and_then(Value::as_str) {
                names.insert(name.to_string());
            }
        }
    }

    Ok(names)
}

fn tidy_io_error(action: &str, path: &Path, source: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        source.kind(),
        format!("failed to {action} at {}: {source}", path.display()),
    )
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

    let project_dirs = [project_dir.to_path_buf()];
    crate::commands::install::workspace_lockfile::scope_workspace_mutation_if_present(
        project_dir,
        &project_dirs,
        async {
            let lockfile_path =
                crate::commands::install::workspace_lockfile::active_lockfile_path(project_dir);
            let lockfile_binary_path = lockfile_path.with_extension("lockb");
            let install_hash_path = project_dir.join(".lpm").join("install-hash");
            let transaction =
                crate::manifest_tx::ManifestTransaction::snapshot_install_state_if_unchanged(
                    &[(manifest_path, original_manifest)],
                    &[lockfile_path.as_path(), lockfile_binary_path.as_path()],
                    &[install_hash_path.as_path()],
                )
                .map_err(|error| {
                    LpmError::Registry(format!(
                        "package.json changed while tidy was analyzing the project; no changes were applied: {error}"
                    ))
                })?;

            let removed = remove_unused_from_manifest(manifest, &fixable);
            let updated = serde_json::to_string_pretty(manifest)
                .map_err(|error| LpmError::Registry(error.to_string()))?;
            write_file_atomic(manifest_path, format!("{updated}\n")).map_err(LpmError::Io)?;

            reconcile_install(client, project_dir).await?;
            let removed_names = removed
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>();
            crate::commands::uninstall::cleanup_removed_packages(
                project_dir,
                &removed_names,
                &HashMap::new(),
            )?;
            crate::commands::install::workspace_lockfile::commit_manifest_transaction(transaction);
            Ok(removed)
        },
    )
    .await
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
        false,
        None,
        None,
        crate::lpm_skills_config::LpmSkillsPreference::Disabled,
        true,
        true,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        &[],
        crate::provenance_fetch::DriftIgnorePolicy::default(),
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
        InstallOmitPolicy::default(),
        false,
        false,
        false,
        false,
        false,
        &[],
    )
    .await
}

impl TidyConfig {
    fn load(project_dir: &Path) -> Result<Self, LpmError> {
        let path = project_dir.join("lpm.toml");
        let content = match lpm_common::read_text_file_capped(
            &path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
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
            install_ui::done_untrusted(&format!(
                "Removed {} unused dependency declaration(s)",
                report.removed.len()
            ));
        }
        return;
    }

    if !report.removed.is_empty() {
        install_ui::done_untrusted(&format!(
            "Removed {} unused dependency declaration(s)",
            report.removed.len()
        ));
        for removed in &report.removed {
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "  - {} {}",
                install_ui::cyan(&removed.name),
                install_ui::dim(&format!("{} {}", removed.section, removed.spec))
            ));
        }
    }

    if !report.unused.is_empty() {
        install_ui::warn_untrusted(&format!(
            "{} unused dependency declaration(s)",
            report.unused.len()
        ));
        for dependency in &report.unused {
            let fix = if dependency.fixable {
                "fixable"
            } else {
                "report-only"
            };
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "  - {} {}",
                install_ui::cyan(&dependency.name),
                install_ui::dim(&format!("{} {} {fix}", dependency.section, dependency.spec))
            ));
        }
    }

    if !report.phantoms.is_empty() {
        install_ui::warn_untrusted(&format!("{} phantom import(s)", report.phantoms.len()));
        for phantom in &report.phantoms {
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "  - {} {}",
                install_ui::cyan(&phantom.name),
                install_ui::dim(&format!("{}:{}", phantom.file, phantom.line))
            ));
            if let Some(via) = &phantom.available_via {
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "    {}",
                    install_ui::dim(via)
                ));
            }
        }
    }

    if !report.ignored.is_empty() {
        install_ui::detail_line(crate::install_ui::terminal_line!(
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
    fn config_dependency_usage_preserves_overlapping_and_scoped_matches() {
        let dependencies = [
            DeclaredDependency {
                name: "foo".to_string(),
                section: DEPENDENCY_SECTIONS[0],
                spec: "1.0.0".to_string(),
            },
            DeclaredDependency {
                name: "foobar".to_string(),
                section: DEPENDENCY_SECTIONS[0],
                spec: "1.0.0".to_string(),
            },
            DeclaredDependency {
                name: "@scope/plugin".to_string(),
                section: DEPENDENCY_SECTIONS[1],
                spec: "1.0.0".to_string(),
            },
        ];

        let usage = config_dependency_usage(&dependencies, "use foobar and plugin").unwrap();

        assert_eq!(usage, vec![true, true, true]);
    }

    #[test]
    fn resolved_removals_update_analysis_without_discarding_unchanged_evidence() {
        let mut analysis = Analysis {
            unused: vec![
                UnusedDependency {
                    name: "removed".to_string(),
                    section: "dependencies",
                    spec: "1.0.0".to_string(),
                    fixable: true,
                    reason: String::new(),
                },
                UnusedDependency {
                    name: "peer-contract".to_string(),
                    section: "peerDependencies",
                    spec: "1.0.0".to_string(),
                    fixable: false,
                    reason: String::new(),
                },
            ],
            phantoms: vec![PhantomDependency {
                name: "phantom".to_string(),
                file: "src/index.js".to_string(),
                line: 1,
                import_count: 1,
                available_via: None,
            }],
            ignored: vec![IgnoredFinding {
                kind: "unused",
                name: "ignored".to_string(),
                reason: String::new(),
            }],
            declared_count: 3,
            imported_count: 1,
        };

        analysis.remove_findings_resolved_by(&[RemovedDependency {
            name: "removed".to_string(),
            section: "dependencies",
            spec: "1.0.0".to_string(),
        }]);

        assert_eq!(analysis.declared_count, 2);
        assert_eq!(analysis.unused.len(), 1);
        assert_eq!(analysis.unused[0].name, "peer-contract");
        assert_eq!(analysis.phantoms.len(), 1);
        assert_eq!(analysis.ignored.len(), 1);
        assert_eq!(analysis.imported_count, 1);
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
