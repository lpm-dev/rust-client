//! The archive checks of a JavaScript package.

use super::js_api::{self, ModuleFacts};
use super::markdown;
use super::npm::{self, Exports, Target};
use super::{
    CLEAN_ARCHIVE_MAX_BYTES, CheckResult, Context, QualityEcosystem, Results, changelog_check,
    coverage_points, description_check, keywords_check, license_check, license_file_check,
    readme_check, repository_check,
};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

pub(super) fn run(context: &Context<'_>) -> Vec<CheckResult> {
    let mut results = Results::new(QualityEcosystem::Js);
    readme_check(context, &mut results);
    changelog_check(context, &mut results);
    license_check(context, &mut results);
    license_file_check(context, &mut results);
    description_check(context, &mut results);
    keywords_check(context, &mut results);
    repository_check(context, &mut results);
    clean_archive(context, &mut results);
    let Some(json) = context.manifest else {
        for id in [
            "readme-install",
            "readme-example",
            "api-docs",
            "entry-points",
            "types",
            "esm",
            "exports-map",
            "side-effects",
            "engines",
            "no-install-scripts",
            "lean-install",
        ] {
            results.fail(id, "No readable package.json at the package root");
        }
        return results.finish();
    };
    let package = Package::new(context, json);
    readme_install(context, &mut results);
    readme_example(context, &package, &mut results);
    api_docs(&package, &mut results);
    entry_points(&package, &mut results);
    types(&package, &mut results);
    esm(&package, &mut results);
    exports_map(&package, &mut results);
    side_effects(json, &mut results);
    engines(json, &mut results);
    install_scripts(context, json, &mut results);
    lean_install(json, &mut results);
    results.finish()
}

/// A JavaScript package's manifest over its archive, with each module it
/// reads parsed once.
struct Package<'a> {
    context: &'a Context<'a>,
    json: &'a Value,
    exports: Option<Result<Exports<'a>, String>>,
    facts: RefCell<HashMap<String, Option<Rc<ModuleFacts>>>>,
    export_sets: RefCell<HashMap<String, Rc<ExportSet>>>,
    /// Names every export set together has kept, against
    /// `MAX_EXPORT_ENTRIES`.
    export_entries: Cell<usize>,
}

/// What a module exports by name, re-exports followed.
#[derive(Debug, Default)]
struct ExportSet {
    names: BTreeMap<Rc<str>, Symbol>,
    /// A re-export from another package or an unread file left names out,
    /// or the package re-exports more names than the checks keep.
    incomplete: bool,
}

#[derive(Debug, Clone)]
struct Symbol {
    /// The declaring file and local name, or `None` for a name another
    /// package declares. Shared by every module that re-exports it.
    key: Option<Rc<(String, String)>>,
    documented: bool,
}

impl Symbol {
    /// Whether two star re-exports reach the same binding, which Node.js
    /// requires of a name more than one of them provides.
    fn same_binding(&self, other: &Symbol) -> bool {
        match (&self.key, &other.key) {
            (Some(left), Some(right)) => Rc::ptr_eq(left, right) || left == right,
            (None, None) => true,
            _ => false,
        }
    }
}

const MAX_REEXPORT_DEPTH: usize = 64;
/// Names every module's export set may keep in all: barrels re-exporting
/// one another would otherwise copy each name into every barrel.
const MAX_EXPORT_ENTRIES: usize = 200_000;
/// Subpaths a pattern in `exports` may add to the API docs check.
const MAX_PATTERN_SUBPATHS: usize = 256;

impl<'a> Package<'a> {
    fn new(context: &'a Context<'a>, json: &'a Value) -> Self {
        Self {
            context,
            json,
            // Node.js reads `"exports": null` as no `exports`.
            exports: json
                .get("exports")
                .filter(|exports| !exports.is_null())
                .map(Exports::parse),
            facts: RefCell::new(HashMap::new()),
            export_sets: RefCell::new(HashMap::new()),
            export_entries: Cell::new(0),
        }
    }

    fn archive(&self) -> &super::Archive {
        self.context.archive
    }

    fn exports(&self) -> Option<&Exports<'a>> {
        self.exports
            .as_ref()
            .and_then(|exports| exports.as_ref().ok())
    }

    /// The `type` of the package.json nearest to `path`, which Node.js
    /// reads for a `.js` file: `None` when that package.json has none.
    fn module_type_for(&self, path: &str) -> Option<&str> {
        let mut directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
        loop {
            if directory.is_empty() {
                return npm::string(self.json, "type");
            }
            if let Some(scope) = self.archive().scope(directory) {
                return scope;
            }
            directory = directory.rsplit_once('/').map_or("", |(parent, _)| parent);
        }
    }

    /// Takes room for `count` more names, or `false` once the export sets
    /// together would keep more than `MAX_EXPORT_ENTRIES`.
    fn take_export_entries(&self, count: usize) -> bool {
        let used = self.export_entries.get().saturating_add(count);
        if used > MAX_EXPORT_ENTRIES {
            return false;
        }
        self.export_entries.set(used);
        true
    }

    fn export_budget_spent(&self) -> bool {
        self.export_entries.get() >= MAX_EXPORT_ENTRIES
    }

    fn facts(&self, path: &str) -> Option<Rc<ModuleFacts>> {
        if let Some(cached) = self.facts.borrow().get(path) {
            return cached.clone();
        }
        let facts = self
            .archive()
            .retained(path)
            .and_then(|source| js_api::module_facts(path, source))
            .map(Rc::new);
        self.facts
            .borrow_mut()
            .insert(path.to_string(), facts.clone());
        facts
    }

    /// The file a relative specifier in `from` names, as TypeScript finds a
    /// declaration or Node.js a module.
    fn resolve_specifier(&self, from: &str, specifier: &str) -> Option<String> {
        if !specifier.starts_with("./") && !specifier.starts_with("../") {
            return None;
        }
        let directory = from.rsplit_once('/').map_or("", |(directory, _)| directory);
        let joined = if directory.is_empty() {
            specifier.to_string()
        } else {
            format!("{directory}/{specifier}")
        };
        let path = npm::normalize(&joined)?;
        let archive = self.archive();
        let candidates: Vec<String> = if npm::is_typescript_source(from) {
            // TypeScript source imports `./x`, `./x.js` or `./x.ts` for `x.ts`.
            let mut candidates = npm::declaration_candidates(&path);
            candidates.extend(["ts", "tsx", "d.ts"].map(|extension| format!("{path}.{extension}")));
            candidates.extend(
                ["index.ts", "index.tsx", "index.d.ts"].map(|index| format!("{path}/{index}")),
            );
            candidates
        } else if npm::is_declaration(from) {
            let mut candidates = Vec::with_capacity(6);
            if npm::is_declaration(&path) {
                candidates.push(path.clone());
            }
            if let Some(declaration) = npm::sibling_declaration(&path) {
                candidates.push(declaration);
            }
            for (source, declaration) in [(".ts", ".d.ts"), (".mts", ".d.mts"), (".cts", ".d.cts")]
            {
                if let Some(stem) = path.strip_suffix(source)
                    && !npm::is_declaration(&path)
                {
                    candidates.push(format!("{stem}{declaration}"));
                }
            }
            candidates.push(format!("{path}.d.ts"));
            candidates.push(format!("{path}/index.d.ts"));
            candidates
        } else {
            vec![
                path.clone(),
                format!("{path}.js"),
                format!("{path}.mjs"),
                format!("{path}/index.js"),
            ]
        };
        candidates
            .into_iter()
            .find(|candidate| archive.has(candidate))
    }

    /// What `path` exports, re-exports followed. A module re-exporting
    /// itself through a cycle contributes nothing the second time.
    fn export_set(&self, path: &str) -> Rc<ExportSet> {
        let mut visiting = HashSet::new();
        self.export_set_within(path, &mut visiting, 0)
    }

    fn export_set_within(
        &self,
        path: &str,
        visiting: &mut HashSet<String>,
        depth: usize,
    ) -> Rc<ExportSet> {
        if let Some(set) = self.export_sets.borrow().get(path) {
            return Rc::clone(set);
        }
        if depth > MAX_REEXPORT_DEPTH || !visiting.insert(path.to_string()) {
            return Rc::new(ExportSet {
                names: BTreeMap::new(),
                incomplete: depth > MAX_REEXPORT_DEPTH,
            });
        }
        let mut set = ExportSet::default();
        match self.facts(path) {
            None => set.incomplete = true,
            Some(facts) => {
                if !self.take_export_entries(facts.local.len() + facts.named_reexports.len()) {
                    set.incomplete = true;
                    visiting.remove(path);
                    return Rc::new(set);
                }
                for export in &facts.local {
                    set.names.insert(
                        Rc::from(export.name.as_str()),
                        Symbol {
                            key: Some(Rc::new((path.to_string(), export.local.clone()))),
                            documented: export.documented,
                        },
                    );
                }
                for (exported, imported, specifier) in &facts.named_reexports {
                    let symbol = match self.resolve_specifier(path, specifier) {
                        Some(target) => {
                            let target_set = self.export_set_within(&target, visiting, depth + 1);
                            match target_set.names.get(imported.as_str()) {
                                Some(symbol) => symbol.clone(),
                                None => {
                                    set.incomplete |= target_set.incomplete;
                                    Symbol {
                                        key: None,
                                        documented: false,
                                    }
                                }
                            }
                        }
                        None => Symbol {
                            key: None,
                            documented: false,
                        },
                    };
                    set.names.insert(Rc::from(exported.as_str()), symbol);
                }
                // Names a module declares or re-exports by name shadow its
                // star re-exports. A name two star re-exports bind to
                // different declarations is ambiguous, and Node.js leaves it
                // out.
                let explicit: HashSet<Rc<str>> = set.names.keys().cloned().collect();
                let mut ambiguous: HashSet<Rc<str>> = HashSet::new();
                'stars: for specifier in &facts.star_reexports {
                    let Some(target) = self.resolve_specifier(path, specifier) else {
                        set.incomplete = true;
                        continue;
                    };
                    let target_set = self.export_set_within(&target, visiting, depth + 1);
                    set.incomplete |= target_set.incomplete;
                    for (name, symbol) in &target_set.names {
                        if &**name == "default"
                            || explicit.contains(name)
                            || ambiguous.contains(name)
                        {
                            continue;
                        }
                        match set.names.get(name) {
                            Some(existing) if existing.same_binding(symbol) => {}
                            Some(_) => {
                                set.names.remove(name);
                                ambiguous.insert(Rc::clone(name));
                            }
                            None => {
                                if !self.take_export_entries(1) {
                                    set.incomplete = true;
                                    break 'stars;
                                }
                                set.names.insert(Rc::clone(name), symbol.clone());
                            }
                        }
                    }
                }
            }
        }
        visiting.remove(path);
        let set = Rc::new(set);
        self.export_sets
            .borrow_mut()
            .insert(path.to_string(), Rc::clone(&set));
        set
    }

    /// The subpaths `exports` maps, with each a pattern maps expanded over
    /// the files it matches (at most `MAX_PATTERN_SUBPATHS`), or `.` alone
    /// for a package without `exports`.
    fn subpaths(&self) -> Vec<String> {
        let Some(exports) = self.exports() else {
            return vec![".".to_string()];
        };
        let mut subpaths = Vec::new();
        let mut expanded = 0usize;
        for (subpath, target) in &exports.entries {
            let Some((key_prefix, key_suffix)) = subpath.split_once('*') else {
                subpaths.push((*subpath).to_string());
                continue;
            };
            if expanded == MAX_PATTERN_SUBPATHS {
                continue;
            }
            let Some((conditions, pattern)) =
                [npm::TYPES_IMPORT_CONDITIONS, npm::IMPORT_CONDITIONS]
                    .iter()
                    .find_map(|conditions| {
                        target
                            .resolve(conditions)
                            .map(|resolution| (*conditions, resolution.path))
                    })
            else {
                continue;
            };
            let Some(files) = npm::pattern_matches(self.archive(), pattern) else {
                continue;
            };
            for (file, matched) in files {
                if expanded == MAX_PATTERN_SUBPATHS {
                    break;
                }
                let subpath = format!("{key_prefix}{matched}{key_suffix}");
                // A more specific subpath, such as a null pattern, may keep it
                // from consumers.
                if exports
                    .resolve_subpath(&subpath, conditions)
                    .is_some_and(|(resolved, _)| resolved == file)
                {
                    subpaths.push(subpath);
                    expanded += 1;
                }
            }
        }
        subpaths
    }

    /// The declaration file TypeScript reads for `subpath` under
    /// `conditions`, when it exists.
    fn declaration_for(
        &self,
        subpath: &str,
        types_conditions: &[&str],
        runtime: &[&str],
    ) -> Option<String> {
        let archive = self.archive();
        match self.exports() {
            Some(exports) => {
                let (path, via_types) = exports.resolve_subpath(subpath, types_conditions)?;
                if via_types || npm::is_declaration(&path) {
                    return npm::declaration_at(archive, &path);
                }
                let (runtime_path, _) = exports.resolve_subpath(subpath, runtime)?;
                npm::declaration_at(archive, &runtime_path)
            }
            None if subpath == "." => {
                for field in ["types", "typings"] {
                    if let Some(raw) = npm::string(self.json, field) {
                        return npm::types_field_file(archive, raw)
                            .and_then(|file| npm::declaration_at(archive, &file));
                    }
                }
                self.main()
                    .and_then(|main| npm::declaration_at(archive, &main))
                    .or_else(|| archive.has("index.d.ts").then(|| "index.d.ts".to_string()))
            }
            None => None,
        }
    }

    /// The runtime entry Node.js loads for `subpath` under `conditions`.
    fn runtime_entry(&self, subpath: &str, conditions: &[&str]) -> Option<String> {
        match self.exports() {
            Some(exports) => exports
                .resolve_subpath(subpath, conditions)
                .map(|(path, _)| path),
            None if subpath == "." => self.main(),
            None => None,
        }
    }

    fn main(&self) -> Option<String> {
        match npm::string(self.json, "main") {
            Some(raw) => npm::resolve_main(self.archive(), raw),
            None => npm::resolve_main(self.archive(), "index"),
        }
    }

    /// The ESM file `import` loads for `subpath`.
    fn esm_entry(&self, subpath: &str) -> Option<String> {
        if self.exports().is_some() {
            return self.runtime_entry(subpath, npm::IMPORT_CONDITIONS);
        }
        if subpath != "." {
            return None;
        }
        if let Some(module) = npm::string(self.json, "module").and_then(npm::normalize) {
            let archive = self.archive();
            if archive.has(&module) {
                return Some(module);
            }
            let with_extension = format!("{module}.js");
            if archive.has(&with_extension) {
                return Some(with_extension);
            }
        }
        self.main().filter(|main| {
            main.ends_with(".mjs")
                || (main.ends_with(".js")
                    && matches!(self.module_type_for(main), Some("module") | None))
        })
    }

    /// Whether Node.js loads `path` as an ES module: `.mjs`, `.js` whose
    /// nearest package.json sets `"type": "module"`, or `.js` whose nearest
    /// package.json sets no `type` and whose syntax is ESM, which Node.js
    /// detects. JSX, which Node.js can't run, never is.
    fn loads_as_esm(&self, path: &str, facts: &ModuleFacts) -> bool {
        if facts.jsx {
            return false;
        }
        if path.ends_with(".mjs") {
            return facts.esm_syntax;
        }
        if !path.ends_with(".js") {
            return false;
        }
        match self.module_type_for(path) {
            Some("module") | None => facts.esm_syntax,
            _ => false,
        }
    }

    /// The names `specifier` (the package or one of its subpaths) exports,
    /// or `None` when they can't be read.
    fn names_of(&self, specifier: &str) -> Option<Rc<ExportSet>> {
        let name = self.context.package_name()?;
        let subpath = match specifier.strip_prefix(name)? {
            "" => ".".to_string(),
            rest => format!(".{rest}"),
        };
        let file = self
            .declaration_for(
                &subpath,
                npm::TYPES_IMPORT_CONDITIONS,
                npm::IMPORT_CONDITIONS,
            )
            .or_else(|| {
                self.declaration_for(
                    &subpath,
                    npm::TYPES_REQUIRE_CONDITIONS,
                    npm::REQUIRE_CONDITIONS,
                )
            })
            .or_else(|| self.esm_entry(&subpath))?;
        let set = self.export_set(&file);
        (!set.names.is_empty() || !set.incomplete).then_some(set)
    }
}

const JS_LANGUAGES: &[&str] = &["js", "javascript", "jsx", "mjs", "cjs"];
const TS_LANGUAGES: &[&str] = &["ts", "typescript", "tsx", "mts", "cts"];

fn readme_install(context: &Context<'_>, results: &mut Results) {
    let Some(text) = context.readme_text() else {
        results.fail("readme-install", "No README");
        return;
    };
    let Some(name) = context.package_name() else {
        results.fail("readme-install", "package.json names no package");
        return;
    };
    let readme = markdown::Readme::parse(text);
    let installers = markdown::Installers {
        javascript: true,
        source_delivery: context.is_source_package(),
    };
    match markdown::find_install_command(&readme.blocks, name, installers) {
        Some(line) => results.pass("readme-install", format!("README shows `{}`", line.trim())),
        None => results.fail(
            "readme-install",
            format!("No README code block installs {name} with lpm, npm, pnpm, yarn or bun"),
        ),
    }
}

fn readme_example(context: &Context<'_>, package: &Package<'_>, results: &mut Results) {
    let Some(text) = context.readme_text() else {
        results.fail("readme-example", "No README");
        return;
    };
    let Some(name) = context.package_name() else {
        results.fail("readme-example", "package.json names no package");
        return;
    };
    let readme = markdown::Readme::parse(text);
    let imports: Vec<js_api::ExampleImport> = readme
        .blocks
        .iter()
        .filter_map(|block| {
            let typescript = TS_LANGUAGES.contains(&block.language.as_str());
            (typescript || JS_LANGUAGES.contains(&block.language.as_str()))
                .then(|| js_api::example_imports(block.body, typescript, name))
        })
        .flatten()
        .collect();
    if imports.is_empty() {
        results.fail(
            "readme-example",
            format!("No js or ts code block in the README imports {name}"),
        );
        return;
    }
    for import in &imports {
        let Some(set) = package.names_of(&import.specifier) else {
            results.score(
                "readme-example",
                2,
                format!(
                    "The example imports {}, whose exports couldn't be read",
                    import.specifier
                ),
            );
            return;
        };
        let Some(names) = &import.names else {
            if set.names.is_empty() {
                results.score(
                    "readme-example",
                    2,
                    format!("{} exports nothing the example could use", import.specifier),
                );
                return;
            }
            continue;
        };
        if let Some(missing) = names
            .iter()
            .find(|imported| !set.names.contains_key(imported.as_str()))
        {
            let detail = if set.incomplete {
                format!(
                    "The example imports {missing} from {}, which couldn't be confirmed",
                    import.specifier
                )
            } else {
                format!(
                    "The example imports {missing}, which {} doesn't export",
                    import.specifier
                )
            };
            results.score("readme-example", 2, detail);
            return;
        }
    }
    results.pass(
        "readme-example",
        "The README imports the package by name, using names it exports",
    );
}

fn api_docs(package: &Package<'_>, results: &mut Results) {
    let mut files: Vec<String> = Vec::new();
    let subpaths = package.subpaths();
    let mut seen = HashSet::new();
    for subpath in &subpaths {
        for (types, runtime) in [
            (npm::TYPES_IMPORT_CONDITIONS, npm::IMPORT_CONDITIONS),
            (npm::TYPES_REQUIRE_CONDITIONS, npm::REQUIRE_CONDITIONS),
        ] {
            if let Some(file) = package.declaration_for(subpath, types, runtime)
                && seen.insert(file.clone())
            {
                files.push(file);
            }
        }
    }
    let source = if files.is_empty() {
        for subpath in &subpaths {
            if let Some(entry) = package.esm_entry(subpath)
                && package
                    .facts(&entry)
                    .is_some_and(|facts| package.loads_as_esm(&entry, &facts))
                && seen.insert(entry.clone())
            {
                files.push(entry);
            }
        }
        "ESM entry"
    } else {
        "type declarations"
    };
    if files.is_empty() {
        results.fail(
            "api-docs",
            "No type declarations or ESM entry to read the exports from",
        );
        return;
    }
    let mut symbols: HashMap<Rc<(String, String)>, bool> = HashMap::new();
    for file in &files {
        for symbol in package.export_set(file).names.values() {
            if let Some(key) = &symbol.key {
                let documented = symbols.entry(Rc::clone(key)).or_insert(false);
                *documented |= symbol.documented;
            }
        }
    }
    if package.export_budget_spent() {
        results.fail(
            "api-docs",
            format!(
                "The package re-exports more than {MAX_EXPORT_ENTRIES} names across its modules, more than the check reads"
            ),
        );
        return;
    }
    let total = symbols.len();
    if total == 0 {
        results.fail(
            "api-docs",
            format!("Found no exported declarations in the {source}"),
        );
        return;
    }
    let documented = symbols.values().filter(|documented| **documented).count();
    let unread = package.archive().unretained();
    let unread_note = if unread > 0 {
        format!(
            "; {unread} file{} over the read limit unchecked",
            if unread == 1 { "" } else { "s" }
        )
    } else {
        String::new()
    };
    results.score(
        "api-docs",
        coverage_points(documented, total),
        format!(
            "{documented} of {total} exports in the {source} have doc comments ({}%){unread_note}",
            documented * 100 / total
        ),
    );
}

fn entry_points(package: &Package<'_>, results: &mut Results) {
    let archive = package.archive();
    let json = package.json;
    let mut declared = 0usize;
    let mut missing: Vec<String> = Vec::new();
    let mut check = |field: &str, raw: &str, exists: bool| {
        declared += 1;
        if !exists {
            missing.push(format!("{field} {raw}"));
        }
    };
    if let Some(raw) = npm::string(json, "main") {
        check("main", raw, npm::resolve_main(archive, raw).is_some());
    }
    if let Some(raw) = npm::string(json, "module") {
        let exists = npm::normalize(raw)
            .is_some_and(|path| archive.has(&path) || archive.has(&format!("{path}.js")));
        check("module", raw, exists);
    }
    for field in ["types", "typings"] {
        if let Some(raw) = npm::string(json, field) {
            check(field, raw, npm::types_field_file(archive, raw).is_some());
        }
    }
    match json.get("bin") {
        Some(Value::String(raw)) => {
            check(
                "bin",
                raw,
                npm::normalize(raw).is_some_and(|path| archive.has(&path)),
            );
        }
        Some(Value::Object(bins)) => {
            for raw in bins.values().filter_map(Value::as_str) {
                check(
                    "bin",
                    raw,
                    npm::normalize(raw).is_some_and(|path| archive.has(&path)),
                );
            }
        }
        _ => {}
    }
    if let Some(exports) = package.exports() {
        for (_, target) in &exports.entries {
            let mut paths = Vec::new();
            target.paths(&mut paths);
            for (raw, via_types) in paths {
                check(
                    "exports",
                    raw,
                    npm::condition_target_exists(archive, raw, via_types),
                );
            }
        }
    }
    if let Some(Err(reason)) = &package.exports {
        results.fail("entry-points", reason.clone());
        return;
    }
    if declared == 0 {
        if archive.has("index.js") {
            results.pass(
                "entry-points",
                "No entry fields; Node.js loads index.js, which exists",
            );
        } else {
            results.fail(
                "entry-points",
                "package.json declares no entry point and the package has no index.js",
            );
        }
        return;
    }
    if missing.is_empty() {
        results.pass(
            "entry-points",
            format!(
                "All {declared} declared entry path{} exist",
                if declared == 1 { "" } else { "s" }
            ),
        );
    } else {
        let shown: Vec<&str> = missing.iter().take(3).map(String::as_str).collect();
        results.fail(
            "entry-points",
            format!(
                "{} of {declared} declared paths are missing: {}",
                missing.len(),
                shown.join(", ")
            ),
        );
    }
}

/// An exports entry under one of `import` and `require`, and whether
/// TypeScript finds declarations for it.
struct TypedEntry {
    label: String,
    typed: bool,
}

fn is_javascript(path: &str) -> bool {
    [".js", ".mjs", ".cjs", ".jsx"]
        .iter()
        .any(|extension| path.ends_with(extension))
        && !npm::is_declaration(path)
}

fn typed_entries(package: &Package<'_>) -> Vec<TypedEntry> {
    let archive = package.archive();
    let mut entries = Vec::new();
    let Some(exports) = package.exports() else {
        let Some(main) = package.main() else {
            return entries;
        };
        entries.push(TypedEntry {
            typed: package
                .declaration_for(".", npm::TYPES_IMPORT_CONDITIONS, npm::IMPORT_CONDITIONS)
                .is_some(),
            label: main,
        });
        return entries;
    };
    let modes = [
        (
            "import",
            npm::IMPORT_CONDITIONS,
            npm::TYPES_IMPORT_CONDITIONS,
        ),
        (
            "require",
            npm::REQUIRE_CONDITIONS,
            npm::TYPES_REQUIRE_CONDITIONS,
        ),
    ];
    for (subpath, target) in &exports.entries {
        for (mode, runtime, types) in modes {
            let Some(runtime_resolution) = target.resolve(runtime) else {
                continue;
            };
            let runtime_raw = runtime_resolution.path;
            let label = format!("{subpath} ({mode})");
            if let Some((key_prefix, key_suffix)) = subpath.split_once('*') {
                // Patterns past the lookups' limit can't be confirmed typed.
                let Some(matched) = npm::pattern_matches(archive, runtime_raw) else {
                    entries.push(TypedEntry {
                        label,
                        typed: false,
                    });
                    continue;
                };
                // Only the files a consumer can reach: a more specific
                // subpath, such as a null pattern, may keep others away.
                let javascript: Vec<(&str, &str)> = matched
                    .into_iter()
                    .filter(|(path, star)| {
                        is_javascript(path)
                            && exports
                                .resolve_subpath(
                                    &format!("{key_prefix}{star}{key_suffix}"),
                                    runtime,
                                )
                                .is_some_and(|(resolved, _)| resolved == *path)
                    })
                    .collect();
                if javascript.is_empty() {
                    continue;
                }
                let typed = typed_pattern(archive, target, types, &javascript);
                entries.push(TypedEntry { label, typed });
                continue;
            }
            let Some(runtime_path) = npm::target_path(runtime_raw) else {
                continue;
            };
            if npm::is_declaration(&runtime_path) {
                entries.push(TypedEntry { label, typed: true });
                continue;
            }
            if !is_javascript(&runtime_path) {
                continue;
            }
            entries.push(TypedEntry {
                label,
                typed: package.declaration_for(subpath, types, runtime).is_some(),
            });
        }
    }
    entries
}

/// Whether every file a pattern entry matches, each with what its `*`
/// matched, has declarations: through a `types` pattern, or beside each
/// file.
fn typed_pattern(
    archive: &super::Archive,
    target: &Target<'_>,
    types: &[&str],
    matched: &[(&str, &str)],
) -> bool {
    let types_pattern = target
        .resolve(types)
        .filter(|resolution| resolution.via_types);
    matched.iter().all(|(path, star)| match types_pattern {
        Some(resolution) => npm::substitute(resolution.path, star)
            .and_then(|declared| npm::target_path(&declared))
            .is_some_and(|declared| npm::declaration_at(archive, &declared).is_some()),
        None => npm::declaration_at(archive, path).is_some(),
    })
}

fn types(package: &Package<'_>, results: &mut Results) {
    if let Some(Err(reason)) = &package.exports {
        results.fail("types", reason.clone());
        return;
    }
    let entries = typed_entries(package);
    if entries.is_empty() {
        results.fail("types", "No JavaScript entry point to declare types for");
        return;
    }
    let typed = entries.iter().filter(|entry| entry.typed).count();
    let total = entries.len();
    if typed == total {
        results.pass(
            "types",
            format!(
                "Every entry has type declarations ({total} entr{})",
                if total == 1 { "y" } else { "ies" }
            ),
        );
    } else if typed > 0 {
        let untyped: Vec<&str> = entries
            .iter()
            .filter(|entry| !entry.typed)
            .take(3)
            .map(|entry| entry.label.as_str())
            .collect();
        results.score(
            "types",
            5,
            format!(
                "{typed} of {total} entries have type declarations; none for {}",
                untyped.join(", ")
            ),
        );
    } else {
        results.fail("types", "No entry has type declarations");
    }
}

fn esm(package: &Package<'_>, results: &mut Results) {
    if let Some(Err(reason)) = &package.exports {
        results.fail("esm", reason.clone());
        return;
    }
    let Some(entry) = package.esm_entry(".") else {
        results.fail(
            "esm",
            if package.exports().is_some() {
                "\"exports\" has no import entry for the package root"
            } else {
                "No \"module\" field, and \"main\" isn't an ES module"
            },
        );
        return;
    };
    if entry.ends_with(".cjs") {
        results.fail("esm", format!("The import entry {entry} is CommonJS"));
        return;
    }
    let Some(facts) = package.facts(&entry) else {
        let reason = if package.archive().has(&entry) {
            "couldn't be read or parsed"
        } else {
            "doesn't exist"
        };
        results.fail("esm", format!("The import entry {entry} {reason}"));
        return;
    };
    if package.loads_as_esm(&entry, &facts) && facts.parsed {
        results.pass("esm", format!("{entry} is an ES module"));
    } else if facts.jsx {
        results.fail(
            "esm",
            format!("{entry} has JSX, which Node.js can't run: ship it compiled"),
        );
    } else if !facts.esm_syntax {
        results.fail(
            "esm",
            format!("{entry} has no import or export declarations"),
        );
    } else if !facts.parsed {
        results.fail("esm", format!("{entry} has syntax errors"));
    } else {
        results.fail(
            "esm",
            format!("Node.js loads {entry} as CommonJS: use .mjs or set \"type\": \"module\""),
        );
    }
}

fn exports_map(package: &Package<'_>, results: &mut Results) {
    match &package.exports {
        None => results.fail("exports-map", "package.json has no \"exports\""),
        Some(Err(reason)) => results.fail("exports-map", reason.clone()),
        Some(Ok(exports)) => {
            let problems = npm::exports_problems(package.archive(), exports);
            if problems.invalid {
                results.fail(
                    "exports-map",
                    "\"exports\" has a target Node.js refuses: not a ./ path, null, array or object, or a path it can't decode",
                );
            } else if let Some(missing) = problems.missing.first() {
                results.fail(
                    "exports-map",
                    format!("\"exports\" points at {missing}, which doesn't exist"),
                );
            } else if let Some(subpath) = problems.misordered.first() {
                results.fail(
                    "exports-map",
                    format!("Under {subpath}, put \"types\" first and \"default\" last"),
                );
            } else {
                let count = exports.entries.len();
                results.pass(
                    "exports-map",
                    format!(
                        "\"exports\" maps {count} subpath{}",
                        if count == 1 { "" } else { "s" }
                    ),
                );
            }
        }
    }
}

fn side_effects(json: &Value, results: &mut Results) {
    match json.get("sideEffects") {
        Some(Value::Bool(false)) => results.pass("side-effects", "\"sideEffects\": false"),
        Some(Value::Array(files)) if files.iter().all(Value::is_string) => results.pass(
            "side-effects",
            format!(
                "\"sideEffects\" lists {} file pattern{}",
                files.len(),
                if files.len() == 1 { "" } else { "s" }
            ),
        ),
        Some(Value::Bool(true)) => results.fail(
            "side-effects",
            "\"sideEffects\": true lets bundlers remove nothing",
        ),
        Some(_) => results.fail(
            "side-effects",
            "\"sideEffects\" isn't false or a list of files",
        ),
        None => results.fail(
            "side-effects",
            "package.json doesn't declare \"sideEffects\"",
        ),
    }
}

fn engines(json: &Value, results: &mut Results) {
    match json.get("engines").and_then(|engines| engines.get("node")) {
        Some(Value::String(range)) if lpm_semver::VersionReq::parse(range).is_ok() => {
            results.pass("engines", format!("engines.node \"{range}\""));
        }
        Some(Value::String(range)) => {
            results.fail(
                "engines",
                format!("engines.node \"{range}\" isn't a valid range"),
            );
        }
        Some(_) => results.fail("engines", "engines.node isn't a string"),
        None => results.fail("engines", "package.json has no engines.node"),
    }
}

/// The packages an install of this one pulls in directly: dependencies,
/// optional dependencies and peers not marked optional, each name once.
fn direct_dependencies(json: &Value) -> usize {
    let optional_peers = npm::object(json, "peerDependenciesMeta");
    let mut names: HashSet<&str> = HashSet::new();
    for field in ["dependencies", "optionalDependencies"] {
        if let Some(entries) = npm::object(json, field) {
            names.extend(entries.keys().map(String::as_str));
        }
    }
    if let Some(peers) = npm::object(json, "peerDependencies") {
        names.extend(peers.keys().map(String::as_str).filter(|name| {
            !optional_peers
                .and_then(|meta| meta.get(*name))
                .and_then(|meta| meta.get("optional"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        }));
    }
    names.len()
}

fn lean_install(json: &Value, results: &mut Results) {
    let count = direct_dependencies(json);
    let points = match count {
        0 => 6,
        1..=2 => 5,
        3..=5 => 4,
        6..=10 => 3,
        11..=20 => 2,
        21..=40 => 1,
        _ => 0,
    };
    results.score(
        "lean-install",
        points,
        format!(
            "{count} direct dependenc{}",
            if count == 1 { "y" } else { "ies" }
        ),
    );
}

const INSTALL_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall"];

fn install_scripts(context: &Context<'_>, json: &Value, results: &mut Results) {
    let scripts = npm::object(json, "scripts");
    let declared: Vec<&str> = INSTALL_SCRIPTS
        .iter()
        .copied()
        .filter(|name| {
            scripts
                .and_then(|scripts| scripts.get(*name))
                .and_then(Value::as_str)
                .is_some_and(|script| !script.trim().is_empty())
        })
        .collect();
    // npm runs `node-gyp rebuild` for a root binding.gyp when no install or
    // preinstall script replaces it.
    let implicit_gyp = context.archive.has("binding.gyp")
        && !declared
            .iter()
            .any(|name| matches!(*name, "install" | "preinstall"));
    if !declared.is_empty() {
        results.fail(
            "no-install-scripts",
            format!("package.json runs {} at install", declared.join(", ")),
        );
    } else if implicit_gyp {
        results.fail(
            "no-install-scripts",
            "binding.gyp at the package root makes npm run node-gyp rebuild at install",
        );
    } else {
        results.pass("no-install-scripts", "Nothing runs at install");
    }
}

const ENV_TEMPLATES: &[&str] = &[".env.example", ".env.sample", ".env.template"];
const OS_AND_EDITOR_FILES: &[&str] = &[".DS_Store", "Thumbs.db", "ehthumbs.db", "desktop.ini"];
const JUNK_DIRECTORIES: &[&str] = &[".git", "coverage", ".idea", ".vscode"];

/// Why a path doesn't belong in a published package, or `None`.
fn junk_reason(path: &str, bundled: &HashSet<&str>, bundles_all: bool) -> Option<String> {
    let segments: Vec<&str> = path.split('/').collect();
    let name = segments.last().copied().unwrap_or(path);
    let directories = &segments[..segments.len().saturating_sub(1)];
    if let Some(directory) = directories
        .iter()
        .find(|segment| JUNK_DIRECTORIES.contains(segment))
    {
        return Some(format!("{directory}/"));
    }
    if name.starts_with(".env") && !ENV_TEMPLATES.contains(&name) {
        return Some(name.to_string());
    }
    if OS_AND_EDITOR_FILES.contains(&name)
        || name.starts_with("._")
        || name.ends_with(".swp")
        || name.ends_with(".swo")
        || name.ends_with('~')
    {
        return Some(name.to_string());
    }
    if name.ends_with(".tgz") || name.ends_with(".tar.gz") {
        return Some(format!("nested archive {name}"));
    }
    if segments.first() == Some(&"node_modules") && !bundles_all {
        let dependency = match segments.get(1) {
            Some(scope) if scope.starts_with('@') => {
                segments.get(2).map(|name| format!("{scope}/{name}"))
            }
            Some(name) => Some((*name).to_string()),
            None => None,
        }?;
        if !bundled.contains(dependency.as_str()) {
            return Some(format!("node_modules/{dependency}, which isn't bundled"));
        }
    }
    None
}

fn clean_archive(context: &Context<'_>, results: &mut Results) {
    let bundle = context.manifest.and_then(|json| {
        json.get("bundleDependencies")
            .or_else(|| json.get("bundledDependencies"))
    });
    let bundles_all = matches!(bundle, Some(Value::Bool(true)));
    let bundled: HashSet<&str> = bundle
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut reasons: Vec<String> = context
        .archive
        .paths()
        .filter_map(|path| junk_reason(path, &bundled, bundles_all))
        .collect();
    reasons.sort_unstable();
    reasons.dedup();
    let size = context.archive.total_bytes;
    if size >= CLEAN_ARCHIVE_MAX_BYTES {
        reasons.push(format!(
            "{:.1} MB unpacked, over 10 MB",
            size as f64 / 1_000_000.0
        ));
    }
    if reasons.is_empty() {
        results.pass(
            "clean-archive",
            format!(
                "No stray files; {} unpacked",
                lpm_common::format_bytes(size)
            ),
        );
    } else {
        let shown: Vec<&str> = reasons.iter().take(4).map(String::as_str).collect();
        let more = reasons.len().saturating_sub(shown.len());
        results.fail(
            "clean-archive",
            if more > 0 {
                format!("{} and {more} more", shown.join(", "))
            } else {
                shown.join(", ")
            },
        );
    }
}
