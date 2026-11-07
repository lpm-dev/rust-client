//! What a package's install-time code reaches beyond the package itself.
//!
//! Script approval is per package, so approving one package must not
//! quietly approve others. The scan reads the files a package's
//! lifecycle commands run, plus the local files they import, and the
//! package manifest. It reports code that starts another package
//! manager, changes whether nested installs run lifecycle scripts, or
//! edits a package manager's script-approval list, and manifests that
//! approve other packages' scripts.
//!
//! Findings that could widen what runs make the package [require
//! individual review](ScriptReach::requires_individual_review): no bulk
//! approval, no advisor approval and no green-tier auto-run. A nested npm or pnpm install already
//! runs with dependency scripts disabled, so starting one is shown but does
//! not gate. Yarn 2+ still builds dependencies a project marks
//! `dependenciesMeta.<name>.built`, bun has no such setting, and corepack
//! can start either, so starting any of those does gate.
//!
//! The scan is textual. It cannot see code assembled at runtime, so an
//! empty result means "nothing recognizable", not "proven safe".

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::script_hash::{import_regexes, normalize_relative_path, path_to_slash_string};
use crate::static_gate::{extract_delegate_path, is_environment_assignment, normalize_operators};

/// Files read per package, counting every lifecycle entry point and import.
pub const MAX_FILES: usize = 128;
/// Larger files are left unscanned and mark the result incomplete.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Bytes read per package across all files.
pub const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
/// `npm run a` → `a: "npm run b"` → … indirection followed per phase.
const MAX_RUN_SCRIPT_DEPTH: usize = 4;

const SCRIPT_EXTENSIONS: &[&str] = &["js", "cjs", "mjs", "ts", "mts", "cts", "jsx", "tsx"];
/// Shell scripts a lifecycle command can run; each line is classified
/// with the static gate instead of following imports.
const SHELL_EXTENSIONS: &[&str] = &["sh", "bash", "zsh", "ps1", "cmd", "bat"];

/// Result of scanning one package. `Default` is "scanned, nothing found".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptReach {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ReachFinding>,
    /// A file, size or containment limit left part of the code unread.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub incomplete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ReachFinding {
    /// The code can start another package manager.
    StartsPackageManager { manager: String, file: String },
    /// The code mentions a setting that turns dependency lifecycle
    /// scripts on or off for a package manager it starts.
    ChangesScriptPolicy { marker: String, file: String },
    /// The code mentions a package manager's script-approval list.
    EditsScriptApprovals { key: String, file: String },
    /// The manifest approves lifecycle scripts for packages that are not
    /// among its own dependencies.
    ApprovesOtherPackages {
        field: String,
        packages: Vec<String>,
    },
    /// A command the lifecycle reaches, but the static gate never saw as a
    /// lifecycle phase, is one it marks Red: a package script run through
    /// `npm run`, a line of a shell script, or a `binding.gyp` command
    /// expansion. `source` names where the command came from.
    RunsRedCommand { source: String, command: String },
}

/// Package managers whose nested installs can still run dependency
/// lifecycle scripts under the guard every dependency script gets.
const UNGUARDED_MANAGERS: &[&str] = &["yarn", "yarnpkg", "bun", "bunx", "corepack"];

impl ReachFinding {
    pub fn requires_individual_review(&self) -> bool {
        match self {
            Self::StartsPackageManager { manager, .. } => {
                UNGUARDED_MANAGERS.contains(&manager.as_str())
            }
            _ => true,
        }
    }
}

impl ScriptReach {
    /// True when the package must be reviewed and approved on its own.
    pub fn requires_individual_review(&self) -> bool {
        self.incomplete
            || self
                .findings
                .iter()
                .any(ReachFinding::requires_individual_review)
    }

    /// Union of two scans of the same artifact, for callers that merge
    /// rows from several origins.
    pub fn merged(mut self, other: &Self) -> Self {
        self.incomplete |= other.incomplete;
        for finding in &other.findings {
            if !self.findings.contains(finding) {
                self.findings.push(finding.clone());
            }
        }
        self
    }

    fn record(&mut self, finding: ReachFinding) {
        let duplicate = self.findings.iter().any(|existing| {
            std::mem::discriminant(existing) == std::mem::discriminant(&finding)
                && existing.subject() == finding.subject()
        });
        if !duplicate {
            self.findings.push(finding);
        }
    }
}

/// Packages listed by [`ReachFinding::ApprovesOtherPackages`]'s
/// `Display` before it summarizes the rest as a count.
const DISPLAYED_PACKAGES: usize = 5;

impl std::fmt::Display for ReachFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StartsPackageManager { manager, file } => {
                write!(f, "starts {manager} ({file})")?;
                if self.requires_individual_review() {
                    f.write_str(", which can run dependency scripts LPM cannot switch off")?;
                }
                Ok(())
            }
            Self::ChangesScriptPolicy { marker, file } => {
                write!(
                    f,
                    "changes whether nested installs run scripts: {marker} ({file})"
                )
            }
            Self::EditsScriptApprovals { key, file } => {
                write!(f, "edits script approvals: {key} ({file})")
            }
            Self::RunsRedCommand { source, command } => {
                write!(
                    f,
                    "runs a command the static gate marks Red ({source}): {command}"
                )
            }
            Self::ApprovesOtherPackages { field, packages } => {
                write!(f, "approves scripts for other packages in {field}: ")?;
                let shown = packages.len().min(DISPLAYED_PACKAGES);
                f.write_str(&packages[..shown].join(", "))?;
                match packages.len() - shown {
                    0 => Ok(()),
                    more => write!(f, " and {more} more"),
                }
            }
        }
    }
}

impl ReachFinding {
    /// What the finding is about, ignoring the file it was first seen in,
    /// so each manager / marker / key is reported once per package.
    fn subject(&self) -> &str {
        match self {
            Self::StartsPackageManager { manager, .. } => manager,
            Self::RunsRedCommand { command, .. } => command,
            Self::ChangesScriptPolicy { marker, .. } => marker,
            Self::EditsScriptApprovals { key, .. } => key,
            Self::ApprovesOtherPackages { field, .. } => field,
        }
    }
}

/// Scan the package at `package_dir` whose non-empty lifecycle phases
/// are `phase_bodies` (as returned by
/// [`crate::script_hash::try_compute_script_hash_with_phase_bodies`]).
pub fn analyze(package_dir: &Path, phase_bodies: &[(String, String)]) -> ScriptReach {
    let mut reach = ScriptReach::default();
    let manifest = match read_manifest(package_dir) {
        Some(manifest) => manifest,
        None => {
            reach.incomplete = true;
            return reach;
        }
    };
    approvals_for_other_packages(&manifest, &mut reach);

    let Ok(root) = package_dir.canonicalize() else {
        reach.incomplete = true;
        return reach;
    };
    let scripts = manifest.get("scripts").and_then(Value::as_object);
    let bins = own_bins(&manifest);
    let mut entries = BTreeSet::new();
    for (_, body) in phase_bodies {
        collect_entry_points(&root, body, scripts, &bins, 0, &mut entries, &mut reach);
    }
    scan_files(&root, entries, &mut reach);
    reach
}

fn read_manifest(package_dir: &Path) -> Option<Map<String, Value>> {
    let (content, _) = lpm_common::read_text_regular_file_capped_with_metadata(
        &package_dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .ok()?;
    match serde_json::from_str(lpm_common::strip_utf8_bom_str(&content)).ok()? {
        Value::Object(manifest) => Some(manifest),
        _ => None,
    }
}

/// Package-relative files a lifecycle command runs: the recognized
/// `node <file>` delegate, any script file it names, the package's own
/// binaries, and the bodies of its own scripts reached through
/// `npm run` / `pnpm run` / `yarn run` / `bun run`.
fn collect_entry_points(
    root: &Path,
    body: &str,
    scripts: Option<&Map<String, Value>>,
    bins: &[(String, String)],
    depth: usize,
    entries: &mut BTreeSet<PathBuf>,
    reach: &mut ScriptReach,
) {
    if let Some(path) = extract_delegate_path(body).and_then(normalize_relative_path) {
        insert_if_file(root, entries, path);
    }
    let Some(tokens) = shlex::split(&normalize_operators(body)) else {
        return;
    };
    // `cd scripts && node install.js` runs `scripts/install.js`.
    let mut dir = PathBuf::new();
    for command in commands(&tokens) {
        let Some((first, rest)) = command.split_first() else {
            continue;
        };
        if matches!(first.as_str(), "cd" | "pushd") {
            match rest.first().map(String::as_str) {
                Some(target) if !target.starts_with(['/', '~', '$', '-']) => {
                    match resolve_within_package(&dir.join(target)) {
                        Some(next) => dir = next,
                        None => reach.incomplete = true,
                    }
                }
                Some(_) => reach.incomplete = true,
                None => dir = PathBuf::new(),
            }
            continue;
        }
        for token in command {
            if let Some(path) =
                script_file_token(token).and_then(|path| resolve_within_package(&dir.join(path)))
            {
                insert_if_file(root, entries, path);
            }
        }
        if let Some(path) = bins
            .iter()
            .find(|(name, _)| name == first)
            .and_then(|(_, target)| normalize_relative_path(target))
        {
            insert_if_file(root, entries, path);
        }
        if NODE_GYP_COMMANDS.contains(&first.as_str()) {
            scan_binding_gyp(root, &dir, entries, reach);
        }
        let Some(name) = run_script_target(first, rest) else {
            continue;
        };
        let Some(nested) = scripts.and_then(|s| s.get(name)).and_then(Value::as_str) else {
            continue;
        };
        if depth == MAX_RUN_SCRIPT_DEPTH {
            reach.incomplete = true;
            continue;
        }
        // The static gate classifies lifecycle phases themselves; a script
        // they reach through `npm run` would otherwise go unclassified.
        record_if_red(reach, &format!("script \"{name}\""), nested);
        collect_entry_points(root, nested, scripts, bins, depth + 1, entries, reach);
    }
}

fn record_if_red(reach: &mut ScriptReach, source: &str, command: &str) {
    if crate::static_gate::classify(command) == crate::triage::StaticTier::Red {
        reach.record(ReachFinding::RunsRedCommand {
            source: source.to_string(),
            command: command.to_string(),
        });
    }
}

/// Commands that configure `binding.gyp`, which can run commands through
/// `<!(…)` / `<!@(…)` expansions and name package scripts in its actions.
const NODE_GYP_COMMANDS: &[&str] = &[
    "node-gyp",
    "node-gyp-build",
    "node-gyp-build-optional-packages",
    "prebuild-install",
    "node-pre-gyp",
];

static GYP_COMMAND_EXPANSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<!@?\(([^)]*)\)").expect("valid gyp command expansion regex"));

static GYP_SCRIPT_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"]([^'"\s]+\.(?:js|cjs|mjs|ts|sh))['"]"#).expect("valid gyp script path regex")
});

fn scan_binding_gyp(
    root: &Path,
    dir: &Path,
    entries: &mut BTreeSet<PathBuf>,
    reach: &mut ScriptReach,
) {
    let gyp = dir.join("binding.gyp");
    let Ok((content, _)) = lpm_common::read_text_regular_file_capped_with_metadata(
        &root.join(&gyp),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) else {
        return;
    };
    let source = path_to_slash_string(&gyp);
    scan_bytes(content.as_bytes(), &source, reach);
    for capture in GYP_COMMAND_EXPANSION.captures_iter(content.as_bytes()) {
        let command = String::from_utf8_lossy(&capture[1]);
        record_if_red(reach, &source, &command);
    }
    for capture in GYP_SCRIPT_PATH.captures_iter(content.as_bytes()) {
        let path = String::from_utf8_lossy(&capture[1]);
        if let Some(path) = resolve_within_package(&dir.join(path.as_ref())) {
            insert_if_file(root, entries, path);
        }
    }
}

/// A command naming a file the package does not ship runs nothing.
fn insert_if_file(root: &Path, entries: &mut BTreeSet<PathBuf>, path: PathBuf) {
    if root.join(&path).is_file() {
        entries.insert(path);
    }
}

/// Simple commands in a token stream, each without leading environment
/// assignments.
fn commands(tokens: &[String]) -> impl Iterator<Item = &[String]> {
    tokens
        .split(|token| {
            matches!(
                token.as_str(),
                "&&" | "||" | ";" | "|" | "&" | "(" | ")" | ">" | ">>" | "<" | "<<"
            )
        })
        .map(|command| {
            let skip = command
                .iter()
                .take_while(|token| is_environment_assignment(token))
                .count();
            &command[skip..]
        })
}

/// `npm run x`, `npm run-script x`, `pnpm run x`, `yarn run x`,
/// `yarn x`, `bun run x` → `x`.
fn run_script_target<'a>(command: &str, rest: &'a [String]) -> Option<&'a str> {
    let mut positionals = rest.iter().filter(|arg| !arg.starts_with('-'));
    let first = positionals.next()?;
    match command {
        "npm" | "pnpm" | "bun" if matches!(first.as_str(), "run" | "run-script") => {
            positionals.next().map(String::as_str)
        }
        "yarn" if first == "run" => positionals.next().map(String::as_str),
        "yarn" => Some(first.as_str()),
        _ => None,
    }
}

fn script_file_token(token: &str) -> Option<PathBuf> {
    let token = token.split_once('=').map_or(token, |(_, value)| value);
    let extension = Path::new(token).extension()?.to_str()?;
    if !(SCRIPT_EXTENSIONS.contains(&extension) || SHELL_EXTENSIONS.contains(&extension))
        || token.starts_with('/')
        || token.starts_with('~')
        || token.starts_with('$')
        || token.contains('\\')
    {
        return None;
    }
    normalize_relative_path(token)
}

fn own_bins(manifest: &Map<String, Value>) -> Vec<(String, String)> {
    match manifest.get("bin") {
        Some(Value::String(target)) => manifest
            .get("name")
            .and_then(Value::as_str)
            .map(|name| name.rsplit('/').next().unwrap_or(name))
            .map(|name| vec![(name.to_string(), target.clone())])
            .unwrap_or_default(),
        Some(Value::Object(bins)) => bins
            .iter()
            .filter_map(|(name, target)| Some((name.clone(), target.as_str()?.to_string())))
            .collect(),
        _ => Vec::new(),
    }
}

fn scan_files(root: &Path, entries: BTreeSet<PathBuf>, reach: &mut ScriptReach) {
    let mut queue: VecDeque<PathBuf> = entries.into_iter().collect();
    let mut seen: HashSet<PathBuf> = queue.iter().cloned().collect();
    let mut files = 0usize;
    let mut total_bytes = 0u64;
    // A helper module can hold the `spawnSync` while another file names
    // the package manager, so process APIs count across the package.
    let mut spawns = false;
    let mut managers: Vec<(String, String)> = Vec::new();
    while let Some(relative) = queue.pop_front() {
        if files == MAX_FILES {
            reach.incomplete = true;
            break;
        }
        files += 1;
        let Some(bytes) = read_contained(root, &relative, &mut total_bytes, reach) else {
            continue;
        };
        let display = path_to_slash_string(&relative);
        scan_bytes(&bytes, &display, reach);
        let is_shell = relative
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| SHELL_EXTENSIONS.contains(&ext));
        if is_shell {
            scan_shell_lines(&bytes, &display, reach);
            continue;
        }
        spawns |= SPAWN_API.is_match(&bytes);
        for capture in PACKAGE_MANAGER_LITERAL.captures_iter(&bytes) {
            managers.push((
                String::from_utf8_lossy(&capture[1]).into_owned(),
                display.clone(),
            ));
        }
        let base = relative.parent().unwrap_or(Path::new(""));
        for candidate in local_imports(root, &bytes, base, reach) {
            if seen.insert(candidate.clone()) {
                queue.push_back(candidate);
            }
        }
    }
    if spawns {
        for (manager, file) in managers {
            reach.record(ReachFinding::StartsPackageManager { manager, file });
        }
    }
}

/// Each command line of a shell script, classified like a lifecycle
/// phase.
fn scan_shell_lines(bytes: &[u8], file: &str, reach: &mut ScriptReach) {
    for line in String::from_utf8_lossy(bytes).lines() {
        let line = line.trim();
        let comment = line.starts_with('#')
            || line.starts_with("::")
            || line
                .get(..4)
                .is_some_and(|rem| rem.eq_ignore_ascii_case("rem "));
        if !line.is_empty() && !comment {
            record_if_red(reach, file, line);
        }
    }
}

fn read_contained(
    root: &Path,
    relative: &Path,
    total_bytes: &mut u64,
    reach: &mut ScriptReach,
) -> Option<Vec<u8>> {
    let canonical = match root.join(relative).canonicalize() {
        Ok(path) if path.starts_with(root) => path,
        _ => {
            reach.incomplete = true;
            return None;
        }
    };
    let remaining = MAX_TOTAL_BYTES.saturating_sub(*total_bytes);
    match lpm_common::read_regular_file_capped_with_metadata(
        &canonical,
        MAX_FILE_BYTES.min(remaining),
    ) {
        Ok((bytes, _)) => {
            *total_bytes += bytes.len() as u64;
            Some(bytes)
        }
        Err(_) => {
            reach.incomplete = true;
            None
        }
    }
}

/// Existing package files that relative `require` / `import` specifiers
/// in `bytes` resolve to, with Node and TypeScript resolution. A
/// specifier that climbs above the package root, or names a directory
/// whose entry cannot be resolved, marks the scan incomplete: that code
/// is outside what was reviewed.
fn local_imports(root: &Path, bytes: &[u8], base: &Path, reach: &mut ScriptReach) -> Vec<PathBuf> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for regex in import_regexes().iter().chain(TEMPLATE_IMPORTS.iter()) {
        for capture in regex.captures_iter(&text) {
            let Some(spec) = capture.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let relative =
                matches!(spec, "." | "..") || spec.starts_with("./") || spec.starts_with("../");
            if !relative {
                continue;
            }
            let Some(path) = resolve_within_package(&base.join(spec)) else {
                reach.incomplete = true;
                continue;
            };
            match resolve_import(root, &path, 0) {
                Some(found) => out.push(found),
                None if root.join(&path).is_dir() => reach.incomplete = true,
                None => {}
            }
        }
    }
    out
}

/// ``require(`./x`)`` / ``import(`./x`)`` with a template literal that has
/// no substitutions name a file as surely as a quoted string.
static TEMPLATE_IMPORTS: LazyLock<[regex::Regex; 2]> = LazyLock::new(|| {
    [
        r"require\s*\(\s*`([^`$]+)`\s*\)",
        r"import\s*\(\s*`([^`$]+)`\s*\)",
    ]
    .map(|pattern| regex::Regex::new(pattern).expect("valid template import regex"))
});

/// Lexically resolve `path` inside the package. `Some("")` is the
/// package root itself (`require('../')` from a subdirectory); `None`
/// means the path climbs above it.
fn resolve_within_package(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Directory `main` fields followed per import (`helper/package.json`
/// pointing at another directory with its own `main`).
const MAX_MAIN_HOPS: usize = 4;

/// The package file Node loads for a relative import of `path`: the file
/// itself, the file with an extension added (or a TypeScript source for
/// an emitted `.js` name), then for a directory its `package.json`
/// `main`, then its `index` file.
fn resolve_import(root: &Path, path: &Path, hops: usize) -> Option<PathBuf> {
    let is_file = |candidate: &Path| root.join(candidate).is_file();
    let extension = path.extension().and_then(|e| e.to_str());
    if let Some(ext) = extension.filter(|ext| SCRIPT_EXTENSIONS.contains(ext)) {
        let swaps: &[&str] = match ext {
            "js" => &["ts", "tsx"],
            "mjs" => &["mts"],
            "cjs" => &["cts"],
            "jsx" => &["tsx"],
            _ => &[],
        };
        return std::iter::once(path.to_path_buf())
            .chain(swaps.iter().map(|swap| path.with_extension(swap)))
            .find(|candidate| is_file(candidate));
    }
    // Node loads `.json` as data and `.node` as a native addon; any
    // other existing file, extensionless included, as JavaScript.
    let data_or_native = matches!(extension, Some("json" | "node"));
    if !path.as_os_str().is_empty() && !data_or_native && is_file(path) {
        return Some(path.to_path_buf());
    }
    if !path.as_os_str().is_empty()
        && let Some(found) = SCRIPT_EXTENSIONS
            .iter()
            .map(|ext| {
                let mut file = path.as_os_str().to_os_string();
                file.push(".");
                file.push(ext);
                PathBuf::from(file)
            })
            .find(|candidate| is_file(candidate))
    {
        return Some(found);
    }
    if !root.join(path).is_dir() {
        return None;
    }
    if hops < MAX_MAIN_HOPS
        && let Some(main) = directory_main(root, path)
        && let Some(found) = resolve_import(root, &main, hops + 1)
    {
        return Some(found);
    }
    ["js", "cjs", "mjs", "ts"]
        .iter()
        .map(|ext| path.join(format!("index.{ext}")))
        .find(|candidate| is_file(candidate))
}

/// `main` of the `package.json` in package directory `dir`, as a path
/// inside the package.
fn directory_main(root: &Path, dir: &Path) -> Option<PathBuf> {
    let (content, _) = lpm_common::read_text_regular_file_capped_with_metadata(
        &root.join(dir).join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .ok()?;
    let manifest: Value = serde_json::from_str(lpm_common::strip_utf8_bom_str(&content)).ok()?;
    let main = manifest.get("main")?.as_str()?;
    resolve_within_package(&dir.join(main)).filter(|main| !main.as_os_str().is_empty())
}

static SPAWN_API: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"child_process|\bexeca\b|cross-spawn|\bBun\.spawn|\bBun\.\$|\bDeno\.Command|\bshelljs\b",
    )
    .expect("valid spawn regex")
});

static PACKAGE_MANAGER_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"['"`](corepack|yarnpkg|bunx|pnpx|pnpm|yarn|deno|npx|npm|bun)(?:['"`]|\s)"#)
        .expect("valid package manager regex")
});

static SCRIPT_POLICY_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)ignore[-_]?scripts|enable[-_]?scripts|--allow-scripts|--allow-build|dangerously[-_]?allow[-_]?all[-_]?(?:builds|scripts)",
    )
    .expect("valid script policy regex")
});

static SCRIPT_APPROVAL_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"allowBuilds|onlyBuiltDependencies|trustedDependencies|allowScripts|dependenciesMeta|approve-builds|approve-scripts|\bpm\s+trust\b")
        .expect("valid script approval regex")
});

/// Script-policy markers and approval keys in any scanned file.
fn scan_bytes(bytes: &[u8], file: &str, reach: &mut ScriptReach) {
    for found in SCRIPT_POLICY_MARKER.find_iter(bytes) {
        reach.record(ReachFinding::ChangesScriptPolicy {
            marker: canonical_policy_marker(found.as_bytes()).to_string(),
            file: file.to_string(),
        });
    }
    for found in SCRIPT_APPROVAL_KEY.find_iter(bytes) {
        let key = String::from_utf8_lossy(found.as_bytes());
        let key = if key.starts_with("pm") {
            "pm trust".into()
        } else {
            key.into_owned()
        };
        reach.record(ReachFinding::EditsScriptApprovals {
            key,
            file: file.to_string(),
        });
    }
}

fn canonical_policy_marker(found: &[u8]) -> &'static str {
    let lower = found.to_ascii_lowercase();
    let contains = |needle: &[u8]| lower.windows(needle.len()).any(|w| w == needle);
    if lower.starts_with(b"--allow-scripts") {
        "--allow-scripts"
    } else if lower.starts_with(b"--allow-build") {
        "--allow-build"
    } else if contains(b"builds") {
        "dangerously-allow-all-builds"
    } else if lower.starts_with(b"dangerously") {
        "dangerously-allow-all-scripts"
    } else if lower.starts_with(b"ignore") {
        "ignore-scripts"
    } else {
        "enable-scripts"
    }
}

/// Approval lists a manifest carries, as `(field, granted package names)`
/// in a fixed field order: npm 12 `allowScripts`, bun
/// `trustedDependencies`, pnpm `onlyBuiltDependencies` / `allowBuilds`,
/// Yarn `dependenciesMeta.<name>.built`, LavaMoat `allowScripts` and LPM
/// `trustedDependencies`. Names are sorted and deduplicated; fields
/// without grants are left out.
pub fn declared_script_approvals(
    manifest: &Map<String, Value>,
) -> Vec<(&'static str, Vec<String>)> {
    let nested = |outer: &str, inner: &str| manifest.get(outer).and_then(|v| v.get(inner));
    let built: BTreeSet<String> = manifest
        .get("dependenciesMeta")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, meta)| meta.get("built").and_then(Value::as_bool) == Some(true))
        .map(|(key, _)| package_name(key).to_string())
        .collect();
    let list = |field: &'static str, value: Option<&Value>| {
        let names: BTreeSet<String> = approved_names(value?).map(str::to_string).collect();
        (!names.is_empty()).then(|| (field, names.into_iter().collect()))
    };
    [
        list("allowScripts", manifest.get("allowScripts")),
        list("trustedDependencies", manifest.get("trustedDependencies")),
        list(
            "pnpm.onlyBuiltDependencies",
            nested("pnpm", "onlyBuiltDependencies"),
        ),
        list("pnpm.allowBuilds", nested("pnpm", "allowBuilds")),
        (!built.is_empty()).then(|| ("dependenciesMeta.built", built.into_iter().collect())),
        list("lavamoat.allowScripts", nested("lavamoat", "allowScripts")),
        list(
            "lpm.trustedDependencies",
            nested("lpm", "trustedDependencies"),
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// LPM honors no approval list from a dependency; lists naming packages
/// outside the dependency's own dependencies are reported because a
/// package that tries to approve unrelated packages' scripts deserves a
/// closer look.
fn approvals_for_other_packages(manifest: &Map<String, Value>, reach: &mut ScriptReach) {
    let own: HashSet<&str> = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ]
    .iter()
    .filter_map(|field| manifest.get(*field).and_then(Value::as_object))
    .flat_map(|deps| deps.keys().map(String::as_str))
    .chain(
        ["bundleDependencies", "bundledDependencies"]
            .iter()
            .filter_map(|field| manifest.get(*field).and_then(Value::as_array))
            .flatten()
            .filter_map(Value::as_str),
    )
    .chain(manifest.get("name").and_then(Value::as_str))
    .collect();
    for (field, names) in declared_script_approvals(manifest) {
        let packages: Vec<String> = names
            .into_iter()
            .filter(|name| !own.contains(name.as_str()))
            .collect();
        if !packages.is_empty() {
            reach.record(ReachFinding::ApprovesOtherPackages {
                field: field.to_string(),
                packages,
            });
        }
    }
}

/// Package names an approval list grants. Object forms grant entries
/// whose value is not `false`; keys may carry a version
/// (`name@1.2.3`), an artifact suffix (`name@1.2.3#id`) or a LavaMoat
/// path (`parent>name`).
fn approved_names(value: &Value) -> Box<dyn Iterator<Item = &str> + '_> {
    match value {
        Value::Array(items) => Box::new(items.iter().filter_map(Value::as_str).map(package_name)),
        Value::Object(entries) => Box::new(
            entries
                .iter()
                .filter(|(_, granted)| !matches!(granted, Value::Bool(false)))
                .map(|(key, _)| package_name(key)),
        ),
        _ => Box::new(std::iter::empty()),
    }
}

fn package_name(spec: &str) -> &str {
    let spec = spec.rsplit('>').next().unwrap_or(spec);
    let spec = spec.split('#').next().unwrap_or(spec);
    let search_from = usize::from(spec.starts_with('@'));
    match spec[search_from..].find('@') {
        Some(at) => &spec[..search_from + at],
        None => spec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn package(manifest: serde_json::Value, files: &[(&str, &str)]) -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), manifest.to_string()).unwrap();
        for (path, content) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        dir
    }

    fn phases(manifest: &serde_json::Value) -> Vec<(String, String)> {
        ["preinstall", "install", "postinstall"]
            .iter()
            .filter_map(|phase| {
                let body = manifest["scripts"][phase].as_str()?;
                Some(((*phase).to_string(), body.to_string()))
            })
            .collect()
    }

    fn scan(manifest: serde_json::Value, files: &[(&str, &str)]) -> ScriptReach {
        let dir = package(manifest.clone(), files);
        analyze(dir.path(), &phases(&manifest))
    }

    #[test]
    fn imported_onboarding_module_that_writes_pnpm_allow_builds_requires_review() {
        let reach = scan(
            serde_json::json!({"name":"tui","version":"2.37.0","scripts":{"postinstall":"node scripts/postinstall.mjs"}}),
            &[
                (
                    "scripts/postinstall.mjs",
                    "const { run } = await import('../bin/onboard-core.mjs');\nawait run();\n",
                ),
                (
                    "bin/onboard-core.mjs",
                    "import { spawnSync } from 'node:child_process';\nimport { writeFileSync } from 'node:fs';\n\
                     export function run() {\n  writeFileSync(profile, 'allowBuilds:\\n  tui: true\\n');\n  spawnSync('pnpm', ['install'], { cwd: profile });\n}\n",
                ),
            ],
        );
        assert!(reach.requires_individual_review());
        assert!(!reach.incomplete);
        assert_eq!(
            reach.findings,
            [
                ReachFinding::EditsScriptApprovals {
                    key: "allowBuilds".into(),
                    file: "bin/onboard-core.mjs".into(),
                },
                ReachFinding::StartsPackageManager {
                    manager: "pnpm".into(),
                    file: "bin/onboard-core.mjs".into(),
                },
            ]
        );
    }

    #[test]
    fn typescript_entry_run_through_node_import_flag_is_scanned() {
        let reach = scan(
            serde_json::json!({"name":"checker","scripts":{"postinstall":"node --import tsx ./scripts/install-checkers.ts"}}),
            &[
                (
                    "scripts/install-checkers.ts",
                    "import { approve } from './lib/manifest.js';\napprove();\n",
                ),
                (
                    "scripts/lib/manifest.ts",
                    "export function approve() { pkg.allowScripts[name] = true; }\n",
                ),
            ],
        );
        assert_eq!(
            reach.findings,
            [ReachFinding::EditsScriptApprovals {
                key: "allowScripts".into(),
                file: "scripts/lib/manifest.ts".into(),
            }]
        );
    }

    #[test]
    fn bun_runtime_entry_that_runs_bun_install_requires_review() {
        let reach = scan(
            serde_json::json!({"name":"kit","scripts":{"postinstall":"bun ./bin/build.js install"}}),
            &[(
                "bin/build.js",
                "const { execSync } = require('child_process');\nexecSync('bun add ' + extra);\n",
            )],
        );
        assert!(reach.requires_individual_review());
        assert!(
            reach
                .findings
                .contains(&ReachFinding::StartsPackageManager {
                    manager: "bun".into(),
                    file: "bin/build.js".into()
                })
        );
    }

    #[test]
    fn starting_a_package_manager_without_a_script_guard_requires_review() {
        for (manager, source) in [
            (
                "bun",
                "require('child_process').execSync('bun --cwd=vendor install');\n",
            ),
            (
                "yarn",
                "require('child_process').spawnSync('yarn', ['install'], { cwd: vendor });\n",
            ),
            (
                "corepack",
                "require('child_process').spawnSync('corepack', ['pnpm', 'install']);\n",
            ),
        ] {
            let reach = scan(
                serde_json::json!({"name":"x","scripts":{"postinstall":"node setup.js"}}),
                &[("setup.js", source)],
            );
            assert!(reach.requires_individual_review(), "{manager}: {reach:?}");
            assert!(reach.findings.iter().any(|finding| matches!(
                finding,
                ReachFinding::StartsPackageManager { manager: found, .. } if found == manager
            )));
        }
        let npm = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node setup.js"}}),
            &[(
                "setup.js",
                "require('child_process').spawnSync('pnpm', ['install']);\n",
            )],
        );
        assert!(
            !npm.requires_individual_review(),
            "pnpm honors the guard: {npm:?}"
        );
    }

    #[test]
    fn yarn_dependencies_meta_build_approvals_are_found_in_code_and_manifests() {
        let reach = scan(
            serde_json::json!({
                "name":"x",
                "scripts":{"postinstall":"node setup.js"},
                "dependenciesMeta":{"evil-native@1.0.0":{"built":true},"quiet":{"built":false},"other":{"optional":true}}
            }),
            &[(
                "setup.js",
                "pkg.dependenciesMeta = { 'evil-native': { built: true } };\n",
            )],
        );
        assert!(reach.requires_individual_review());
        assert!(
            reach
                .findings
                .contains(&ReachFinding::ApprovesOtherPackages {
                    field: "dependenciesMeta.built".into(),
                    packages: vec!["evil-native".into()],
                })
        );
        assert!(
            reach
                .findings
                .contains(&ReachFinding::EditsScriptApprovals {
                    key: "dependenciesMeta".into(),
                    file: "setup.js".into(),
                })
        );
    }

    #[test]
    fn directory_import_follows_the_directory_package_main_before_index() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node install.js"}}),
            &[
                ("install.js", "require('./helper');\n"),
                ("helper/package.json", r#"{"main":"approve.cjs"}"#),
                (
                    "helper/approve.cjs",
                    "pkg.allowScripts = { other: true };\n",
                ),
                ("helper/index.js", "module.exports = {};\n"),
            ],
        );
        assert!(!reach.incomplete);
        assert_eq!(
            reach.findings,
            [ReachFinding::EditsScriptApprovals {
                key: "allowScripts".into(),
                file: "helper/approve.cjs".into(),
            }]
        );
    }

    #[test]
    fn directory_import_with_no_resolvable_entry_marks_the_scan_incomplete() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node install.js"}}),
            &[
                ("install.js", "require('./native');\n"),
                (
                    "native/package.json",
                    r#"{"main":"build/Release/addon.node"}"#,
                ),
            ],
        );
        assert!(reach.incomplete);
    }

    #[test]
    fn red_script_reached_through_npm_run_requires_review() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"npm run setup","setup":"bun install"}}),
            &[],
        );
        assert!(reach.requires_individual_review());
        assert_eq!(
            reach.findings,
            [ReachFinding::RunsRedCommand {
                source: "script \"setup\"".into(),
                command: "bun install".into(),
            }]
        );
    }

    #[test]
    fn extensionless_file_import_is_scanned() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node setup.js"}}),
            &[
                ("setup.js", "require('./helper');\n"),
                ("helper", "pkg.trustedDependencies = ['other'];\n"),
            ],
        );
        assert_eq!(
            reach.findings,
            [ReachFinding::EditsScriptApprovals {
                key: "trustedDependencies".into(),
                file: "helper".into(),
            }]
        );
    }

    #[test]
    fn imported_json_data_is_not_scanned_as_code() {
        let reach = scan(
            serde_json::json!({
                "name":"x",
                "scripts":{"postinstall":"node setup.js"},
                "devDependencies":{"esbuild":"^0.28.0"},
                "allowScripts":{"esbuild@0.28.2":true}
            }),
            &[("setup.js", "const pkg = require('./package.json');\n")],
        );
        assert_eq!(reach, ScriptReach::default());
    }

    #[test]
    fn template_literal_import_is_followed() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node scripts/setup.mjs"}}),
            &[
                (
                    "scripts/setup.mjs",
                    "const m = await import(`../bin/onboard.mjs`);\n",
                ),
                (
                    "bin/onboard.mjs",
                    "write(profile, 'allowBuilds:\\n  x: true');\n",
                ),
            ],
        );
        assert_eq!(
            reach.findings,
            [ReachFinding::EditsScriptApprovals {
                key: "allowBuilds".into(),
                file: "bin/onboard.mjs".into(),
            }]
        );
    }

    #[test]
    fn package_manager_named_beside_a_spawn_helper_in_another_file_is_found() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node install.js"}}),
            &[
                ("install.js", "require('./run.js')('bun', ['install']);\n"),
                (
                    "run.js",
                    "const { spawnSync } = require('child_process');\nmodule.exports = (cmd, args) => spawnSync(cmd, args);\n",
                ),
            ],
        );
        assert!(reach.requires_individual_review(), "{reach:?}");
        assert!(
            reach
                .findings
                .contains(&ReachFinding::StartsPackageManager {
                    manager: "bun".into(),
                    file: "install.js".into(),
                })
        );
    }

    #[test]
    fn working_directory_change_in_the_lifecycle_command_is_followed() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"cd scripts && node install.js"}}),
            &[(
                "scripts/install.js",
                "pkg.allowScripts = { other: true };\n",
            )],
        );
        assert_eq!(
            reach.findings,
            [ReachFinding::EditsScriptApprovals {
                key: "allowScripts".into(),
                file: "scripts/install.js".into(),
            }]
        );
        let escaping = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"cd .. && node install.js"}}),
            &[],
        );
        assert!(escaping.incomplete);
    }

    #[test]
    fn shell_script_entry_is_classified_line_by_line() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"sh ./install.sh"}}),
            &[(
                "install.sh",
                "#!/bin/sh\n# bun install is mentioned in a comment\nset -e\nbun install\n",
            )],
        );
        assert!(reach.requires_individual_review());
        assert_eq!(
            reach.findings,
            [ReachFinding::RunsRedCommand {
                source: "install.sh".into(),
                command: "bun install".into(),
            }]
        );
    }

    #[test]
    fn binding_gyp_command_expansions_and_scripts_are_scanned_for_node_gyp() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"install":"node-gyp rebuild"}}),
            &[
                (
                    "binding.gyp",
                    "{'targets':[{'target_name':'x','variables':{'v':'<!(bun install)'},'actions':[{'action':['node','scripts/gen.js']}]}]}\n",
                ),
                ("scripts/gen.js", "pkg.allowBuilds = {};\n"),
            ],
        );
        assert!(reach.findings.contains(&ReachFinding::RunsRedCommand {
            source: "binding.gyp".into(),
            command: "bun install".into(),
        }));
        assert!(
            reach
                .findings
                .contains(&ReachFinding::EditsScriptApprovals {
                    key: "allowBuilds".into(),
                    file: "scripts/gen.js".into(),
                })
        );
    }

    #[test]
    fn run_script_chain_deeper_than_the_limit_marks_the_scan_incomplete() {
        let mut scripts = serde_json::Map::new();
        scripts.insert("postinstall".into(), "npm run s0".into());
        for index in 0..=MAX_RUN_SCRIPT_DEPTH {
            scripts.insert(
                format!("s{index}"),
                format!("npm run s{}", index + 1).into(),
            );
        }
        let reach = scan(serde_json::json!({"name":"x","scripts":scripts}), &[]);
        assert!(reach.incomplete);
    }

    #[test]
    fn own_binary_and_run_script_indirection_are_followed() {
        let reach = scan(
            serde_json::json!({
                "name":"@scope/setup",
                "bin":{"setup-tool":"cli/setup.cjs"},
                "scripts":{"postinstall":"npm run prepare-env","prepare-env":"setup-tool --quiet"}
            }),
            &[(
                "cli/setup.cjs",
                "process.env.npm_config_ignore_scripts = 'false';\n",
            )],
        );
        assert_eq!(
            reach.findings,
            [ReachFinding::ChangesScriptPolicy {
                marker: "ignore-scripts".into(),
                file: "cli/setup.cjs".into(),
            }]
        );
    }

    #[test]
    fn package_manager_fallback_without_policy_changes_is_informational() {
        let reach = scan(
            serde_json::json!({"name":"native-tool","scripts":{"postinstall":"node install.js"}}),
            &[(
                "install.js",
                "const child_process = require('child_process');\n\
                 child_process.execSync(`npm install --loglevel=error --prefer-offline ${pkg}@${version}`);\n",
            )],
        );
        assert_eq!(
            reach.findings,
            [ReachFinding::StartsPackageManager {
                manager: "npm".into(),
                file: "install.js".into(),
            }]
        );
        assert!(!reach.requires_individual_review());
    }

    #[test]
    fn manifest_approvals_for_packages_outside_its_dependencies_require_review() {
        let reach = scan(
            serde_json::json!({
                "name":"utils",
                "scripts":{"postinstall":"node-gyp rebuild"},
                "dependencies":{"esbuild":"^0.28.0"},
                "allowScripts":{"esbuild@0.28.2":true,"@swc/core@1.16.1":true,"core-js":false},
                "pnpm":{"onlyBuiltDependencies":["esbuild"]},
                "trustedDependencies":["sharp"],
                "lavamoat":{"allowScripts":{"esbuild>@esbuild/linux-x64":true}},
                "lpm":{"trustedDependencies":{"better-sqlite3@12.0.0#sha512":{}}}
            }),
            &[],
        );
        assert!(reach.requires_individual_review());
        assert_eq!(
            reach.findings,
            [
                ReachFinding::ApprovesOtherPackages {
                    field: "allowScripts".into(),
                    packages: vec!["@swc/core".into()],
                },
                ReachFinding::ApprovesOtherPackages {
                    field: "trustedDependencies".into(),
                    packages: vec!["sharp".into()],
                },
                ReachFinding::ApprovesOtherPackages {
                    field: "lavamoat.allowScripts".into(),
                    packages: vec!["@esbuild/linux-x64".into()],
                },
                ReachFinding::ApprovesOtherPackages {
                    field: "lpm.trustedDependencies".into(),
                    packages: vec!["better-sqlite3".into()],
                },
            ]
        );
    }

    #[test]
    fn manifest_approvals_limited_to_own_dependencies_are_not_reported() {
        let reach = scan(
            serde_json::json!({
                "name":"address",
                "scripts":{"postinstall":"node-gyp rebuild"},
                "devDependencies":{"esbuild":"^0.28.2"},
                "allowScripts":{"esbuild@0.28.2":true}
            }),
            &[],
        );
        assert_eq!(reach, ScriptReach::default());
    }

    #[test]
    fn script_policy_markers_are_reported_once_by_canonical_name() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node setup.js"}}),
            &[(
                "setup.js",
                "run(['--ignore-scripts=false']); env.NPM_CONFIG_IGNORE_SCRIPTS = '';\n\
                 run(['--dangerously-allow-all-builds']); env.YARN_ENABLE_SCRIPTS = 'true';\n\
                 run(['deno', 'install', '--allow-scripts=npm:x']);\n",
            )],
        );
        let markers: Vec<&str> = reach
            .findings
            .iter()
            .filter_map(|finding| match finding {
                ReachFinding::ChangesScriptPolicy { marker, .. } => Some(marker.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            markers,
            [
                "ignore-scripts",
                "dangerously-allow-all-builds",
                "enable-scripts",
                "--allow-scripts",
            ]
        );
    }

    #[test]
    fn imports_that_leave_the_package_mark_the_scan_incomplete() {
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node scripts/setup.js"}}),
            &[
                (
                    "scripts/setup.js",
                    "require('../lib/ok.js');\nrequire('../../sibling/payload.js');\n",
                ),
                ("lib/ok.js", ""),
            ],
        );
        assert!(reach.findings.is_empty());
        assert!(
            reach.incomplete,
            "an import above the package root is unreviewed code"
        );

        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node scripts/setup.js"}}),
            &[
                (
                    "scripts/setup.js",
                    "require('../lib/ok.js');\ntry { require('./optional.js') } catch {}\n",
                ),
                ("lib/ok.js", ""),
            ],
        );
        assert!(
            !reach.incomplete,
            "in-package and missing optional imports are fine"
        );

        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("pkg");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(outer.path().join("payload.js"), "allowBuilds").unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"x","scripts":{"postinstall":"node setup.js"}}"#,
        )
        .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outer.path().join("payload.js"), root.join("linked.js"))
            .unwrap();
        #[cfg(unix)]
        {
            std::fs::write(root.join("setup.js"), "require('./linked.js');\n").unwrap();
            let reach = analyze(&root, &[("postinstall".into(), "node setup.js".into())]);
            assert!(reach.incomplete, "a symlink out of the package is not read");
            assert!(reach.findings.is_empty());
            assert!(reach.requires_individual_review());
        }
    }

    #[test]
    fn importing_the_package_root_resolves_to_its_main_entry() {
        let reach = scan(
            serde_json::json!({"name":"x","main":"lib/index","scripts":{"postinstall":"node scripts/build.js"}}),
            &[
                ("scripts/build.js", "require('../').render();\n"),
                (
                    "lib/index.js",
                    "module.exports = { render() { pkg.trustedDependencies = []; } };\n",
                ),
            ],
        );
        assert!(!reach.incomplete);
        assert_eq!(
            reach.findings,
            [ReachFinding::EditsScriptApprovals {
                key: "trustedDependencies".into(),
                file: "lib/index.js".into(),
            }]
        );
    }

    #[test]
    fn oversized_files_and_import_graphs_mark_the_scan_incomplete() {
        let large = "x".repeat(usize::try_from(MAX_FILE_BYTES).unwrap() + 1);
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node big.js"}}),
            &[("big.js", &large)],
        );
        assert!(reach.incomplete);

        let mut files: Vec<(String, String)> = (0..MAX_FILES)
            .map(|index| {
                (
                    format!("lib/m{index}.js"),
                    format!("require('./m{}.js');\n", index + 1),
                )
            })
            .collect();
        files.push(("entry.js".into(), "require('./lib/m0.js');\n".into()));
        files.push((format!("lib/m{MAX_FILES}.js"), String::new()));
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        let reach = scan(
            serde_json::json!({"name":"x","scripts":{"postinstall":"node entry.js"}}),
            &borrowed,
        );
        assert!(reach.incomplete);
    }

    #[test]
    fn lifecycle_command_naming_a_missing_file_runs_nothing_and_stays_complete() {
        let reach = scan(
            serde_json::json!({"name":"x","bin":{"x":"cli.js"},"scripts":{"postinstall":"node install.js && x"}}),
            &[],
        );
        assert_eq!(reach, ScriptReach::default());
    }

    #[test]
    fn unreadable_manifest_marks_the_scan_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let reach = analyze(dir.path(), &[("postinstall".into(), "node x.js".into())]);
        assert!(reach.incomplete);
        assert!(reach.requires_individual_review());
    }

    #[test]
    fn findings_serialize_with_a_kebab_case_kind_tag() {
        let reach = ScriptReach {
            findings: vec![ReachFinding::EditsScriptApprovals {
                key: "allowBuilds".into(),
                file: "bin/onboard.mjs".into(),
            }],
            incomplete: false,
        };
        assert_eq!(
            serde_json::to_value(&reach).unwrap(),
            serde_json::json!({"findings":[{"kind":"edits-script-approvals","key":"allowBuilds","file":"bin/onboard.mjs"}]})
        );
        assert_eq!(
            serde_json::from_value::<ScriptReach>(serde_json::json!({})).unwrap(),
            ScriptReach::default()
        );
    }

    #[test]
    fn findings_describe_themselves_for_the_approval_card() {
        let finding = ReachFinding::ApprovesOtherPackages {
            field: "allowScripts".into(),
            packages: ["a", "b", "c", "d", "e", "f", "g"]
                .map(String::from)
                .to_vec(),
        };
        assert_eq!(
            finding.to_string(),
            "approves scripts for other packages in allowScripts: a, b, c, d, e and 2 more"
        );
        assert_eq!(
            ReachFinding::EditsScriptApprovals {
                key: "allowBuilds".into(),
                file: "bin/onboard.mjs".into(),
            }
            .to_string(),
            "edits script approvals: allowBuilds (bin/onboard.mjs)"
        );
    }

    #[test]
    fn package_names_strip_versions_artifacts_and_lavamoat_paths() {
        assert_eq!(package_name("esbuild@0.28.2"), "esbuild");
        assert_eq!(package_name("@swc/core@1.16.1"), "@swc/core");
        assert_eq!(package_name("@swc/core"), "@swc/core");
        assert_eq!(package_name("sqlite@1.0.0#sha512-x"), "sqlite");
        assert_eq!(package_name("a>b>@scope/c"), "@scope/c");
    }
}
