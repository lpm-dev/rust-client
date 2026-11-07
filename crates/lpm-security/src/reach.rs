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
//! Every finding except [`ReachFinding::StartsPackageManager`] makes the
//! package [require individual review](ScriptReach::requires_individual_review):
//! no bulk approval, no advisor approval, no green-tier auto-run. A
//! nested npm, pnpm or Yarn install already runs with dependency
//! scripts disabled, so starting one is shown but does not gate; bun has
//! no such setting, so a bun install does.
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
    /// The code runs `bun install` / `bun add` / `bun pm`, which run the
    /// lifecycle scripts of packages bun trusts.
    InstallsWithBun { file: String },
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
}

impl ReachFinding {
    pub fn requires_individual_review(&self) -> bool {
        !matches!(self, Self::StartsPackageManager { .. })
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
            Self::StartsPackageManager { manager, file } => write!(f, "starts {manager} ({file})"),
            Self::InstallsWithBun { file } => write!(f, "installs packages with bun ({file})"),
            Self::ChangesScriptPolicy { marker, file } => {
                write!(
                    f,
                    "changes whether nested installs run scripts: {marker} ({file})"
                )
            }
            Self::EditsScriptApprovals { key, file } => {
                write!(f, "edits script approvals: {key} ({file})")
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
            Self::InstallsWithBun { .. } => "bun",
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
        collect_entry_points(&root, body, scripts, &bins, 0, &mut entries);
    }
    let main = manifest
        .get("main")
        .and_then(Value::as_str)
        .and_then(normalize_relative_path);
    scan_files(&root, main.as_deref(), entries, &mut reach);
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
) {
    if let Some(path) = extract_delegate_path(body).and_then(normalize_relative_path) {
        insert_if_file(root, entries, path);
    }
    let Some(tokens) = shlex::split(&normalize_operators(body)) else {
        return;
    };
    for token in &tokens {
        if let Some(path) = script_file_token(token) {
            insert_if_file(root, entries, path);
        }
    }
    for command in commands(&tokens) {
        let Some((first, rest)) = command.split_first() else {
            continue;
        };
        if let Some(path) = bins
            .iter()
            .find(|(name, _)| name == first)
            .and_then(|(_, target)| normalize_relative_path(target))
        {
            insert_if_file(root, entries, path);
        }
        if depth < MAX_RUN_SCRIPT_DEPTH
            && let Some(name) = run_script_target(first, rest)
            && let Some(nested) = scripts.and_then(|s| s.get(name)).and_then(Value::as_str)
        {
            collect_entry_points(root, nested, scripts, bins, depth + 1, entries);
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
    if !SCRIPT_EXTENSIONS.contains(&extension)
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

fn scan_files(
    root: &Path,
    main: Option<&Path>,
    entries: BTreeSet<PathBuf>,
    reach: &mut ScriptReach,
) {
    let mut queue: VecDeque<PathBuf> = entries.into_iter().collect();
    let mut seen: HashSet<PathBuf> = queue.iter().cloned().collect();
    let mut files = 0usize;
    let mut total_bytes = 0u64;
    while let Some(relative) = queue.pop_front() {
        if files == MAX_FILES {
            reach.incomplete = true;
            return;
        }
        files += 1;
        let Some(bytes) = read_contained(root, &relative, &mut total_bytes, reach) else {
            continue;
        };
        let display = path_to_slash_string(&relative);
        scan_bytes(&bytes, &display, reach);
        let base = relative.parent().unwrap_or(Path::new(""));
        for candidate in local_imports(root, main, &bytes, base, reach) {
            if seen.insert(candidate.clone()) {
                queue.push_back(candidate);
            }
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
/// specifier that climbs above the package root marks the scan
/// incomplete: that code is outside what was reviewed.
fn local_imports(
    root: &Path,
    main: Option<&Path>,
    bytes: &[u8],
    base: &Path,
    reach: &mut ScriptReach,
) -> Vec<PathBuf> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for regex in import_regexes() {
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
            if let Some(found) = resolve_candidates(path, main)
                .into_iter()
                .find(|candidate| root.join(candidate).is_file())
            {
                out.push(found);
            }
        }
    }
    out
}

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

fn resolve_candidates(path: PathBuf, main: Option<&Path>) -> Vec<PathBuf> {
    if path.as_os_str().is_empty() {
        let mut candidates: Vec<PathBuf> = main.map(Path::to_path_buf).into_iter().collect();
        if let Some(main) = main {
            candidates.extend(resolve_candidates(main.to_path_buf(), None));
        }
        candidates
            .extend(["js", "cjs", "mjs", "ts"].map(|ext| PathBuf::from(format!("index.{ext}"))));
        return candidates;
    }
    let extension = path.extension().and_then(|e| e.to_str()).map(str::to_owned);
    let mut candidates = Vec::with_capacity(12);
    match extension.as_deref() {
        Some(ext) if SCRIPT_EXTENSIONS.contains(&ext) => {
            candidates.push(path.clone());
            // TypeScript sources import their emitted names.
            let swaps: &[&str] = match ext {
                "js" => &["ts", "tsx"],
                "mjs" => &["mts"],
                "cjs" => &["cts"],
                "jsx" => &["tsx"],
                _ => &[],
            };
            for swap in swaps {
                candidates.push(path.with_extension(swap));
            }
        }
        _ => {
            for ext in SCRIPT_EXTENSIONS {
                let mut file = path.clone().into_os_string();
                file.push(".");
                file.push(ext);
                candidates.push(PathBuf::from(file));
            }
            for ext in ["js", "cjs", "mjs", "ts"] {
                candidates.push(path.join(format!("index.{ext}")));
            }
        }
    }
    candidates
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

static BUN_INSTALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"['"`]bun\s+(?:install|i|add|a|update|pm)\b|['"`]bun['"`]\s*,\s*\[\s*['"`](?:install|i|add|a|update|pm)['"`]"#,
    )
    .expect("valid bun install regex")
});

static SCRIPT_POLICY_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)ignore[-_]?scripts|enable[-_]?scripts|--allow-scripts|--allow-build|dangerously[-_]?allow[-_]?all[-_]?(?:builds|scripts)",
    )
    .expect("valid script policy regex")
});

static SCRIPT_APPROVAL_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"allowBuilds|onlyBuiltDependencies|trustedDependencies|allowScripts|approve-builds|approve-scripts|\bpm\s+trust\b")
        .expect("valid script approval regex")
});

fn scan_bytes(bytes: &[u8], file: &str, reach: &mut ScriptReach) {
    if SPAWN_API.is_match(bytes) {
        if BUN_INSTALL.is_match(bytes) {
            reach.record(ReachFinding::InstallsWithBun {
                file: file.to_string(),
            });
        }
        for capture in PACKAGE_MANAGER_LITERAL.captures_iter(bytes) {
            let manager = String::from_utf8_lossy(&capture[1]).into_owned();
            reach.record(ReachFinding::StartsPackageManager {
                manager,
                file: file.to_string(),
            });
        }
    }
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

/// Approval lists a manifest can carry for npm 12, bun, pnpm, LavaMoat
/// and LPM. LPM honors none of them from a dependency; they are reported
/// because a package that tries to approve unrelated packages' scripts
/// deserves a closer look.
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
    let nested = |outer: &str, inner: &str| manifest.get(outer).and_then(|v| v.get(inner));
    let fields: [(&str, Option<&Value>); 6] = [
        ("allowScripts", manifest.get("allowScripts")),
        ("trustedDependencies", manifest.get("trustedDependencies")),
        (
            "pnpm.onlyBuiltDependencies",
            nested("pnpm", "onlyBuiltDependencies"),
        ),
        ("pnpm.allowBuilds", nested("pnpm", "allowBuilds")),
        ("lavamoat.allowScripts", nested("lavamoat", "allowScripts")),
        (
            "lpm.trustedDependencies",
            nested("lpm", "trustedDependencies"),
        ),
    ];
    for (field, value) in fields {
        let Some(value) = value else {
            continue;
        };
        let packages: BTreeSet<String> = approved_names(value)
            .filter(|name| !own.contains(name))
            .map(str::to_string)
            .collect();
        if !packages.is_empty() {
            reach.record(ReachFinding::ApprovesOtherPackages {
                field: field.to_string(),
                packages: packages.into_iter().collect(),
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
                ReachFinding::StartsPackageManager {
                    manager: "pnpm".into(),
                    file: "bin/onboard-core.mjs".into(),
                },
                ReachFinding::EditsScriptApprovals {
                    key: "allowBuilds".into(),
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
        assert!(reach.findings.contains(&ReachFinding::InstallsWithBun {
            file: "bin/build.js".into()
        }));
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
