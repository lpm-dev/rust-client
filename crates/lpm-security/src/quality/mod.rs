//! The quality checks a package's archive decides, run on its files as they
//! stream past. LPM.dev Registry runs them on every published release with
//! `lpm internal-package-signals`, and `lpm publish --check` runs them on the
//! tarball it would upload, so the two always agree. The checks that need
//! registry data (provenance, the owner's verified domain, vulnerabilities
//! over the resolved tree, the dependency tree's size, approved Agent
//! Skills) are LPM.dev Registry's; [`spec`] lists them with the rest.

mod js;
mod js_api;
mod markdown;
mod npm;
pub mod spec;
mod swift;

pub use spec::{Category, CheckSpec, Decider, QualityEcosystem};

use serde::Serialize;
use serde_json::Value;
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

/// Version of the [`QualityReport`] document. Bump it when a field changes
/// meaning or goes away.
pub const QUALITY_SCHEMA_VERSION: u32 = 1;

/// Version of the archive checks' rules. Bump it when a check's points or
/// what earns them change, so LPM.dev Registry knows to score its releases
/// again.
pub const QUALITY_RULES_VERSION: u32 = 1;

/// Most README bytes `lpm publish` sends and LPM.dev Registry reads; a
/// longer README is cut at a character boundary.
pub const MAX_README_BYTES: usize = 1_000_000;
const MAX_CHANGELOG_BYTES: u64 = 1024 * 1024;
/// All changelogs together, however many entries an archive repeats.
const MAX_CHANGELOGS_BYTES: u64 = 4 * 1024 * 1024;
/// Public Swift declaration names kept across files, for the README
/// example check.
const MAX_SWIFT_NAMES: usize = 65_536;
/// Declaration and JavaScript files are kept for the end, when package.json
/// says which are entries: each up to this size, all together up to
/// [`MAX_RETAINED_BYTES`].
const MAX_RETAINED_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RETAINED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SWIFT_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Nested package.json files kept for the `type` each sets for the files
/// under it, and the size of each.
const MAX_SCOPES: usize = 2_000;
const MAX_SCOPE_MANIFEST_BYTES: u64 = 64 * 1024;
/// An archive this large unpacked fails clean-archive: 10 MB.
const CLEAN_ARCHIVE_MAX_BYTES: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Passed,
    Partial,
    Failed,
    /// Its evidence isn't available yet, such as a Swift package's
    /// evaluated manifest.
    Pending,
}

/// One check's result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub id: &'static str,
    pub category: Category,
    pub points: u32,
    pub max_points: u32,
    pub status: CheckStatus,
    pub detail: String,
}

/// The archive checks of one release.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityReport {
    pub schema_version: u32,
    pub rules_version: u32,
    pub ecosystem: QualityEcosystem,
    pub checks: Vec<CheckResult>,
    pub facts: QualityFacts,
}

/// What the archive says that LPM.dev Registry's own checks compare with
/// its data.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QualityFacts {
    /// package.json's repository as `host/owner/name`, lowercase, when it
    /// names one: what provenance's repository is compared with.
    pub repository: Option<String>,
}

impl QualityReport {
    /// Points the archive checks earned, of the points they're worth.
    pub fn archive_points(&self) -> (u32, u32) {
        self.checks.iter().fold((0, 0), |(earned, max), check| {
            (earned + check.points, max + check.max_points)
        })
    }
}

/// Where a package-root README ranks among the archive's READMEs, lowest
/// first, or `None` for any other path: `.md`, none, `.txt`, `.markdown`,
/// then any other extension that isn't an editor backup. The LPM CLI
/// publishes this README, and LPM.dev Registry stores it.
pub fn readme_rank(path: &str) -> Option<u8> {
    if path.contains(['/', '\\']) {
        return None;
    }
    let (base, extension) = path
        .split_once('.')
        .map_or((path, None), |(base, extension)| (base, Some(extension)));
    if !base.eq_ignore_ascii_case("readme") {
        return None;
    }
    match extension {
        None => Some(1),
        Some(extension) if extension.eq_ignore_ascii_case("md") => Some(0),
        Some(extension) if extension.eq_ignore_ascii_case("txt") => Some(2),
        Some(extension) if extension.eq_ignore_ascii_case("markdown") => Some(3),
        Some(extension) if !extension.is_empty() && !extension.ends_with(['~', '$']) => Some(4),
        Some(_) => None,
    }
}

/// Paths the pattern lookups of one report may visit in all. A package.json
/// can hold up to a million `exports` patterns; this keeps them from making
/// the checks scan every file once each.
const MAX_PATTERN_VISITS: usize = 1_000_000;

/// The archive's files and the contents the checks keep.
#[derive(Default)]
pub(crate) struct Archive {
    /// Every file and its size, in path order.
    files: BTreeMap<String, u64>,
    /// Paths the pattern lookups have visited, against `MAX_PATTERN_VISITS`.
    pattern_visits: Cell<usize>,
    total_bytes: u64,
    retained: HashMap<String, String>,
    retained_bytes: u64,
    /// Declaration or JavaScript files left unread past the size limits.
    unretained: usize,
    /// The `type` each nested package.json sets, by its directory.
    scopes: HashMap<String, Option<String>>,
}

impl Archive {
    pub fn has(&self, path: &str) -> bool {
        self.files.contains_key(path)
    }

    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// The files under `prefix` that end with `suffix` and are longer than
    /// both, in path order: what an `exports` pattern matches. `None` once
    /// the lookups together have visited `MAX_PATTERN_VISITS` paths.
    pub fn pattern_files(&self, prefix: &str, suffix: &str) -> Option<Vec<&str>> {
        let mut visits = self.pattern_visits.get().saturating_add(1);
        let mut found = Vec::new();
        for path in self
            .files
            .range::<str, _>((Bound::Included(prefix), Bound::Unbounded))
            .map(|(path, _)| path.as_str())
            .take_while(|path| path.starts_with(prefix))
        {
            visits += 1;
            if visits > MAX_PATTERN_VISITS {
                break;
            }
            if path.len() > prefix.len() + suffix.len() && path.ends_with(suffix) {
                found.push(path);
            }
        }
        self.pattern_visits.set(visits.min(MAX_PATTERN_VISITS + 1));
        (visits <= MAX_PATTERN_VISITS).then_some(found)
    }

    pub fn retained(&self, path: &str) -> Option<&str> {
        self.retained.get(path).map(String::as_str)
    }

    pub fn unretained(&self) -> usize {
        self.unretained
    }

    /// The `type` the package.json in `directory` sets, when the archive
    /// has one there: `Some(None)` for one that sets none.
    pub fn scope(&self, directory: &str) -> Option<Option<&str>> {
        self.scopes.get(directory).map(Option::as_deref)
    }
}

enum Readme {
    Text(String),
    NotUtf8,
}

/// Collects what the checks read from an archive's entries, one at a time.
pub struct QualityCollector {
    ecosystem: QualityEcosystem,
    archive: Archive,
    readme: Option<(u8, String, Readme)>,
    changelogs: Vec<(String, String)>,
    changelog_bytes: u64,
    swift_files: Vec<(String, swift::SwiftFileFacts)>,
    swift_names: usize,
    swift_unread: usize,
    /// The READMEs [`Self::note_file`] asked for, with the bytes the source
    /// checks read of one that is a module too (`README.js`).
    readme_reads: HashMap<String, Option<u64>>,
}

const RETAINED_EXTENSIONS: &[&str] = &[".d.ts", ".d.mts", ".d.cts", ".js", ".mjs", ".cjs", ".jsx"];
const SWIFT_SKIPPED_SEGMENTS: &[&str] =
    &[".build", "DerivedData", "Pods", ".swiftpm", "xcuserdata"];

/// A changelog at the package root: CHANGELOG, CHANGES or HISTORY, bare or
/// with a text extension.
fn is_changelog(path: &str) -> bool {
    if path.contains('/') {
        return false;
    }
    let (stem, extension) = path
        .split_once('.')
        .map_or((path, None), |(stem, extension)| (stem, Some(extension)));
    ["changelog", "changes", "history"]
        .iter()
        .any(|name| stem.eq_ignore_ascii_case(name))
        && extension.is_none_or(|extension| {
            ["md", "markdown", "txt", "rst", "adoc", "org"]
                .iter()
                .any(|text| extension.eq_ignore_ascii_case(text))
        })
}

/// A package.json below the package root, outside `node_modules`, which
/// sets the module type of the files under it.
fn is_nested_manifest(path: &str) -> bool {
    path.ends_with("/package.json") && !in_node_modules(path)
}

fn in_node_modules(path: &str) -> bool {
    path.split('/').any(|segment| segment == "node_modules")
}

fn is_swift_manifest(path: &str) -> bool {
    path == "Package.swift"
        || (path.starts_with("Package@swift-") && path.ends_with(".swift") && !path.contains('/'))
}

impl QualityCollector {
    pub fn new(ecosystem: QualityEcosystem) -> Self {
        Self {
            ecosystem,
            archive: Archive::default(),
            readme: None,
            changelogs: Vec::new(),
            changelog_bytes: 0,
            swift_files: Vec::new(),
            swift_names: 0,
            swift_unread: 0,
            readme_reads: HashMap::new(),
        }
    }

    /// Whether the README at `path` of `rank` would replace the one found
    /// so far: the best-ranked README that is UTF-8 wins, and of two of the
    /// same rank the first in path order, as the LPM CLI packs them.
    fn wants_readme(&self, rank: u8, path: &str) -> bool {
        match &self.readme {
            None | Some((_, _, Readme::NotUtf8)) => true,
            Some((best, best_path, Readme::Text(_))) => {
                rank < *best || (rank == *best && path < best_path.as_str())
            }
        }
    }

    /// Records a regular file of the archive and says how many of its bytes
    /// the checks read, or `None` when they read none.
    pub fn note_file(&mut self, path: &str, size: u64) -> Option<u64> {
        self.archive.files.insert(path.to_string(), size);
        self.archive.total_bytes = self.archive.total_bytes.saturating_add(size);
        if let Some(rank) = readme_rank(path)
            && self.wants_readme(rank, path)
        {
            let readme = size.min(MAX_README_BYTES as u64);
            // A README that is also a module (`README.js`) is read as both.
            let source = self.source_bytes(path, size);
            self.readme_reads.insert(path.to_string(), source);
            return Some(source.map_or(readme, |source| readme.max(source)));
        }
        if is_changelog(path) {
            let remaining = MAX_CHANGELOGS_BYTES.saturating_sub(self.changelog_bytes);
            return (remaining > 0).then(|| size.min(MAX_CHANGELOG_BYTES).min(remaining));
        }
        if self.ecosystem == QualityEcosystem::Js && is_nested_manifest(path) {
            return (size <= MAX_SCOPE_MANIFEST_BYTES && self.archive.scopes.len() < MAX_SCOPES)
                .then_some(size);
        }
        self.source_bytes(path, size)
    }

    /// How many bytes of a source file the checks read, counted against
    /// their limits, or `None` for a file they don't read.
    fn source_bytes(&mut self, path: &str, size: u64) -> Option<u64> {
        match self.ecosystem {
            QualityEcosystem::Js => {
                if !RETAINED_EXTENSIONS
                    .iter()
                    .any(|extension| path.ends_with(extension))
                    || in_node_modules(path)
                    || crate::behavioral::roles::is_test_path(path)
                {
                    return None;
                }
                if size > MAX_RETAINED_FILE_BYTES
                    || self.archive.retained_bytes.saturating_add(size) > MAX_RETAINED_BYTES
                {
                    self.archive.unretained += 1;
                    return None;
                }
                self.archive.retained_bytes += size;
                Some(size)
            }
            QualityEcosystem::Swift => {
                if !path.ends_with(".swift")
                    || is_swift_manifest(path)
                    || path
                        .split('/')
                        .any(|segment| SWIFT_SKIPPED_SEGMENTS.contains(&segment))
                {
                    return None;
                }
                if size > MAX_SWIFT_FILE_BYTES {
                    self.swift_unread += 1;
                    return None;
                }
                Some(size)
            }
        }
    }

    /// The bytes of a file [`Self::note_file`] asked for, cut at the length
    /// it asked for.
    pub fn add_content(&mut self, path: &str, content: &[u8]) {
        if let Some(source) = self.readme_reads.remove(path)
            && let Some(rank) = readme_rank(path)
        {
            if self.wants_readme(rank, path) {
                let cut = self
                    .archive
                    .files
                    .get(path)
                    .is_some_and(|&size| size > MAX_README_BYTES as u64);
                let readme = &content[..content.len().min(MAX_README_BYTES)];
                match decode_readme(readme, cut) {
                    Some(text) => self.readme = Some((rank, path.to_string(), Readme::Text(text))),
                    None if self.readme.is_none() => {
                        self.readme = Some((rank, path.to_string(), Readme::NotUtf8));
                    }
                    None => {}
                }
            }
            if let Some(source) = source {
                let end =
                    usize::try_from(source).map_or(content.len(), |end| end.min(content.len()));
                self.add_source(path, &content[..end]);
            }
            return;
        }
        if is_changelog(path) {
            self.changelog_bytes = self.changelog_bytes.saturating_add(content.len() as u64);
            let text = String::from_utf8_lossy(content).into_owned();
            match self
                .changelogs
                .iter_mut()
                .find(|(existing, _)| existing == path)
            {
                Some(entry) => entry.1 = text,
                None => self.changelogs.push((path.to_string(), text)),
            }
            return;
        }
        if self.ecosystem == QualityEcosystem::Js && is_nested_manifest(path) {
            let directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
            let module_type = serde_json::from_slice::<Value>(content)
                .ok()
                .and_then(|json| json.get("type").and_then(Value::as_str).map(str::to_string));
            self.archive
                .scopes
                .insert(directory.to_string(), module_type);
            return;
        }
        self.add_source(path, content);
    }

    fn add_source(&mut self, path: &str, content: &[u8]) {
        match self.ecosystem {
            QualityEcosystem::Js => {
                self.archive.retained.insert(
                    path.to_string(),
                    String::from_utf8_lossy(content).into_owned(),
                );
            }
            QualityEcosystem::Swift => {
                let mut facts = swift::file_facts(&String::from_utf8_lossy(content));
                facts
                    .public_names
                    .truncate(MAX_SWIFT_NAMES.saturating_sub(self.swift_names));
                self.swift_names += facts.public_names.len();
                self.swift_files.push((path.to_string(), facts));
            }
        }
    }

    /// Runs the checks. `package_json` is the root package.json's bytes;
    /// `swift_manifest` is a Swift package's evaluated manifest, without
    /// which the checks that read it are pending.
    pub fn finish(
        self,
        package_json: Option<&[u8]>,
        swift_manifest: Option<&Value>,
    ) -> QualityReport {
        let manifest: Option<Value> =
            package_json.and_then(|bytes| serde_json::from_slice(bytes).ok());
        let manifest = manifest.filter(Value::is_object);
        let context = Context {
            archive: &self.archive,
            manifest: manifest.as_ref(),
            readme: self
                .readme
                .as_ref()
                .map(|(_, path, readme)| (path.as_str(), readme)),
            changelogs: &self.changelogs,
        };
        let checks = match self.ecosystem {
            QualityEcosystem::Js => js::run(&context),
            QualityEcosystem::Swift => run_swift(
                &context,
                &self.swift_files,
                self.swift_unread,
                swift_manifest,
            ),
        };
        let facts = QualityFacts {
            repository: context.manifest.and_then(repository_identity),
        };
        QualityReport {
            schema_version: QUALITY_SCHEMA_VERSION,
            rules_version: QUALITY_RULES_VERSION,
            ecosystem: self.ecosystem,
            checks,
            facts,
        }
    }
}

/// A README's text, or `None` when it isn't UTF-8. A README cut at the size
/// limit drops the character the cut split.
/// A README's text, without a byte order mark, as LPM.dev Registry shows
/// it; `None` when it isn't UTF-8. A README cut at the limit drops only a
/// character the cut split.
fn decode_readme(content: &[u8], cut: bool) -> Option<String> {
    let text = match std::str::from_utf8(content) {
        Ok(text) => text.to_string(),
        Err(error) if cut && error.error_len().is_none() => {
            String::from_utf8_lossy(&content[..error.valid_up_to()]).into_owned()
        }
        Err(_) => return None,
    };
    Some(match text.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_string(),
        None => text,
    })
}

/// What every check reads.
pub(crate) struct Context<'a> {
    pub archive: &'a Archive,
    pub manifest: Option<&'a Value>,
    readme: Option<(&'a str, &'a Readme)>,
    changelogs: &'a [(String, String)],
}

impl Context<'_> {
    pub fn package_name(&self) -> Option<&str> {
        self.manifest.and_then(|json| npm::string(json, "name"))
    }

    pub fn version(&self) -> Option<&str> {
        self.manifest.and_then(|json| npm::string(json, "version"))
    }

    /// A source package, which `lpm add` copies into a project: its archive
    /// has a root `lpm.config.json`, or its package.json the legacy
    /// `lpm.source`.
    pub fn is_source_package(&self) -> bool {
        self.archive.files.contains_key("lpm.config.json")
            || self
                .manifest
                .and_then(|json| json.get("lpm"))
                .and_then(|lpm| lpm.get("source"))
                .is_some_and(Value::is_string)
    }

    pub fn readme_text(&self) -> Option<&str> {
        match self.readme {
            Some((_, Readme::Text(text))) => Some(text),
            _ => None,
        }
    }
}

/// Builds results in spec order.
pub(crate) struct Results {
    ecosystem: QualityEcosystem,
    checks: Vec<CheckResult>,
}

impl Results {
    pub fn new(ecosystem: QualityEcosystem) -> Self {
        Self {
            ecosystem,
            checks: Vec::with_capacity(32),
        }
    }

    fn spec(&self, id: &'static str) -> &'static CheckSpec {
        spec::check(self.ecosystem, id)
            .unwrap_or_else(|| panic!("no {id} check for {:?}", self.ecosystem))
    }

    /// `points` earned of the check's maximum, with why.
    pub fn score(&mut self, id: &'static str, points: u32, detail: impl Into<String>) {
        let spec = self.spec(id);
        debug_assert_eq!(spec.decider, Decider::Archive, "{id} is a registry check");
        let points = points.min(spec.max_points);
        let status = if points == spec.max_points {
            CheckStatus::Passed
        } else if points == 0 {
            CheckStatus::Failed
        } else {
            CheckStatus::Partial
        };
        self.checks.push(CheckResult {
            id: spec.id,
            category: spec.category,
            points,
            max_points: spec.max_points,
            status,
            detail: detail.into(),
        });
    }

    pub fn pass(&mut self, id: &'static str, detail: impl Into<String>) {
        let max = self.spec(id).max_points;
        self.score(id, max, detail);
    }

    pub fn fail(&mut self, id: &'static str, detail: impl Into<String>) {
        self.score(id, 0, detail);
    }

    pub fn pending(&mut self, id: &'static str, detail: impl Into<String>) {
        let spec = self.spec(id);
        self.checks.push(CheckResult {
            id: spec.id,
            category: spec.category,
            points: 0,
            max_points: spec.max_points,
            status: CheckStatus::Pending,
            detail: detail.into(),
        });
    }

    /// The results in the ecosystem's report order.
    pub fn finish(mut self) -> Vec<CheckResult> {
        let order: HashMap<&str, usize> = spec::checks(self.ecosystem)
            .enumerate()
            .map(|(index, spec)| (spec.id, index))
            .collect();
        self.checks
            .sort_by_key(|check| order.get(check.id).copied().unwrap_or(usize::MAX));
        debug_assert_eq!(
            self.checks.len(),
            spec::checks(self.ecosystem)
                .filter(|spec| spec.decider == Decider::Archive)
                .count(),
            "every archive check reports once"
        );
        self.checks
    }
}

const MIN_README_PROSE: usize = 300;

pub(crate) fn readme_check(context: &Context<'_>, results: &mut Results) {
    match context.readme {
        None => results.fail("readme", "No README at the package root"),
        Some((path, Readme::NotUtf8)) => results.fail("readme", format!("{path} isn't UTF-8 text")),
        Some((path, Readme::Text(text))) => {
            let prose = markdown::Readme::parse(text).prose_chars();
            if prose >= MIN_README_PROSE {
                results.pass("readme", format!("{path} has {prose} characters of prose"));
            } else {
                results.fail(
                    "readme",
                    format!(
                        "{path} has {prose} characters of prose; {MIN_README_PROSE} earn the points"
                    ),
                );
            }
        }
    }
}

/// Whether `text` names `version` as a whole token, with or without a `v`.
fn mentions_version(text: &str, version: &str) -> bool {
    let bytes = text.as_bytes();
    let is_version_char =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+');
    let mut from = 0;
    while let Some(found) = text[from..].find(version) {
        let start = from + found;
        let end = start + version.len();
        let before = start.checked_sub(1).map(|index| bytes[index]);
        let before_ok = match before {
            None => true,
            Some(b'v' | b'V') => start < 2 || !is_version_char(bytes[start - 2]),
            Some(byte) => !is_version_char(byte),
        };
        let after_ok = bytes.get(end).is_none_or(|&byte| {
            !is_version_char(byte)
                || (byte == b'.'
                    && bytes
                        .get(end + 1)
                        .is_none_or(|&next| !next.is_ascii_alphanumeric()))
        });
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

pub(crate) fn changelog_check(context: &Context<'_>, results: &mut Results) {
    if context.changelogs.is_empty() {
        results.fail(
            "changelog",
            "No CHANGELOG, CHANGES or HISTORY file at the package root",
        );
        return;
    }
    let Some(version) = context.version() else {
        results.fail("changelog", "package.json names no version to look for");
        return;
    };
    match context
        .changelogs
        .iter()
        .find(|(_, text)| mentions_version(text, version))
    {
        Some((path, _)) => results.pass("changelog", format!("{path} has an entry for {version}")),
        None => results.fail(
            "changelog",
            format!("{} doesn't mention {version}", context.changelogs[0].0),
        ),
    }
}

pub(crate) fn license_check(context: &Context<'_>, results: &mut Results) {
    let Some(json) = context.manifest else {
        results.fail("license", "No readable package.json at the package root");
        return;
    };
    match json.get("license") {
        Some(Value::String(license)) => {
            let license = license.trim();
            if license == "UNLICENSED" {
                results.fail(
                    "license",
                    "\"UNLICENSED\" grants no rights; use \"SEE LICENSE IN <file>\" for proprietary terms",
                );
            } else if let Some(file) = license.strip_prefix("SEE LICENSE IN ") {
                let file = file.trim();
                if npm::normalize(file).is_some_and(|path| context.archive.has(&path)) {
                    results.pass("license", format!("SEE LICENSE IN {file}"));
                } else {
                    results.fail("license", format!("\"SEE LICENSE IN {file}\" names a file the package doesn't contain"));
                }
            } else if spdx::Expression::parse_mode(license, spdx::ParseMode::STRICT).is_ok() {
                results.pass("license", format!("SPDX expression \"{license}\""));
            } else {
                let deprecated = spdx::Expression::parse_mode(
                    license,
                    spdx::ParseMode {
                        allow_deprecated: true,
                        ..spdx::ParseMode::STRICT
                    },
                )
                .is_ok();
                results.fail(
                    "license",
                    if deprecated {
                        format!("\"{license}\" uses a deprecated SPDX identifier")
                    } else {
                        format!("\"{license}\" isn't a valid SPDX expression")
                    },
                );
            }
        }
        Some(Value::Object(_)) => results.fail("license", "\"license\" is an object; use an SPDX expression string"),
        Some(_) => results.fail("license", "\"license\" isn't a string"),
        None if json.get("licenses").is_some() => results.fail(
            "license",
            "package.json uses the deprecated \"licenses\" array; use a \"license\" SPDX expression",
        ),
        None => results.fail("license", "package.json has no \"license\""),
    }
}

pub(crate) fn license_file_check(context: &Context<'_>, results: &mut Results) {
    let mut found: Vec<&str> = context
        .archive
        .paths()
        .filter(|path| {
            !path.contains('/')
                && ["LICENSE", "LICENCE", "COPYING"].iter().any(|name| {
                    path.get(..name.len())
                        .is_some_and(|start| start.eq_ignore_ascii_case(name))
                        && path[name.len()..]
                            .chars()
                            .next()
                            .is_none_or(|ch| matches!(ch, '.' | '-' | '_'))
                })
        })
        .collect();
    found.sort_unstable();
    match found.first() {
        Some(path) => results.pass("license-file", format!("{path} at the package root")),
        None => results.fail(
            "license-file",
            "No LICENSE, LICENCE or COPYING file at the package root",
        ),
    }
}

fn normalized_words(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

pub(crate) fn description_check(context: &Context<'_>, results: &mut Results) {
    let Some(json) = context.manifest else {
        results.fail(
            "description",
            "No readable package.json at the package root",
        );
        return;
    };
    let Some(description) = npm::string(json, "description").map(str::trim) else {
        results.fail("description", "package.json has no \"description\"");
        return;
    };
    let length = description.chars().count();
    let name = context.package_name().unwrap_or("");
    let short_name = name
        .strip_prefix("@lpm.dev/")
        .and_then(|rest| rest.split_once('.').map(|(_, name)| name))
        .unwrap_or(name);
    let words = normalized_words(description);
    if !words.is_empty()
        && (words == normalized_words(name) || words == normalized_words(short_name))
    {
        results.fail(
            "description",
            "The description only repeats the package name",
        );
    } else if !(20..=280).contains(&length) {
        results.fail(
            "description",
            format!("The description has {length} characters; 20 to 280 earn the points"),
        );
    } else {
        results.pass("description", format!("{length} characters"));
    }
}

pub(crate) fn keywords_check(context: &Context<'_>, results: &mut Results) {
    let count = context
        .manifest
        .and_then(|json| json.get("keywords"))
        .and_then(Value::as_array)
        .map_or(0, |keywords| {
            keywords
                .iter()
                .filter(|keyword| keyword.as_str().is_some_and(|text| !text.trim().is_empty()))
                .count()
        });
    if count > 0 {
        results.pass(
            "keywords",
            format!("{count} keyword{}", if count == 1 { "" } else { "s" }),
        );
    } else {
        results.fail("keywords", "package.json has no keywords");
    }
}

/// Whether `value` is a repository URL npm can open: a URL with a host and
/// a path, an scp-style `git@host:path`, or a `github:`, `gitlab:`,
/// `bitbucket:` or `gist:` shorthand, or `owner/repo`.
fn parse_repository(value: &str) -> bool {
    let value = value.trim();
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    for prefix in ["github:", "gitlab:", "bitbucket:"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            return rest.split_once('/').is_some_and(|(owner, repo)| {
                valid_part(owner) && valid_part(repo.trim_end_matches(".git"))
            });
        }
    }
    if let Some(rest) = value.strip_prefix("gist:") {
        return valid_part(rest);
    }
    if !value.contains(':')
        && let Some((owner, repo)) = value.split_once('/')
    {
        return valid_part(owner) && valid_part(repo);
    }
    let value = value.strip_prefix("git+").unwrap_or(value);
    if let Some(rest) = value.strip_prefix("git@") {
        return rest
            .split_once(':')
            .is_some_and(|(host, path)| !host.is_empty() && path.trim_matches('/').len() > 1);
    }
    url::Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "https" | "http" | "git" | "ssh")
            && url.host_str().is_some_and(|host| !host.is_empty())
            && url.path().trim_matches('/').len() > 1
    })
}

/// Longest repository identity LPM.dev Registry stores.
const MAX_REPOSITORY_IDENTITY_LEN: usize = 300;

/// An owner or repository name as git hosts allow them: ASCII letters,
/// digits, `.`, `_`, `-` and `~`, not only dots.
fn is_repository_part(part: &str) -> bool {
    part.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~'))
        && part.bytes().any(|byte| byte != b'.')
}

/// package.json's repository as `host/owner/name`, lowercase: shorthands
/// expanded as npm expands them (`owner/name` is GitHub), `.git` and the
/// scheme dropped.
fn repository_identity(json: &Value) -> Option<String> {
    let raw = match json.get("repository")? {
        Value::String(url) => url.as_str(),
        Value::Object(object) => object.get("url")?.as_str()?,
        _ => return None,
    }
    .trim();
    if !parse_repository(raw) {
        return None;
    }
    let path_of = |host: &str, path: &str| {
        let path = path.trim_matches('/').trim_end_matches(".git");
        let mut parts = path.split('/').filter(|part| !part.is_empty());
        let (owner, name) = (parts.next()?, parts.next()?);
        let host = host.to_ascii_lowercase();
        let identity = format!("{host}/{owner}/{name}").to_ascii_lowercase();
        // The shape LPM.dev Registry accepts; anything else names no
        // repository rather than failing the whole report there.
        let valid = !host.is_empty()
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
            && [owner, name].iter().all(|part| is_repository_part(part))
            && identity.len() <= MAX_REPOSITORY_IDENTITY_LEN;
        valid.then_some(identity)
    };
    for (prefix, host) in [
        ("github:", "github.com"),
        ("gitlab:", "gitlab.com"),
        ("bitbucket:", "bitbucket.org"),
    ] {
        if let Some(rest) = raw.strip_prefix(prefix) {
            return path_of(host, rest);
        }
    }
    if raw.starts_with("gist:") {
        return None;
    }
    if !raw.contains(':') {
        return path_of("github.com", raw);
    }
    let raw = raw.strip_prefix("git+").unwrap_or(raw);
    if let Some(rest) = raw.strip_prefix("git@") {
        let (host, path) = rest.split_once(':')?;
        return path_of(host, path);
    }
    let url = url::Url::parse(raw).ok()?;
    let host = url.host_str()?.trim_start_matches("www.");
    path_of(host, url.path())
}

pub(crate) fn repository_check(context: &Context<'_>, results: &mut Results) {
    let repository = context.manifest.and_then(|json| json.get("repository"));
    let url = match repository {
        Some(Value::String(url)) => Some(url.as_str()),
        Some(Value::Object(object)) => object.get("url").and_then(Value::as_str),
        _ => None,
    };
    match url {
        None => results.fail("repository", "package.json has no \"repository\" URL"),
        Some(url) if parse_repository(url) => results.pass("repository", url.to_string()),
        Some(url) => results.fail(
            "repository",
            format!("\"{url}\" isn't a repository URL npm can open"),
        ),
    }
}

fn run_swift(
    context: &Context<'_>,
    files: &[(String, swift::SwiftFileFacts)],
    unread: usize,
    manifest_json: Option<&Value>,
) -> Vec<CheckResult> {
    let mut results = Results::new(QualityEcosystem::Swift);
    readme_check(context, &mut results);
    changelog_check(context, &mut results);
    license_check(context, &mut results);
    license_file_check(context, &mut results);
    description_check(context, &mut results);
    keywords_check(context, &mut results);
    repository_check(context, &mut results);
    swift_clean_archive(context, &mut results);
    swift_readme_install(context, &mut results);

    let manifest = manifest_json.map(swift::Manifest::new);
    let targets = manifest
        .as_ref()
        .map(swift::Manifest::targets)
        .unwrap_or_default();
    let in_tests = |path: &str| {
        path.starts_with("Tests/")
            || targets
                .iter()
                .any(|target| target.kind == "test" && target.contains(path))
    };

    let (declarations, documented) = files.iter().filter(|(path, _)| !in_tests(path)).fold(
        (0usize, 0usize),
        |(declarations, documented), (_, facts)| {
            (
                declarations + facts.public_declarations,
                documented + facts.documented_declarations,
            )
        },
    );
    let unread_note = if unread > 0 {
        format!(
            " ({unread} source file{} over 2 MiB unread)",
            if unread == 1 { "" } else { "s" }
        )
    } else {
        String::new()
    };
    if declarations == 0 {
        results.fail(
            "public-api",
            format!("No public or open declarations outside Tests/{unread_note}"),
        );
        results.fail("api-docs", "No public or open declarations to document");
    } else {
        results.pass(
            "public-api",
            format!(
                "{declarations} public or open declaration{}{unread_note}",
                if declarations == 1 { "" } else { "s" }
            ),
        );
        let points = coverage_points(documented, declarations);
        results.score(
            "api-docs",
            points,
            format!(
                "{documented} of {declarations} public declarations have doc comments ({}%)",
                documented * 100 / declarations
            ),
        );
    }

    let Some(manifest) = manifest else {
        for id in [
            "readme-example",
            "platforms",
            "swift-6",
            "versioned-deps",
            "no-unsafe-flags",
            "has-tests",
            "lean-deps",
        ] {
            results.pending(id, "Waiting for the evaluated Package.swift");
        }
        return results.finish();
    };

    swift_readme_example(context, &mut results, &manifest, &targets, files);

    let platforms = manifest.platforms();
    if platforms.is_empty() {
        results.fail("platforms", "Package.swift declares no platforms");
    } else if let Some((name, _)) = platforms.iter().find(|(_, version)| version.is_none()) {
        results.fail("platforms", format!("{name} has no minimum version"));
    } else {
        let list: Vec<String> = platforms
            .iter()
            .map(|(name, version)| format!("{name} {}", version.as_deref().unwrap_or("")))
            .collect();
        results.pass("platforms", list.join(", "));
    }

    let tools = manifest.tools_version();
    let default_mode = manifest.default_language_mode();
    let swift_targets: Vec<&swift::TargetInfo> = targets
        .iter()
        .filter(|target| !matches!(target.kind.as_str(), "binary" | "system"))
        .collect();
    let not_six: Vec<&str> = swift_targets
        .iter()
        .filter(|target| {
            target
                .language_mode
                .as_deref()
                .unwrap_or(default_mode.as_str())
                != "6"
        })
        .map(|target| target.name.as_str())
        .collect();
    let tools_label = tools.map_or_else(
        || "unknown".to_string(),
        |(major, minor)| format!("{major}.{minor}"),
    );
    if not_six.is_empty() && !swift_targets.is_empty() {
        results.pass(
            "swift-6",
            format!("Every target uses the Swift 6 language mode (tools {tools_label})"),
        );
    } else if tools.is_some_and(|version| version >= (5, 9)) {
        results.score(
            "swift-6",
            3,
            format!(
                "swift-tools-version {tools_label}; {} not in the Swift 6 language mode",
                not_six.join(", ")
            ),
        );
    } else {
        results.fail(
            "swift-6",
            format!("swift-tools-version {tools_label} is older than 5.9"),
        );
    }

    let dependencies = manifest.dependencies();
    let unpinned: Vec<&str> = dependencies
        .iter()
        .filter(|(_, versioned)| !versioned)
        .map(|(identity, _)| identity.as_str())
        .collect();
    if unpinned.is_empty() {
        results.pass(
            "versioned-deps",
            if dependencies.is_empty() {
                "No dependencies".to_string()
            } else {
                format!(
                    "All {} dependencies have version requirements",
                    dependencies.len()
                )
            },
        );
    } else {
        results.fail(
            "versioned-deps",
            format!("No version requirement: {}", unpinned.join(", ")),
        );
    }

    let flagged: Vec<&str> = targets
        .iter()
        .filter(|target| target.unsafe_flags)
        .map(|target| target.name.as_str())
        .collect();
    if flagged.is_empty() {
        results.pass("no-unsafe-flags", "No target uses unsafeFlags");
    } else {
        results.fail(
            "no-unsafe-flags",
            format!("unsafeFlags in {}", flagged.join(", ")),
        );
    }

    let tested: Vec<&str> = targets
        .iter()
        .filter(|target| target.kind == "test")
        .filter(|target| {
            files
                .iter()
                .any(|(path, facts)| facts.declares_tests && target.contains(path))
        })
        .map(|target| target.name.as_str())
        .collect();
    let test_targets = targets
        .iter()
        .filter(|target| target.kind == "test")
        .count();
    if let Some(first) = tested.first() {
        results.pass("has-tests", format!("{first} declares tests"));
    } else if test_targets == 0 {
        results.fail("has-tests", "Package.swift declares no test target");
    } else {
        results.fail(
            "has-tests",
            "No test target's directory has an XCTestCase subclass or @Test function",
        );
    }

    let count = dependencies.len();
    let points = match count {
        0 => 7,
        1 => 6,
        2 => 5,
        3..=4 => 4,
        5..=6 => 3,
        7..=10 => 2,
        11..=20 => 1,
        _ => 0,
    };
    results.score(
        "lean-deps",
        points,
        format!("{count} dependenc{}", if count == 1 { "y" } else { "ies" }),
    );

    results.finish()
}

/// Points for documented `documented` of `total`: 80% earn 10, 50% earn 6,
/// 20% earn 3.
pub(crate) fn coverage_points(documented: usize, total: usize) -> u32 {
    if total == 0 {
        return 0;
    }
    let percent = documented * 100;
    if percent >= 80 * total {
        10
    } else if percent >= 50 * total {
        6
    } else if percent >= 20 * total {
        3
    } else {
        0
    }
}

/// The SE-0292 identity of an `@lpm.dev/owner.name` package.
fn swift_identity(name: &str) -> Option<String> {
    let (owner, package) = name.strip_prefix("@lpm.dev/")?.split_once('.')?;
    Some(format!("lpmdev.{owner}_{package}"))
}

fn swift_readme_install(context: &Context<'_>, results: &mut Results) {
    let Some(text) = context.readme_text() else {
        results.fail("readme-install", "No README");
        return;
    };
    let Some(name) = context.package_name() else {
        results.fail("readme-install", "package.json names no package");
        return;
    };
    let readme = markdown::Readme::parse(text);
    if let Some(line) = swift_identity(name)
        .and_then(|identity| markdown::find_swift_package_declaration(&readme.blocks, &identity))
        .or_else(|| {
            markdown::find_install_command(
                &readme.blocks,
                name,
                markdown::Installers {
                    javascript: false,
                    source_delivery: context.is_source_package(),
                },
            )
        })
    {
        results.pass("readme-install", format!("README shows `{}`", line.trim()));
    } else {
        results.fail(
            "readme-install",
            format!(
                "No code block declares .package(id: \"{}\") or runs lpm install {name}",
                swift_identity(name).unwrap_or_default()
            ),
        );
    }
}

fn swift_readme_example(
    context: &Context<'_>,
    results: &mut Results,
    manifest: &swift::Manifest<'_>,
    targets: &[swift::TargetInfo],
    files: &[(String, swift::SwiftFileFacts)],
) {
    let Some(text) = context.readme_text() else {
        results.fail("readme-example", "No README");
        return;
    };
    let modules = manifest.library_modules();
    let readme = markdown::Readme::parse(text);
    let samples: Vec<swift::SampleUse> = readme
        .blocks
        .iter()
        .filter(|block| block.language == "swift")
        .map(|block| swift::sample_use(block.body))
        .filter(|sample| sample.imports.iter().any(|module| modules.contains(module)))
        .collect();
    if samples.is_empty() {
        results.fail(
            "readme-example",
            if modules.is_empty() {
                "The package has no library product to import".to_string()
            } else {
                format!("No swift code block imports {}", modules.join(" or "))
            },
        );
        return;
    }
    let public_names = |module: &str| -> std::collections::HashSet<&str> {
        let Some(target) = targets
            .iter()
            .find(|target| swift::module_name(&target.name) == module)
        else {
            return Default::default();
        };
        files
            .iter()
            .filter(|(path, _)| target.contains(path))
            .flat_map(|(_, facts)| facts.public_names.iter().map(String::as_str))
            .collect()
    };
    let mut used = false;
    let mut missing = None;
    for sample in &samples {
        for module in sample
            .imports
            .iter()
            .filter(|module| modules.contains(module))
        {
            let names = public_names(module);
            used |= sample
                .identifiers
                .iter()
                .any(|identifier| names.contains(identifier.as_str()));
            if let Some((_, name)) = sample
                .qualified
                .iter()
                .find(|(qualifier, name)| qualifier == module && !names.contains(name.as_str()))
            {
                missing.get_or_insert_with(|| format!("{module}.{name}"));
            }
        }
    }
    match (used, missing) {
        (true, None) => results.pass(
            "readme-example",
            "A swift example imports the package and uses its public API",
        ),
        (_, Some(name)) => results.score(
            "readme-example",
            2,
            format!("The example uses {name}, which the module doesn't declare public"),
        ),
        (false, None) => results.score(
            "readme-example",
            2,
            "The example imports the package but uses none of its public declarations",
        ),
    }
}

fn swift_clean_archive(context: &Context<'_>, results: &mut Results) {
    const JUNK: &[&str] = &[".build", ".swiftpm", "xcuserdata", "DerivedData", ".git"];
    let mut found: Vec<&str> = context
        .archive
        .paths()
        .filter_map(|path| path.split('/').find(|segment| JUNK.contains(segment)))
        .collect();
    found.sort_unstable();
    found.dedup();
    if found.is_empty() {
        results.pass(
            "clean-archive",
            "No build output or local state in the package",
        );
    } else {
        results.fail(
            "clean-archive",
            format!("The package contains {}", found.join(", ")),
        );
    }
}

#[cfg(test)]
mod tests;
