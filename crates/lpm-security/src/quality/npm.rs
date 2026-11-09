//! A JavaScript package's entry points as Node.js and TypeScript resolve
//! them from package.json, over the files its archive holds.

use super::Archive;
use serde_json::{Map, Value};
use std::cell::Cell;
use std::collections::HashMap;

/// A package-relative path as `package.json` writes it (`./lib/x.js`,
/// `lib/x.js`), normalized, or `None` when it leaves the package or isn't
/// relative.
pub(crate) fn normalize(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.starts_with('/') || raw.contains('\\') || raw.contains(':') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    Some(parts.join("/"))
}

/// A target or condition tree of `exports`.
#[derive(Debug)]
pub(crate) enum Target<'a> {
    Path(&'a str),
    Null,
    Conditions(Vec<(&'a str, Target<'a>)>),
    Fallbacks(Vec<Target<'a>>),
    /// A target Node.js refuses (`ERR_INVALID_PACKAGE_TARGET`), such as a
    /// number or a path with a `..` segment. A fallback array skips it.
    Invalid,
    /// A condition object with a numeric key, which Node.js refuses as a
    /// broken package.json (`ERR_INVALID_PACKAGE_CONFIG`). Nothing skips it.
    InvalidConfig,
}

impl<'a> Target<'a> {
    fn parse(value: &'a Value) -> Self {
        match value {
            Value::String(path) if valid_target(path) => Self::Path(path),
            Value::Null => Self::Null,
            Value::Array(items) => Self::Fallbacks(items.iter().map(Self::parse).collect()),
            Value::Object(map) if map.keys().any(|key| is_array_index(key)) => Self::InvalidConfig,
            Value::Object(map) => Self::Conditions(
                map.iter()
                    .map(|(key, value)| (key.as_str(), Self::parse(value)))
                    .collect(),
            ),
            _ => Self::Invalid,
        }
    }

    /// Every path the tree can resolve to, each with whether a `types`
    /// condition leads to it.
    pub fn paths(&self, out: &mut Vec<(&'a str, bool)>) {
        self.paths_within(out, false);
    }

    fn paths_within(&self, out: &mut Vec<(&'a str, bool)>, via_types: bool) {
        match self {
            Self::Path(path) => out.push((path, via_types)),
            Self::Conditions(conditions) => {
                for (key, target) in conditions {
                    target.paths_within(out, via_types || *key == "types");
                }
            }
            Self::Fallbacks(targets) => {
                for target in targets {
                    target.paths_within(out, via_types);
                }
            }
            Self::Null | Self::Invalid | Self::InvalidConfig => {}
        }
    }

    /// The path `conditions` select, as Node.js resolves a condition tree,
    /// and whether a `types` condition chose it. `None` when no condition
    /// matches or the tree maps to null.
    pub fn resolve(&self, conditions: &[&str]) -> Option<Resolution<'a>> {
        match self.resolve_with(conditions, false) {
            Outcome::Found(resolution) => Some(resolution),
            Outcome::Excluded | Outcome::NoMatch | Outcome::Invalid | Outcome::InvalidConfig => {
                None
            }
        }
    }

    /// Node.js's PACKAGE_TARGET_RESOLVE: a matched condition whose target
    /// is null excludes the subpath instead of falling through to the next
    /// condition, and an invalid target fails it. A fallback array skips
    /// both and ends as its last skipped item did, as Node.js's resolver
    /// does.
    fn resolve_with(&self, conditions: &[&str], via_types: bool) -> Outcome<'a> {
        match self {
            Self::Path(path) => Outcome::Found(Resolution { path, via_types }),
            Self::Null => Outcome::Excluded,
            Self::Invalid => Outcome::Invalid,
            Self::InvalidConfig => Outcome::InvalidConfig,
            Self::Conditions(entries) => {
                for (key, target) in entries {
                    if *key != "default" && !conditions.contains(key) {
                        continue;
                    }
                    match target.resolve_with(conditions, via_types || *key == "types") {
                        Outcome::NoMatch => {}
                        outcome => return outcome,
                    }
                }
                Outcome::NoMatch
            }
            Self::Fallbacks(targets) => {
                let mut last = Outcome::NoMatch;
                for target in targets {
                    match target.resolve_with(conditions, via_types) {
                        Outcome::Found(resolution) => return Outcome::Found(resolution),
                        Outcome::InvalidConfig => return Outcome::InvalidConfig,
                        Outcome::NoMatch => {}
                        skipped => last = skipped,
                    }
                }
                last
            }
        }
    }

    /// Each condition object's keys, for the ordering rules.
    fn condition_lists(&self, out: &mut Vec<Vec<&'a str>>) {
        match self {
            Self::Conditions(entries) => {
                out.push(entries.iter().map(|(key, _)| *key).collect());
                for (_, target) in entries {
                    target.condition_lists(out);
                }
            }
            Self::Fallbacks(targets) => {
                for target in targets {
                    target.condition_lists(out);
                }
            }
            _ => {}
        }
    }

    fn has_invalid(&self) -> bool {
        match self {
            Self::Invalid | Self::InvalidConfig => true,
            Self::Conditions(entries) => entries.iter().any(|(_, target)| target.has_invalid()),
            Self::Fallbacks(targets) => targets.iter().any(Target::has_invalid),
            _ => false,
        }
    }
}

enum Outcome<'a> {
    Found(Resolution<'a>),
    Excluded,
    NoMatch,
    Invalid,
    InvalidConfig,
}

/// A key Node.js reads as an array index, which no condition object may
/// have.
fn is_array_index(key: &str) -> bool {
    !key.is_empty()
        && key.bytes().all(|byte| byte.is_ascii_digit())
        && (key == "0" || !key.starts_with('0'))
        && key.parse::<u32>().is_ok_and(|index| index < u32::MAX)
}

/// Node.js's rule for an `exports` target: `./`, then no segment Node.js
/// refuses, and no percent-encoding it can't turn into a file path.
fn valid_target(raw: &str) -> bool {
    raw.strip_prefix("./")
        .is_some_and(|rest| !has_refused_segment(rest))
        && percent_decoded(raw).is_some()
}

/// The longest path a target can name. A pattern whose substitution would
/// be longer names no file, so it's never built: a target of thousands of
/// `*` would otherwise multiply a long subpath into megabytes.
const MAX_TARGET_BYTES: usize = 4096;

/// A target's file as Node.js loads it, which decodes the target's URL
/// percent-encoding, normalized. `None` when it leaves the package, or
/// Node.js can't decode it: an encoded `/` or `\`, a malformed escape, or
/// bytes that aren't UTF-8.
pub(crate) fn target_path(raw: &str) -> Option<String> {
    normalize(&percent_decoded(raw)?)
}

fn percent_decoded(raw: &str) -> Option<String> {
    if !raw.contains('%') {
        return Some(raw.to_string());
    }
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let hex = bytes.get(index + 1..index + 3)?;
        let byte = u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
        if byte == b'/' || byte == b'\\' {
            return None;
        }
        decoded.push(byte);
        index += 3;
    }
    String::from_utf8(decoded).ok()
}

/// `target` with each `*` replaced by `matched`, as Node.js substitutes a
/// pattern's match, or `None` when the result would be longer than
/// [`MAX_TARGET_BYTES`].
pub(crate) fn substitute(target: &str, matched: &str) -> Option<String> {
    let stars = target.bytes().filter(|&byte| byte == b'*').count();
    let length = stars
        .checked_mul(matched.len())?
        .checked_add(target.len() - stars)?;
    (length <= MAX_TARGET_BYTES).then(|| target.replace('*', matched))
}

/// Whether a target, or the part of a subpath a pattern's `*` matches, has a
/// `.`, `..` or `node_modules` segment, percent-encoded or not and in any
/// case, as Node.js's resolver refuses. An empty segment only draws its
/// deprecation warning.
fn has_refused_segment(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escaped = (bytes[index] == b'%')
            .then(|| bytes.get(index + 1..index + 3))
            .flatten()
            .and_then(|code| match [code[0], code[1].to_ascii_lowercase()] {
                [b'2', b'e'] => Some(b'.'),
                [b'5', b'f'] => Some(b'_'),
                [b'6' | b'4', b'e'] => Some(b'n'),
                [b'6' | b'4', b'f'] => Some(b'o'),
                [b'6' | b'4', b'4'] => Some(b'd'),
                [b'6' | b'4', b'5'] => Some(b'e'),
                [b'6' | b'4', b'd'] => Some(b'm'),
                [b'6' | b'4', b'c'] => Some(b'l'),
                [b'7' | b'5', b'5'] => Some(b'u'),
                [b'7' | b'5', b'3'] => Some(b's'),
                _ => None,
            });
        match escaped {
            Some(byte) => {
                decoded.push(byte);
                index += 3;
            }
            None => {
                decoded.push(bytes[index].to_ascii_lowercase());
                index += 1;
            }
        }
    }
    decoded
        .split(|&byte| byte == b'/' || byte == b'\\')
        .any(|segment| matches!(segment, b"." | b".." | b"node_modules"))
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Resolution<'a> {
    pub path: &'a str,
    pub via_types: bool,
}

/// `exports`, as subpaths and their targets.
pub(crate) struct Exports<'a> {
    pub entries: Vec<(&'a str, Target<'a>)>,
    /// The index in `entries` of each subpath without a `*`.
    exact: HashMap<&'a str, usize>,
    /// Each pattern subpath (one `*`) as its prefix and suffix, with its
    /// index in `entries`.
    patterns: Vec<(&'a str, &'a str, usize)>,
    /// Pattern keys the lookups have compared, against
    /// `MAX_PATTERN_COMPARISONS`.
    pattern_comparisons: Cell<usize>,
}

/// Pattern keys the subpath lookups of one report may compare in all. Node.js
/// compares a subpath with every pattern key; a package.json with a million
/// of them would make each lookup scan them all.
const MAX_PATTERN_COMPARISONS: usize = 2_000_000;

impl<'a> Exports<'a> {
    /// `Err` with the reason when Node.js would refuse the map.
    pub fn parse(value: &'a Value) -> Result<Self, String> {
        let entries = match value {
            Value::Object(map) => {
                let subpaths = map.keys().filter(|key| key.starts_with('.')).count();
                if subpaths == 0 {
                    vec![(".", Target::parse(value))]
                } else if subpaths == map.len() {
                    map.iter()
                        .map(|(key, value)| (key.as_str(), Target::parse(value)))
                        .collect()
                } else {
                    return Err(
                        "\"exports\" mixes subpaths (\"./x\") with conditions (\"import\") at its top level"
                            .to_string(),
                    );
                }
            }
            Value::String(_) | Value::Array(_) => vec![(".", Target::parse(value))],
            _ => return Err("\"exports\" is not a path, an array or an object".to_string()),
        };
        let mut exact = HashMap::new();
        let mut patterns = Vec::new();
        for (index, (key, _)) in entries.iter().enumerate() {
            match key.split_once('*') {
                None => {
                    exact.insert(*key, index);
                }
                Some((prefix, suffix)) if !suffix.contains('*') => {
                    patterns.push((prefix, suffix, index));
                }
                Some(_) => {}
            }
        }
        Ok(Self {
            entries,
            exact,
            patterns,
            pattern_comparisons: Cell::new(0),
        })
    }

    /// The file `subpath` resolves to under `conditions`, through an exact
    /// subpath or else the pattern Node.js picks (the longest prefix before
    /// its `*`), with whether a `types` condition chose it.
    pub fn resolve_subpath(&self, subpath: &str, conditions: &[&str]) -> Option<(String, bool)> {
        if let Some(&index) = self.exact.get(subpath) {
            let resolution = self.entries[index].1.resolve(conditions)?;
            return target_path(resolution.path).map(|path| (path, resolution.via_types));
        }
        let compared = self
            .pattern_comparisons
            .get()
            .saturating_add(self.patterns.len());
        self.pattern_comparisons.set(compared);
        if compared > MAX_PATTERN_COMPARISONS {
            return None;
        }
        let (index, matched) = self
            .patterns
            .iter()
            .filter(|(prefix, suffix, _)| {
                subpath.len() > prefix.len() + suffix.len()
                    && subpath.starts_with(prefix)
                    && subpath.ends_with(suffix)
            })
            .max_by_key(|(prefix, suffix, _)| (prefix.len(), suffix.len()))
            .map(|(prefix, suffix, index)| {
                (*index, &subpath[prefix.len()..subpath.len() - suffix.len()])
            })?;
        if has_refused_segment(matched) {
            return None;
        }
        let resolution = self.entries[index].1.resolve(conditions)?;
        target_path(&substitute(resolution.path, matched)?).map(|path| (path, resolution.via_types))
    }
}

/// The runtime conditions Node.js matches for `import` and `require`.
pub(crate) const IMPORT_CONDITIONS: &[&str] = &["import", "node"];
pub(crate) const REQUIRE_CONDITIONS: &[&str] = &["require", "node"];
/// TypeScript's conditions under `moduleResolution: "nodenext"`.
pub(crate) const TYPES_IMPORT_CONDITIONS: &[&str] = &["types", "import", "node"];
pub(crate) const TYPES_REQUIRE_CONDITIONS: &[&str] = &["types", "require", "node"];

pub(crate) fn is_declaration(path: &str) -> bool {
    path.ends_with(".d.ts") || path.ends_with(".d.mts") || path.ends_with(".d.cts")
}

/// The declaration file TypeScript reads beside a JavaScript file: `.d.ts`
/// for `.js`, `.d.mts` for `.mjs`, `.d.cts` for `.cjs`.
pub(crate) fn sibling_declaration(path: &str) -> Option<String> {
    for (js, declaration) in [
        (".mjs", ".d.mts"),
        (".cjs", ".d.cts"),
        (".jsx", ".d.ts"),
        (".js", ".d.ts"),
    ] {
        if let Some(stem) = path.strip_suffix(js) {
            return Some(format!("{stem}{declaration}"));
        }
    }
    None
}

/// The files an `exports` pattern target (`./dist/*.js`) matches, each with
/// what its `*` matched, in path order, or `None` once the archive's
/// pattern lookups have run out. A target with several `*` matches a file
/// only where each takes the same text, as Node.js substitutes one match
/// into all of them.
pub(crate) fn pattern_matches<'f>(
    archive: &'f Archive,
    target: &str,
) -> Option<Vec<(&'f str, &'f str)>> {
    let Some(pattern) = TargetPattern::parse(target) else {
        return Some(Vec::new());
    };
    let files = archive.pattern_files(&pattern.prefix, &pattern.suffix)?;
    Some(
        files
            .into_iter()
            .filter_map(|file| pattern.capture(file).map(|matched| (file, matched)))
            .collect(),
    )
}

/// A pattern target split at its `*`s, each piece decoded as Node.js
/// decodes the target.
struct TargetPattern {
    prefix: String,
    middles: Vec<String>,
    suffix: String,
}

impl TargetPattern {
    fn parse(target: &str) -> Option<Self> {
        let mut pieces = target.split('*');
        let prefix = normalize_prefix(&percent_decoded(pieces.next()?)?)?;
        let mut rest: Vec<String> = pieces.map(percent_decoded).collect::<Option<_>>()?;
        let suffix = rest.pop()?;
        Some(Self {
            prefix,
            middles: rest,
            suffix,
        })
    }

    /// What each `*` matches in `file`, which `pattern_files` found under
    /// the prefix and ending with the suffix.
    fn capture<'f>(&self, file: &'f str) -> Option<&'f str> {
        let middle = file.get(self.prefix.len()..file.len().checked_sub(self.suffix.len())?)?;
        if self.middles.is_empty() {
            return (!middle.is_empty()).then_some(middle);
        }
        let stars = self.middles.len() + 1;
        let literal: usize = self.middles.iter().map(String::len).sum();
        let spare = middle.len().checked_sub(literal)?;
        if spare == 0 || spare % stars != 0 {
            return None;
        }
        let matched = middle.get(..spare / stars)?;
        let mut rest = &middle[matched.len()..];
        for piece in &self.middles {
            rest = rest.strip_prefix(piece.as_str())?.strip_prefix(matched)?;
        }
        rest.is_empty().then_some(matched)
    }
}

fn normalize_prefix(prefix: &str) -> Option<String> {
    let trailing_slash = prefix.ends_with('/');
    let normalized = normalize(prefix.trim_end_matches('/'))?;
    Some(if trailing_slash && !normalized.is_empty() {
        format!("{normalized}/")
    } else if trailing_slash {
        String::new()
    } else {
        normalized
    })
}

/// Where Node.js finds `main`: the path, then with `.js`, `.json` or
/// `.node`, then `index.*` inside it.
pub(crate) fn resolve_main(archive: &Archive, raw: &str) -> Option<String> {
    let path = normalize(raw)?;
    let candidates = [
        path.clone(),
        format!("{path}.js"),
        format!("{path}.json"),
        format!("{path}.node"),
        join(&path, "index.js"),
        join(&path, "index.json"),
        join(&path, "index.node"),
    ];
    candidates
        .into_iter()
        .find(|candidate| archive.has(candidate))
}

/// The file a `types` or `typings` field names, as TypeScript looks for it:
/// the declarations it finds there, the path itself, the path with
/// `.d.ts`, or `index.d.ts` inside it.
pub(crate) fn types_field_file(archive: &Archive, raw: &str) -> Option<String> {
    let path = normalize(raw)?;
    declaration_at(archive, &path).or_else(|| {
        [
            path.clone(),
            format!("{path}.d.ts"),
            join(&path, "index.d.ts"),
        ]
        .into_iter()
        .find(|candidate| archive.has(candidate))
    })
}

/// The declarations TypeScript reads where a `types` field or condition
/// points: a declaration file or TypeScript source, or for a JavaScript
/// path the source or declaration TypeScript puts in its place, whether or
/// not the JavaScript file is there. A README or JSON file declares nothing.
pub(crate) fn declaration_at(archive: &Archive, path: &str) -> Option<String> {
    declaration_candidates(path)
        .into_iter()
        .find(|candidate| archive.has(candidate))
}

/// Where TypeScript looks for the declarations of `path`, in its order: a
/// declaration or TypeScript source as it is, or for a JavaScript
/// extension the TypeScript extensions it substitutes.
pub(crate) fn declaration_candidates(path: &str) -> Vec<String> {
    if is_declaration(path) || is_typescript_source(path) {
        return vec![path.to_string()];
    }
    for (javascript, substitutes) in [
        (".mjs", &[".mts", ".d.mts"][..]),
        (".cjs", &[".cts", ".d.cts"][..]),
        (".jsx", &[".tsx", ".ts", ".d.ts"][..]),
        (".js", &[".ts", ".tsx", ".d.ts"][..]),
    ] {
        if let Some(stem) = path.strip_suffix(javascript) {
            return substitutes
                .iter()
                .map(|extension| format!("{stem}{extension}"))
                .collect();
        }
    }
    Vec::new()
}

/// Whether TypeScript finds declarations where a `types` condition's
/// target points: an exact path, or a pattern that matches one.
fn types_target_exists(archive: &Archive, raw: &str) -> bool {
    if raw.contains('*') {
        return declaration_candidates(raw)
            .iter()
            .any(|pattern| target_exists(archive, pattern));
    }
    target_path(raw).is_some_and(|path| declaration_at(archive, &path).is_some())
}

pub(crate) fn is_typescript_source(path: &str) -> bool {
    [".ts", ".mts", ".cts", ".tsx"]
        .iter()
        .any(|extension| path.ends_with(extension))
        && !is_declaration(path)
}

fn join(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_string()
    } else {
        format!("{directory}/{name}")
    }
}

/// An `exports` target that must exist: an exact path, or a pattern at
/// least one file matches.
pub(crate) fn target_exists(archive: &Archive, raw: &str) -> bool {
    if !raw.starts_with("./") {
        return false;
    }
    if raw.contains('*') {
        return pattern_matches(archive, raw).is_some_and(|matched| !matched.is_empty());
    }
    target_path(raw).is_some_and(|path| archive.has(&path))
}

/// Whether a target an `exports` condition leads to is there: under a
/// `types` condition, the declarations TypeScript reads for it will do.
pub(crate) fn condition_target_exists(archive: &Archive, raw: &str, via_types: bool) -> bool {
    target_exists(archive, raw) || (via_types && types_target_exists(archive, raw))
}

/// The paths `exports` names that are missing, and the condition objects
/// that break its ordering rules.
pub(crate) struct ExportsProblems {
    pub missing: Vec<String>,
    pub misordered: Vec<String>,
    pub invalid: bool,
}

pub(crate) fn exports_problems(archive: &Archive, exports: &Exports<'_>) -> ExportsProblems {
    let mut problems = ExportsProblems {
        missing: Vec::new(),
        misordered: Vec::new(),
        invalid: false,
    };
    for (subpath, target) in &exports.entries {
        let mut paths = Vec::new();
        target.paths(&mut paths);
        for (path, via_types) in paths {
            if !condition_target_exists(archive, path, via_types) {
                problems.missing.push(path.to_string());
            }
        }
        problems.invalid |= target.has_invalid();
        let mut lists = Vec::new();
        target.condition_lists(&mut lists);
        for keys in lists {
            let types_misplaced = keys
                .iter()
                .position(|key| *key == "types")
                .is_some_and(|index| index != 0);
            let default_misplaced = keys
                .iter()
                .position(|key| *key == "default")
                .is_some_and(|index| index + 1 != keys.len());
            if types_misplaced || default_misplaced {
                problems.misordered.push((*subpath).to_string());
            }
        }
    }
    problems.misordered.dedup();
    problems
}

pub(crate) fn object<'v>(json: &'v Value, key: &str) -> Option<&'v Map<String, Value>> {
    json.get(key).and_then(Value::as_object)
}

pub(crate) fn string<'v>(json: &'v Value, key: &str) -> Option<&'v str> {
    json.get(key).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_follow_node_segment_rules() {
        for valid in [
            "./index.js",
            "./dist//index.js",
            "./a.b/c",
            "./node_modules_x/a",
        ] {
            assert!(valid_target(valid), "{valid}");
        }
        for refused in [
            "index.js",
            "../index.js",
            "./dist/../index.js",
            "./dist/./index.js",
            "./node_modules/x/index.js",
            "./%2e%2E/index.js",
            "./%4E%4fde_modules/x.js",
            "./NODE_MODULES/x.js",
            "./dist\\..\\index.js",
        ] {
            assert!(!valid_target(refused), "{refused}");
        }
    }

    #[test]
    fn a_pattern_resolves_by_its_longest_prefix_and_refuses_traversal() {
        let value = serde_json::json!({
            "./*": "./dist/*.js",
            "./icons/*": "./dist/icons/*.svg.js",
            "./internal/*": null
        });
        let exports = Exports::parse(&value).unwrap();
        let resolve = |subpath: &str| {
            exports
                .resolve_subpath(subpath, &["import"])
                .map(|(path, _)| path)
        };
        assert_eq!(resolve("./a").as_deref(), Some("dist/a.js"));
        assert_eq!(resolve("./icons/x").as_deref(), Some("dist/icons/x.svg.js"));
        assert_eq!(resolve("./internal/x"), None);
        assert_eq!(resolve("./../../etc/passwd"), None);
        assert_eq!(resolve("./a/%2e%2e/b"), None);
    }

    #[test]
    fn a_numeric_condition_key_fails_even_inside_a_fallback_array() {
        let exports = serde_json::json!([{ "0": "./a.js" }, "./b.js"]);
        assert!(Target::parse(&exports).resolve(&["import"]).is_none());
        let exports = serde_json::json!(["../a.js", "./b.js"]);
        assert_eq!(
            Target::parse(&exports)
                .resolve(&["import"])
                .map(|found| found.path),
            Some("./b.js")
        );
    }
    use serde_json::json;

    #[test]
    fn normalize_keeps_paths_inside_the_package() {
        assert_eq!(
            normalize("./lib/./index.js").as_deref(),
            Some("lib/index.js")
        );
        assert_eq!(normalize("lib/../dist/x.js").as_deref(), Some("dist/x.js"));
        assert_eq!(normalize("../outside.js"), None);
        assert_eq!(normalize("/abs.js"), None);
        assert_eq!(normalize("C:\\x.js"), None);
    }

    #[test]
    fn conditions_resolve_in_object_order_with_default_last_resort() {
        let value = json!({
            "types": "./index.d.ts",
            "import": { "types": "./index.d.mts", "default": "./index.mjs" },
            "require": "./index.cjs",
            "default": "./index.js"
        });
        let target = Target::parse(&value);
        let import = target.resolve(IMPORT_CONDITIONS).unwrap();
        assert_eq!(import.path, "./index.mjs");
        assert!(!import.via_types);
        let types = target.resolve(TYPES_IMPORT_CONDITIONS).unwrap();
        assert_eq!(types.path, "./index.d.ts");
        assert!(types.via_types);
        assert_eq!(
            target.resolve(REQUIRE_CONDITIONS).unwrap().path,
            "./index.cjs"
        );
        assert_eq!(target.resolve(&["browser"]).unwrap().path, "./index.js");
    }

    #[test]
    fn a_null_target_resolves_to_nothing() {
        let value = json!({ "import": null, "default": "./x.js" });
        assert!(Target::parse(&value).resolve(IMPORT_CONDITIONS).is_none());
    }

    #[test]
    fn exports_mixing_subpaths_and_conditions_is_refused() {
        let value = json!({ ".": "./a.js", "import": "./b.mjs" });
        assert!(Exports::parse(&value).is_err());
    }

    fn archive_of(paths: &[&str]) -> Archive {
        let mut archive = Archive::default();
        for path in paths {
            archive.files.insert((*path).to_string(), 1);
        }
        archive
    }

    #[test]
    fn a_target_is_decoded_as_node_loads_its_file() {
        assert_eq!(target_path("./%61.js").as_deref(), Some("a.js"));
        assert_eq!(
            target_path("./dist/caf%C3%A9.js").as_deref(),
            Some("dist/café.js")
        );
        for refused in [
            "./a%2fb.js",
            "./a%2Fb.js",
            "./a%5Cb.js",
            "./a%zz.js",
            "./%ff.js",
        ] {
            assert!(!valid_target(refused), "{refused}");
        }
    }

    #[test]
    fn every_star_of_a_target_takes_the_same_match() {
        let value = json!({ "./*": "./dist/*-*.js" });
        let exports = Exports::parse(&value).unwrap();
        assert_eq!(
            exports
                .resolve_subpath("./a", IMPORT_CONDITIONS)
                .map(|(path, _)| path)
                .as_deref(),
            Some("dist/a-a.js")
        );
        let archive = archive_of(&["dist/a-a.js", "dist/a-b.js", "dist/ab-ab.js"]);
        assert_eq!(
            pattern_matches(&archive, "./dist/*-*.js"),
            Some(vec![("dist/a-a.js", "a"), ("dist/ab-ab.js", "ab")])
        );
    }

    #[test]
    fn a_substitution_longer_than_any_path_names_no_file() {
        let value = json!({ "./*": format!("./{}.js", "*".repeat(50_000)) });
        let exports = Exports::parse(&value).unwrap();
        let subpath = format!("./{}", "a".repeat(1_000));
        assert_eq!(exports.resolve_subpath(&subpath, IMPORT_CONDITIONS), None);
        assert_eq!(substitute("./*.js", &"a".repeat(MAX_TARGET_BYTES)), None);
    }

    #[test]
    fn typescript_reads_the_declaration_in_place_of_a_javascript_path() {
        let archive = archive_of(&["types/index.d.ts", "esm/a.d.mts", "src/b.ts"]);
        assert_eq!(
            declaration_at(&archive, "types/index.js").as_deref(),
            Some("types/index.d.ts")
        );
        assert_eq!(
            declaration_at(&archive, "esm/a.mjs").as_deref(),
            Some("esm/a.d.mts")
        );
        assert_eq!(
            declaration_at(&archive, "src/b.js").as_deref(),
            Some("src/b.ts")
        );
        assert_eq!(
            types_field_file(&archive, "./types/index.js").as_deref(),
            Some("types/index.d.ts")
        );
        assert!(condition_target_exists(&archive, "./types/index.js", true));
        assert!(!condition_target_exists(
            &archive,
            "./types/index.js",
            false
        ));
    }

    #[test]
    fn sibling_declarations_follow_the_module_format() {
        assert_eq!(
            sibling_declaration("dist/a.mjs").as_deref(),
            Some("dist/a.d.mts")
        );
        assert_eq!(
            sibling_declaration("dist/a.cjs").as_deref(),
            Some("dist/a.d.cts")
        );
        assert_eq!(
            sibling_declaration("dist/a.js").as_deref(),
            Some("dist/a.d.ts")
        );
        assert_eq!(sibling_declaration("dist/a.json"), None);
    }
}
