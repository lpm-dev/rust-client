//! A JavaScript package's entry points as Node.js and TypeScript resolve
//! them from package.json, over the files its archive holds.

use super::Archive;
use serde_json::{Map, Value};

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
    /// A value no resolver accepts, such as a number.
    Invalid,
}

impl<'a> Target<'a> {
    fn parse(value: &'a Value) -> Self {
        match value {
            Value::String(path) => Self::Path(path),
            Value::Null => Self::Null,
            Value::Array(items) => Self::Fallbacks(items.iter().map(Self::parse).collect()),
            Value::Object(map) => Self::Conditions(
                map.iter()
                    .map(|(key, value)| (key.as_str(), Self::parse(value)))
                    .collect(),
            ),
            _ => Self::Invalid,
        }
    }

    /// Every path the tree can resolve to.
    pub fn paths(&self, out: &mut Vec<&'a str>) {
        match self {
            Self::Path(path) => out.push(path),
            Self::Conditions(conditions) => {
                for (_, target) in conditions {
                    target.paths(out);
                }
            }
            Self::Fallbacks(targets) => {
                for target in targets {
                    target.paths(out);
                }
            }
            Self::Null | Self::Invalid => {}
        }
    }

    /// The path `conditions` select, as Node.js resolves a condition tree,
    /// and whether a `types` condition chose it. `None` when no condition
    /// matches or the tree maps to null.
    pub fn resolve(&self, conditions: &[&str]) -> Option<Resolution<'a>> {
        match self.resolve_with(conditions, false) {
            Outcome::Found(resolution) => Some(resolution),
            Outcome::Excluded | Outcome::NoMatch => None,
        }
    }

    /// Node.js's PACKAGE_TARGET_RESOLVE: a matched condition whose target
    /// is null excludes the subpath instead of falling through to the next
    /// condition.
    fn resolve_with(&self, conditions: &[&str], via_types: bool) -> Outcome<'a> {
        match self {
            Self::Path(path) => Outcome::Found(Resolution { path, via_types }),
            Self::Null => Outcome::Excluded,
            Self::Invalid => Outcome::NoMatch,
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
                for target in targets {
                    match target.resolve_with(conditions, via_types) {
                        Outcome::NoMatch => {}
                        outcome => return outcome,
                    }
                }
                Outcome::NoMatch
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
            Self::Invalid => true,
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
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Resolution<'a> {
    pub path: &'a str,
    pub via_types: bool,
}

/// `exports`, as subpaths and their targets.
pub(crate) struct Exports<'a> {
    pub entries: Vec<(&'a str, Target<'a>)>,
}

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
        Ok(Self { entries })
    }

    pub fn target(&self, subpath: &str) -> Option<&Target<'a>> {
        self.entries
            .iter()
            .find(|(key, _)| *key == subpath)
            .map(|(_, target)| target)
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

/// The files a target with one `*` matches, by Node.js pattern rules.
pub(crate) fn pattern_matches<'f>(archive: &'f Archive, target: &str) -> Vec<&'f str> {
    let Some((prefix, suffix)) = target.split_once('*') else {
        return Vec::new();
    };
    let (Some(prefix), suffix) = (normalize_prefix(prefix), suffix) else {
        return Vec::new();
    };
    archive
        .paths()
        .filter(|path| {
            path.len() > prefix.len() + suffix.len()
                && path.starts_with(prefix.as_str())
                && path.ends_with(suffix)
        })
        .collect()
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

/// Where TypeScript finds `types` or `typings`: the path, with `.d.ts`, or
/// `index.d.ts` inside it.
pub(crate) fn resolve_types_field(archive: &Archive, raw: &str) -> Option<String> {
    let path = normalize(raw)?;
    [
        path.clone(),
        format!("{path}.d.ts"),
        join(&path, "index.d.ts"),
    ]
    .into_iter()
    .find(|candidate| archive.has(candidate))
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
        return !pattern_matches(archive, raw).is_empty();
    }
    normalize(raw).is_some_and(|path| archive.has(&path))
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
        for path in paths {
            if !target_exists(archive, path) {
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
