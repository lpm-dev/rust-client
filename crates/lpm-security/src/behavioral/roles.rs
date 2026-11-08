//! What a package file is for, as far as its behavioral tags go: a test, a
//! native addon, or a file the package's manifest runs or exports.
//!
//! These rules match lpm.dev's, so a tag the registry reports as found only
//! in tests is one a local scan reports the same way.

/// Directories whose files are tests, compared case-insensitively.
const TEST_DIRECTORIES: &[&str] = &[
    "test",
    "tests",
    "__tests__",
    "__test__",
    "spec",
    "specs",
    "__mocks__",
    "__fixtures__",
];

/// Scripts the package manager runs when the package is installed or removed.
const LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
];

/// Manifest fields whose paths a consumer's code or shell runs.
const ENTRY_FIELDS: &[&str] = &["main", "module", "browser", "bin", "exports"];

/// Whether a package-relative path is a test: under a test directory, named
/// `*.test.*` or `*.spec.*`, or a Python `test_*.py` or `*_test.py` file.
pub fn is_test_path(path: &str) -> bool {
    let (directories, name) = path.rsplit_once('/').unwrap_or(("", path));
    if directories.split('/').any(|segment| {
        TEST_DIRECTORIES
            .iter()
            .any(|directory| segment.eq_ignore_ascii_case(directory))
    }) {
        return true;
    }
    if let Some((stem, extension)) = name.rsplit_once('.')
        && !extension.is_empty()
        && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        let stem = stem.as_bytes();
        let marked = |marker: &[u8]| {
            stem.len() >= marker.len()
                && stem[stem.len() - marker.len()..].eq_ignore_ascii_case(marker)
        };
        if marked(b".test") || marked(b".spec") {
            return true;
        }
    }
    name.strip_suffix(".py").is_some_and(|stem| {
        stem.strip_prefix("test_")
            .is_some_and(|rest| !rest.is_empty())
            || stem.ends_with("_test")
    })
}

/// Whether a package file is native code: a compiled `.node` addon, or the
/// `binding.gyp` node-gyp builds one from on install.
pub fn is_native_artifact_path(path: &str) -> bool {
    is_native_artifact_name(path.rsplit('/').next().unwrap_or(path).as_bytes())
}

/// [`is_native_artifact_path`] by the file's name alone.
#[inline]
pub fn is_native_artifact_name(name: &[u8]) -> bool {
    name.ends_with(b".node") || name == b"binding.gyp"
}

/// The strings of a manifest's lifecycle scripts and entry points. A file one
/// of them names runs whatever its path says, so it's never only a test.
#[derive(Debug, Default)]
pub(super) struct EntryReferences(Vec<String>);

impl EntryReferences {
    pub(super) fn from_manifest(manifest: &serde_json::Value) -> Self {
        let mut references = Vec::new();
        let scripts = manifest.get("scripts");
        let mut pending: Vec<&serde_json::Value> = LIFECYCLE_SCRIPTS
            .iter()
            .filter_map(|name| scripts.and_then(|scripts| scripts.get(name)))
            .chain(ENTRY_FIELDS.iter().filter_map(|field| manifest.get(field)))
            .collect();
        while let Some(value) = pending.pop() {
            match value {
                serde_json::Value::String(text) => references.push(text.replace('\\', "/")),
                serde_json::Value::Array(items) => pending.extend(items),
                serde_json::Value::Object(entries) => pending.extend(entries.values()),
                _ => {}
            }
        }
        Self(references)
    }

    /// Whether a script or entry point names `path`, with or without its
    /// extension, or names the directory of an `index` file as Node resolves
    /// a directory to it.
    pub(super) fn name(&self, path: &str) -> bool {
        let (directory, name) = match path.rsplit_once('/') {
            Some((directory, name)) => (Some(directory), name),
            None => (None, path),
        };
        let stem = match name.rfind('.') {
            Some(dot) => &path[..path.len() - name.len() + dot],
            None => path,
        };
        let index_directory = directory.filter(|_| {
            name.rsplit_once('.')
                .map_or(name, |(stem, _)| stem)
                .eq("index")
        });
        self.0.iter().any(|reference| {
            reference.contains(path)
                || reference.contains(stem)
                || index_directory.is_some_and(|directory| names_directory(reference, directory))
        })
    }
}

/// How [`EntryReferences::names`] must find a path's needle in a reference.
#[derive(Clone, Copy)]
enum Needle {
    /// Anywhere: the path itself, or the path without its extension.
    Anywhere,
    /// As a whole path, by [`names_directory`]'s rule: the directory of an
    /// `index` file.
    WholeDirectory,
}

/// Matches [`EntryReferences::names`] reports before it gives up and names
/// every path, per byte of references and for any references. A match is a
/// needle ending at a position, so needles that are suffixes of each other
/// can match at every position; real manifests report a few per reference.
const MATCHES_PER_REFERENCE_BYTE: usize = 4;
const MATCHES_FLOOR: usize = 1 << 20;

impl EntryReferences {
    /// [`EntryReferences::name`] for each of `paths`, in one pass over the
    /// references. Asking `name` for every test file searched every
    /// reference once per file. If the references make the pass report
    /// more matches than they are allowed, every path is named: a named
    /// file counts as code the package runs, never as only a test.
    pub(super) fn names(&self, paths: &[&str]) -> Vec<bool> {
        let mut named = vec![false; paths.len()];
        if paths.is_empty() || self.0.is_empty() {
            return named;
        }
        let mut needles: Vec<&str> = Vec::new();
        let mut owners: Vec<Vec<(usize, Needle)>> = Vec::new();
        let mut index_of: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for (path_index, path) in paths.iter().enumerate() {
            let (directory, name) = match path.rsplit_once('/') {
                Some((directory, name)) => (Some(directory), name),
                None => (None, *path),
            };
            let stem = match name.rfind('.') {
                Some(dot) => &path[..path.len() - name.len() + dot],
                None => path,
            };
            let index_directory = directory.filter(|_| {
                name.rsplit_once('.')
                    .map_or(name, |(stem, _)| stem)
                    .eq("index")
            });
            let wanted = [
                Some((*path, Needle::Anywhere)),
                Some((stem, Needle::Anywhere)),
                index_directory.map(|directory| (directory, Needle::WholeDirectory)),
            ];
            for (needle, kind) in wanted.into_iter().flatten() {
                if needle.is_empty() {
                    match kind {
                        Needle::Anywhere => named[path_index] = true,
                        Needle::WholeDirectory => {
                            if self
                                .0
                                .iter()
                                .any(|reference| names_directory(reference, needle))
                            {
                                named[path_index] = true;
                            }
                        }
                    }
                    continue;
                }
                let slot = *index_of.entry(needle).or_insert_with(|| {
                    needles.push(needle);
                    owners.push(Vec::new());
                    needles.len() - 1
                });
                owners[slot].push((path_index, kind));
            }
        }
        if needles.is_empty() {
            return named;
        }
        let Ok(matcher) = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(&needles)
        else {
            return vec![true; paths.len()];
        };
        let reference_bytes: usize = self.0.iter().map(String::len).sum();
        let mut budget = reference_bytes
            .saturating_mul(MATCHES_PER_REFERENCE_BYTE)
            .max(MATCHES_FLOOR);
        let mut unnamed = named.iter().filter(|named| !**named).count();
        for reference in &self.0 {
            for found in matcher.find_overlapping_iter(reference) {
                if unnamed == 0 {
                    return named;
                }
                if budget == 0 {
                    return vec![true; paths.len()];
                }
                budget -= 1;
                let slot = found.pattern().as_usize();
                let mut whole_directory = None;
                for &(path_index, kind) in &owners[slot] {
                    if named[path_index] {
                        continue;
                    }
                    let matched = match kind {
                        Needle::Anywhere => true,
                        Needle::WholeDirectory => *whole_directory.get_or_insert_with(|| {
                            names_directory_at(reference, found.start(), found.end())
                        }),
                    };
                    if matched {
                        named[path_index] = true;
                        unnamed -= 1;
                    }
                }
            }
        }
        named
    }

    /// Whether a script or entry point mentions a path under `directory`.
    pub(super) fn mention_directory(&self, directory: &str) -> bool {
        self.0.iter().any(|reference| {
            reference
                .match_indices(directory)
                .any(|(start, _)| reference[start + directory.len()..].starts_with('/'))
        })
    }
}

/// Whether `reference` names `directory` as a whole path, optionally after
/// `./`: the path starts the reference or follows a character that can't be
/// part of a path in a script, and ends the reference or is followed by `/`
/// or such a character.
fn names_directory(reference: &str, directory: &str) -> bool {
    reference
        .match_indices(directory)
        .any(|(start, _)| names_directory_at(reference, start, start + directory.len()))
}

/// Whether the occurrence at `start..end` of a directory in `reference` is
/// a whole path, by [`names_directory`]'s rule.
fn names_directory_at(reference: &str, start: usize, end: usize) -> bool {
    let before = &reference[..start];
    let before = before.strip_suffix("./").unwrap_or(before);
    let starts_path = before
        .chars()
        .next_back()
        .is_none_or(|character| !is_path_character(character));
    let ends_path = reference[end..]
        .chars()
        .next()
        .is_none_or(|character| character == '/' || !is_path_character(character));
    starts_path && ends_path
}

fn is_path_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '/' | '.' | '-' | '_' | '@' | '+' | '~')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_test_files_by_their_directory_or_name() {
        for path in [
            "test/a.js",
            "src/tests/b.ts",
            "lib/__tests__/c.js",
            "__mocks__/d.js",
            "Tests/KitTests/KitTests.swift",
            "src/e.test.ts",
            "src/f.spec.mjs",
            "src/G.Test.JS",
            "pkg/test_g.py",
            "pkg/h_test.py",
        ] {
            assert!(is_test_path(path), "{path}");
        }
        for path in [
            "dist/index.js",
            "src/testing-library.js",
            "lib/contest.js",
            "examples/jsm/loaders/GLTFLoader.js",
            "src/latest.ts",
            "test.js",
            "pkg/test_.py",
            "src/e.test.d-ts",
        ] {
            assert!(!is_test_path(path), "{path}");
        }
    }

    #[test]
    fn native_artifacts_are_node_addons_and_binding_gyp() {
        for path in [
            "build/Release/addon.node",
            "addon.node",
            "binding.gyp",
            "native/binding.gyp",
        ] {
            assert!(is_native_artifact_path(path), "{path}");
        }
        for path in [
            "server.node.js",
            "my-binding.gyp",
            "binding.gyp.bak",
            "node",
        ] {
            assert!(!is_native_artifact_path(path), "{path}");
        }
    }

    #[test]
    fn entry_references_cover_lifecycle_scripts_and_entry_points() {
        let manifest = serde_json::json!({
            "main": "./tests/main.js",
            "bin": { "kit": "spec/cli.js" },
            "exports": { ".": { "import": ["./__mocks__/esm.mjs"] } },
            "scripts": { "postinstall": "node test/setup", "test": "node test/other.js" },
        });
        let references = EntryReferences::from_manifest(&manifest);

        for path in [
            "tests/main.js",
            "spec/cli.js",
            "__mocks__/esm.mjs",
            "test/setup.js",
        ] {
            assert!(references.name(path), "{path}");
        }
        assert!(!references.name("test/other.js"));
        assert!(!EntryReferences::default().name("test/setup.js"));
    }

    #[test]
    fn entry_references_name_the_index_of_a_directory_and_windows_style_paths() {
        let manifest = serde_json::json!({
            "main": "./spec",
            "bin": "tests\\cli.js",
            "module": "lib/specs/",
        });
        let references = EntryReferences::from_manifest(&manifest);

        for path in [
            "spec/index.js",
            "spec/index.mjs",
            "tests/cli.js",
            "lib/specs/index.ts",
        ] {
            assert!(references.name(path), "{path}");
        }
        for path in ["spec/helper.js", "specs/index.js", "lib/spec/index.js"] {
            assert!(!references.name(path), "{path}");
        }
    }

    #[test]
    fn naming_paths_together_answers_what_naming_each_answers() {
        struct Rng(u64);
        impl Rng {
            fn below(&mut self, n: usize) -> usize {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                (self.0 % n as u64) as usize
            }
        }
        const SEGMENTS: &[&str] = &[
            "test",
            "lib",
            "src",
            "index",
            "a",
            "b.js",
            "index.js",
            "index.mjs",
            ".js",
            "é",
            "x-y",
            "",
        ];
        const GLUE: &[&str] = &[
            "", "./", " ", "/", ".", "node ", " && ", "@", "+", "~", "\"\"", ":", "-", "é",
        ];
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        let piece = |rng: &mut Rng, parts: usize| {
            let mut text = String::new();
            for part in 0..parts {
                if part > 0 && rng.below(3) == 0 {
                    text.push('/');
                }
                text.push_str(GLUE[rng.below(GLUE.len())]);
                text.push_str(SEGMENTS[rng.below(SEGMENTS.len())]);
            }
            text
        };
        for _ in 0..3_000 {
            let references: Vec<String> = (0..rng.below(4))
                .map(|_| {
                    let parts = 1 + rng.below(6);
                    piece(&mut rng, parts)
                })
                .collect();
            let references = EntryReferences(references);
            let paths: Vec<String> = (0..1 + rng.below(6))
                .map(|_| {
                    let parts = 1 + rng.below(4);
                    piece(&mut rng, parts).replace(' ', "")
                })
                .collect();
            let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
            let each: Vec<bool> = paths.iter().map(|path| references.name(path)).collect();
            assert_eq!(
                references.names(&paths),
                each,
                "{:?} {paths:?}",
                references.0
            );
        }
        for (references, paths) in [
            (vec![], vec!["test/a.js"]),
            (vec!["lib"], vec!["/index.js", ".js", "", "lib/index.js"]),
            (
                vec!["./lib/x", "node lib"],
                vec!["lib/index.js", "lib/index.mjs"],
            ),
            (vec!["mylib/x"], vec!["lib/index.js"]),
            (
                vec!["test/a"],
                vec!["test/a.js", "test/a.js", "test/a.spec.js"],
            ),
        ] {
            let references = EntryReferences(references.into_iter().map(String::from).collect());
            let each: Vec<bool> = paths.iter().map(|path| references.name(path)).collect();
            assert_eq!(
                references.names(&paths),
                each,
                "{:?} {paths:?}",
                references.0
            );
        }
    }

    #[test]
    fn references_that_report_too_many_matches_name_every_path() {
        // Paths that are suffixes of each other all match at every
        // position of a reference made of them: 200 of them in 40,000
        // bytes report about 4 million matches.
        let mut paths: Vec<String> = (1..=200).map(|depth| vec!["a"; depth].join("/")).collect();
        paths.push("zzz/q.js".to_owned());
        let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
        let references = EntryReferences(vec!["a/".repeat(20_000)]);
        assert!(!references.name("zzz/q.js"));
        assert_eq!(references.names(&paths), vec![true; paths.len()]);
    }
}
