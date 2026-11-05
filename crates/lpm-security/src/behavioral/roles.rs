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

impl EntryReferences {
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
    reference.match_indices(directory).any(|(start, _)| {
        let before = &reference[..start];
        let before = before.strip_suffix("./").unwrap_or(before);
        let starts_path = before
            .chars()
            .next_back()
            .is_none_or(|character| !is_path_character(character));
        let ends_path = reference[start + directory.len()..]
            .chars()
            .next()
            .is_none_or(|character| character == '/' || !is_path_character(character));
        starts_path && ends_path
    })
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
}
