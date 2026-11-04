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
    path.ends_with(".node") || path == "binding.gyp" || path.ends_with("/binding.gyp")
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
                serde_json::Value::String(text) => references.push(text.clone()),
                serde_json::Value::Array(items) => pending.extend(items),
                serde_json::Value::Object(entries) => pending.extend(entries.values()),
                _ => {}
            }
        }
        Self(references)
    }

    /// Whether a script or entry point names `path`, with or without its
    /// extension.
    pub(super) fn name(&self, path: &str) -> bool {
        let stem = match (path.rfind('.'), path.rfind('/')) {
            (Some(dot), slash) if slash.is_none_or(|slash| dot > slash) => &path[..dot],
            _ => path,
        };
        self.0
            .iter()
            .any(|reference| reference.contains(path) || reference.contains(stem))
    }
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
}
