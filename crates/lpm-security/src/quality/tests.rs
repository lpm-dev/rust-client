use super::*;
use serde_json::json;

fn report_with(
    ecosystem: QualityEcosystem,
    files: &[(&str, &[u8])],
    swift_manifest: Option<&Value>,
) -> QualityReport {
    let mut collector = QualityCollector::new(ecosystem);
    let mut package_json = None;
    for (path, content) in files {
        if *path == "package.json" {
            package_json = Some(content.to_vec());
        }
        if let Some(limit) = collector.note_file(path, content.len() as u64) {
            let end = usize::try_from(limit).unwrap().min(content.len());
            collector.add_content(path, &content[..end]);
        }
    }
    collector.finish(package_json.as_deref(), swift_manifest)
}

fn js_report(files: &[(&str, &str)]) -> QualityReport {
    let files: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(path, text)| (*path, text.as_bytes()))
        .collect();
    report_with(QualityEcosystem::Js, &files, None)
}

fn check<'r>(report: &'r QualityReport, id: &str) -> &'r CheckResult {
    report
        .checks
        .iter()
        .find(|check| check.id == id)
        .unwrap_or_else(|| {
            panic!(
                "no {id} in {:?}",
                report.checks.iter().map(|c| c.id).collect::<Vec<_>>()
            )
        })
}

fn points(report: &QualityReport, id: &str) -> u32 {
    check(report, id).points
}

const PROSE: &str = "Markdown parses CommonMark and GitHub Flavored Markdown into sanitized HTML. It keeps the output safe to render in a browser by default, removes dangerous URLs, supports custom renderers for every node, and streams large documents without holding the whole tree in memory. It runs in Node.js and every modern browser, and ships its own type declarations.";

fn good_readme() -> String {
    format!(
        "# Markdown\n\n{PROSE}\n\n## Install\n\n```sh\nlpm install @lpm.dev/acme.md\n```\n\n## Usage\n\n```ts\nimport {{ parse, render }} from '@lpm.dev/acme.md'\n\nrender(parse('# hi'))\n```\n"
    )
}

fn good_manifest() -> Value {
    json!({
        "name": "@lpm.dev/acme.md",
        "version": "1.2.3",
        "description": "Parses Markdown into sanitized HTML",
        "keywords": ["markdown"],
        "license": "MIT",
        "repository": { "type": "git", "url": "git+https://github.com/acme/md.git" },
        "type": "module",
        "sideEffects": false,
        "engines": { "node": ">=20" },
        "main": "./dist/index.cjs",
        "types": "./dist/index.d.ts",
        "exports": {
            ".": {
                "types": "./dist/index.d.ts",
                "import": "./dist/index.mjs",
                "require": "./dist/index.cjs",
                "default": "./dist/index.mjs"
            },
            "./package.json": "./package.json"
        }
    })
}

const DOCUMENTED_DTS: &str = "/** Parses Markdown source into a syntax tree. */\nexport declare function parse(source: string): Root;\n/** Renders a syntax tree into sanitized HTML. */\nexport declare function render(tree: Root): string;\n/** The root node of a parsed Markdown document. */\nexport interface Root { children: unknown[] }\n";

fn good_package(manifest: &Value) -> Vec<(&'static str, String)> {
    vec![
        ("package.json", manifest.to_string()),
        ("README.md", good_readme()),
        (
            "CHANGELOG.md",
            "# Changelog\n\n## 1.2.3\n\n- Faster.\n".to_string(),
        ),
        ("LICENSE", "MIT License".to_string()),
        (
            "dist/index.mjs",
            "export function parse(s) { return s }\nexport function render(t) { return t }\n"
                .to_string(),
        ),
        (
            "dist/index.cjs",
            "exports.parse = s => s\nexports.render = t => t\n".to_string(),
        ),
        ("dist/index.d.ts", DOCUMENTED_DTS.to_string()),
    ]
}

fn report_of(files: &[(&'static str, String)]) -> QualityReport {
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, text)| (*path, text.as_str()))
        .collect();
    js_report(&borrowed)
}

fn replace(
    files: &mut Vec<(&'static str, String)>,
    path: &'static str,
    content: impl Into<String>,
) {
    files.retain(|(existing, _)| *existing != path);
    files.push((path, content.into()));
}

#[test]
fn a_well_made_javascript_package_earns_every_archive_point() {
    let report = report_of(&good_package(&good_manifest()));
    for result in &report.checks {
        assert_eq!(
            result.status,
            CheckStatus::Passed,
            "{}: {}",
            result.id,
            result.detail
        );
    }
    let registry: u32 = spec::checks(QualityEcosystem::Js)
        .filter(|spec| spec.decider == Decider::Registry)
        .map(|spec| spec.max_points)
        .sum();
    assert_eq!(report.archive_points(), (100 - registry, 100 - registry));
    assert_eq!(report.ecosystem, QualityEcosystem::Js);
    assert_eq!(report.rules_version, QUALITY_RULES_VERSION);
}

#[test]
fn the_report_lists_only_archive_checks_in_spec_order() {
    let report = report_of(&good_package(&good_manifest()));
    let expected: Vec<&str> = spec::checks(QualityEcosystem::Js)
        .filter(|spec| spec.decider == Decider::Archive)
        .map(|spec| spec.id)
        .collect();
    let ids: Vec<&str> = report.checks.iter().map(|check| check.id).collect();
    assert_eq!(ids, expected);
}

#[test]
fn a_readme_short_on_prose_fails_however_much_code_it_has() {
    let mut files = good_package(&good_manifest());
    let code = "```js\nconsole.log(1)\n```\n".repeat(50);
    replace(
        &mut files,
        "README.md",
        format!("# Short\n\nTiny.\n\n{code}"),
    );
    let report = report_of(&files);
    assert_eq!(points(&report, "readme"), 0);
    assert!(
        check(&report, "readme")
            .detail
            .contains("characters of prose")
    );
}

#[test]
fn an_example_importing_a_name_the_package_does_not_export_earns_two_points() {
    let mut files = good_package(&good_manifest());
    replace(
        &mut files,
        "README.md",
        good_readme().replace("{ parse, render }", "{ parse, compile }"),
    );
    let report = report_of(&files);
    assert_eq!(points(&report, "readme-example"), 2);
    assert!(check(&report, "readme-example").detail.contains("compile"));
}

#[test]
fn an_example_importing_another_package_earns_nothing() {
    let mut files = good_package(&good_manifest());
    replace(
        &mut files,
        "README.md",
        good_readme().replace(
            "'@lpm.dev/acme.md'\n\nrender",
            "'@lpm.dev/acme.mdx'\n\nrender",
        ),
    );
    assert_eq!(points(&report_of(&files), "readme-example"), 0);
}

#[test]
fn api_docs_count_exports_reached_through_reexports_once() {
    let mut files = good_package(&good_manifest());
    replace(
        &mut files,
        "dist/index.d.ts",
        "export * from './parse.js';\nexport { render as toHtml } from './render.js';\nexport { render } from './render.js';\n",
    );
    files.push((
        "dist/parse.d.ts",
        "/** Parses Markdown source into a syntax tree. */\nexport declare function parse(s: string): unknown;\nexport declare const version: string;\n".to_string(),
    ));
    files.push((
        "dist/render.d.ts",
        "/** Renders a syntax tree into sanitized HTML. */\nexport declare function render(t: unknown): string;\n".to_string(),
    ));
    let report = report_of(&files);
    let api = check(&report, "api-docs");
    assert_eq!(
        api.detail,
        "2 of 3 exports in the type declarations have doc comments (66%)"
    );
    assert_eq!(api.points, 6);
}

#[test]
fn api_docs_fall_back_to_the_esm_entry_without_declarations() {
    let mut manifest = good_manifest();
    manifest["exports"] =
        json!({ ".": { "import": "./dist/index.mjs", "require": "./dist/index.cjs" } });
    manifest.as_object_mut().unwrap().remove("types");
    let mut files = good_package(&manifest);
    files.retain(|(path, _)| *path != "dist/index.d.ts");
    replace(
        &mut files,
        "dist/index.mjs",
        "/** Parses Markdown source into a syntax tree. */\nexport function parse(s) { return s }\nexport function render(t) { return t }\n",
    );
    let report = report_of(&files);
    assert!(check(&report, "api-docs").detail.contains("ESM entry"));
    assert_eq!(points(&report, "api-docs"), 6);
    assert_eq!(points(&report, "types"), 0);
}

#[test]
fn types_for_import_but_not_require_earn_half() {
    let mut manifest = good_manifest();
    manifest["exports"] = json!({
        ".": {
            "import": { "types": "./dist/index.d.ts", "default": "./dist/index.mjs" },
            "require": "./dist/index.cjs"
        }
    });
    let report = report_of(&good_package(&manifest));
    assert_eq!(points(&report, "types"), 5);
    assert!(check(&report, "types").detail.contains(". (require)"));
}

#[test]
fn sibling_declarations_must_match_the_module_format() {
    let mut manifest = good_manifest();
    manifest["exports"] =
        json!({ ".": { "import": "./dist/index.mjs", "require": "./dist/index.cjs" } });
    let mut files = good_package(&manifest);
    files.push(("dist/index.d.mts", DOCUMENTED_DTS.to_string()));
    let report = report_of(&files);
    // index.d.ts sits beside neither index.mjs nor index.cjs by format.
    assert_eq!(points(&report, "types"), 5);
    files.push(("dist/index.d.cts", DOCUMENTED_DTS.to_string()));
    assert_eq!(points(&report_of(&files), "types"), 10);
}

#[test]
fn esm_needs_module_syntax_that_node_loads_as_esm() {
    let mut manifest = good_manifest();
    manifest["type"] = json!("commonjs");
    manifest["exports"]["."]["import"] = json!("./dist/index.js");
    let mut files = good_package(&manifest);
    files.push(("dist/index.js", "export const a = 1\n".to_string()));
    let report = report_of(&files);
    assert_eq!(points(&report, "esm"), 0);
    assert!(check(&report, "esm").detail.contains("CommonJS"));

    manifest.as_object_mut().unwrap().remove("type");
    let mut files = good_package(&manifest);
    files.push(("dist/index.js", "export const a = 1\n".to_string()));
    assert_eq!(
        points(&report_of(&files), "esm"),
        4,
        "Node.js detects ESM syntax without a type"
    );

    let mut files = good_package(&manifest);
    files.push(("dist/index.js", "module.exports = 1\n".to_string()));
    assert_eq!(points(&report_of(&files), "esm"), 0);
}

#[test]
fn exports_map_requires_types_first_and_default_last() {
    let mut manifest = good_manifest();
    manifest["exports"] = json!({
        ".": { "import": "./dist/index.mjs", "types": "./dist/index.d.ts", "default": "./dist/index.mjs" }
    });
    let report = report_of(&good_package(&manifest));
    assert_eq!(points(&report, "exports-map"), 0);
    assert!(
        check(&report, "exports-map")
            .detail
            .contains("\"types\" first")
    );
}

#[test]
fn missing_entry_paths_fail_entry_points_and_exports_map() {
    let mut manifest = good_manifest();
    manifest["bin"] = json!({ "md": "./bin/md.js" });
    manifest["exports"]["./extra"] = json!("./dist/extra.mjs");
    let report = report_of(&good_package(&manifest));
    assert_eq!(points(&report, "entry-points"), 0);
    assert!(
        check(&report, "entry-points")
            .detail
            .contains("bin ./bin/md.js")
    );
    assert_eq!(points(&report, "exports-map"), 0);
}

#[test]
fn install_scripts_and_a_root_binding_gyp_fail() {
    let mut manifest = good_manifest();
    manifest["scripts"] = json!({ "postinstall": "node setup.js", "test": "vitest" });
    let report = report_of(&good_package(&manifest));
    assert_eq!(
        check(&report, "no-install-scripts").detail,
        "package.json runs postinstall at install"
    );

    let mut files = good_package(&good_manifest());
    files.push(("binding.gyp", "{}".to_string()));
    let report = report_of(&files);
    assert!(
        check(&report, "no-install-scripts")
            .detail
            .contains("node-gyp")
    );
}

#[test]
fn clean_archive_allows_env_templates_and_bundled_dependencies_only() {
    let mut files = good_package(&good_manifest());
    files.push((".env.example", "KEY=".to_string()));
    assert_eq!(points(&report_of(&files), "clean-archive"), 6);

    files.push(("config/.env.local", "KEY=secret".to_string()));
    let report = report_of(&files);
    assert_eq!(points(&report, "clean-archive"), 0);
    assert!(
        check(&report, "clean-archive")
            .detail
            .contains(".env.local")
    );

    let mut manifest = good_manifest();
    manifest["bundleDependencies"] = json!(["vendored"]);
    let mut files = good_package(&manifest);
    files.push(("node_modules/vendored/index.js", "".to_string()));
    assert_eq!(points(&report_of(&files), "clean-archive"), 6);
    files.push(("node_modules/@scope/other/index.js", "".to_string()));
    let report = report_of(&files);
    assert!(
        check(&report, "clean-archive")
            .detail
            .contains("node_modules/@scope/other")
    );
}

#[test]
fn clean_archive_fails_at_ten_megabytes_unpacked() {
    let mut files = good_package(&good_manifest());
    files.push(("assets/big.bin", "x".repeat(10_000_000)));
    let report = report_of(&files);
    assert_eq!(points(&report, "clean-archive"), 0);
    assert!(
        check(&report, "clean-archive")
            .detail
            .contains("over 10 MB")
    );
}

#[test]
fn license_rules_follow_spdx_and_npm() {
    let license = |value: Value, extra: Option<(&'static str, &str)>| {
        let mut manifest = good_manifest();
        manifest["license"] = value;
        let mut files = good_package(&manifest);
        if let Some((path, text)) = extra {
            files.push((path, text.to_string()));
        }
        let report = report_of(&files);
        (
            points(&report, "license"),
            check(&report, "license").detail.clone(),
        )
    };
    assert_eq!(license(json!("MIT OR Apache-2.0"), None).0, 5);
    assert_eq!(license(json!("LicenseRef-Acme-Commercial"), None).0, 5);
    assert_eq!(
        license(
            json!("SEE LICENSE IN TERMS.md"),
            Some(("TERMS.md", "terms"))
        )
        .0,
        5
    );
    assert!(
        license(json!("SEE LICENSE IN TERMS.md"), None)
            .1
            .contains("doesn't contain")
    );
    let (points, detail) = license(json!("UNLICENSED"), None);
    assert_eq!(points, 0);
    assert!(detail.contains("SEE LICENSE IN"));
    assert!(license(json!("GPL-2.0"), None).1.contains("deprecated"));
    assert_eq!(license(json!("mit"), None).0, 0);
}

#[test]
fn a_changelog_must_name_this_exact_version() {
    let mut files = good_package(&good_manifest());
    replace(&mut files, "CHANGELOG.md", "## 1.2.30\n## 11.2.3\n");
    assert_eq!(points(&report_of(&files), "changelog"), 0);
    replace(&mut files, "CHANGELOG.md", "## v1.2.3 - 2026-11-01\n");
    assert_eq!(points(&report_of(&files), "changelog"), 3);
    replace(&mut files, "CHANGELOG.md", "Released 1.2.3.\n");
    assert_eq!(points(&report_of(&files), "changelog"), 3);
}

#[test]
fn a_description_that_repeats_the_name_fails() {
    let mut manifest = good_manifest();
    manifest["description"] = json!("MD");
    assert_eq!(
        points(&report_of(&good_package(&manifest)), "description"),
        0
    );
    manifest["description"] = json!("acme.md acme.md acme.md");
    let report = report_of(&good_package(&manifest));
    assert_eq!(
        points(&report, "description"),
        2,
        "{}",
        check(&report, "description").detail
    );
}

#[test]
fn repository_urls_npm_understands_pass() {
    for url in [
        "github:acme/md",
        "acme/md",
        "git@github.com:acme/md.git",
        "git+ssh://git@github.com/acme/md.git",
        "https://gitlab.com/acme/md",
    ] {
        assert!(parse_repository(url), "{url}");
    }
    for url in [
        "md",
        "https://github.com",
        "ftp://example.com/x",
        "github:acme",
    ] {
        assert!(!parse_repository(url), "{url}");
    }
}

#[test]
fn without_package_json_every_manifest_check_fails() {
    let report = js_report(&[("README.md", &good_readme()), ("index.js", "export {}")]);
    assert!(
        report
            .checks
            .iter()
            .all(|check| check.status != CheckStatus::Pending)
    );
    assert_eq!(points(&report, "readme"), 6);
    assert_eq!(points(&report, "types"), 0);
    assert!(check(&report, "engines").detail.contains("package.json"));
}

#[test]
fn a_readme_that_is_not_utf8_counts_as_unreadable() {
    let manifest = good_manifest().to_string();
    let report = report_with(
        QualityEcosystem::Js,
        &[
            ("package.json", manifest.as_bytes()),
            ("README.md", &[0x23, 0x20, 0xff, 0xfe]),
        ],
        None,
    );
    assert!(check(&report, "readme").detail.contains("isn't UTF-8"));
}

#[test]
fn a_readme_that_is_not_utf8_gives_way_to_the_next_ranked_readme() {
    let manifest = good_manifest().to_string();
    let readme = good_readme();
    for files in [
        [
            ("README.md", [0x23, 0x20, 0xff, 0xfe].as_slice()),
            ("README.txt", readme.as_bytes()),
        ],
        [
            ("README.txt", readme.as_bytes()),
            ("README.md", [0x23, 0x20, 0xff, 0xfe].as_slice()),
        ],
    ] {
        let mut all: Vec<(&str, &[u8])> = vec![("package.json", manifest.as_bytes())];
        all.extend(files);
        let report = report_with(QualityEcosystem::Js, &all, None);
        assert_eq!(
            check(&report, "readme").points,
            6,
            "{}",
            check(&report, "readme").detail
        );
        assert!(check(&report, "readme").detail.starts_with("README.txt"));
    }
}

#[test]
fn the_best_ranked_readme_wins_in_any_order() {
    let mut files = good_package(&good_manifest());
    files.retain(|(path, _)| *path != "README.md");
    files.insert(0, ("README.txt", "short".to_string()));
    files.push(("README.md", good_readme()));
    files.push(("README", "short".to_string()));
    assert_eq!(points(&report_of(&files), "readme"), 6);
}

#[test]
fn of_two_readmes_of_the_same_rank_the_first_in_path_order_wins() {
    let manifest = good_manifest().to_string();
    let readme = good_readme();
    for files in [
        [
            ("README.rst", "short".as_bytes()),
            ("README.html", readme.as_bytes()),
        ],
        [
            ("README.html", readme.as_bytes()),
            ("README.rst", "short".as_bytes()),
        ],
    ] {
        let mut all: Vec<(&str, &[u8])> = vec![("package.json", manifest.as_bytes())];
        all.extend(files);
        let report = report_with(QualityEcosystem::Js, &all, None);
        assert!(
            check(&report, "readme").detail.starts_with("README.html"),
            "{}",
            check(&report, "readme").detail
        );
    }
}

#[test]
fn a_readme_past_the_published_limit_is_cut_before_a_split_character() {
    assert_eq!(MAX_README_BYTES, 1_000_000);
    let manifest = good_manifest().to_string();
    let mut long = good_readme().into_bytes();
    long.resize(MAX_README_BYTES - 1, b' ');
    long.extend_from_slice("é and more".as_bytes());
    let report = report_with(
        QualityEcosystem::Js,
        &[("package.json", manifest.as_bytes()), ("README.md", &long)],
        None,
    );
    assert_eq!(
        points(&report, "readme"),
        6,
        "{}",
        check(&report, "readme").detail
    );

    let mut invalid = good_readme().into_bytes();
    invalid.resize(MAX_README_BYTES - 1, b' ');
    invalid.extend_from_slice(&[0xff, b'a', b'b']);
    let report = report_with(
        QualityEcosystem::Js,
        &[
            ("package.json", manifest.as_bytes()),
            ("README.md", &invalid),
        ],
        None,
    );
    assert!(check(&report, "readme").detail.contains("isn't UTF-8"));
}

#[test]
fn a_readme_within_the_limit_that_ends_inside_a_character_is_not_utf8() {
    let manifest = good_manifest().to_string();
    let mut readme = good_readme().into_bytes();
    readme.extend_from_slice(&[0xe2, 0x82]);
    let report = report_with(
        QualityEcosystem::Js,
        &[
            ("package.json", manifest.as_bytes()),
            ("README.md", &readme),
        ],
        None,
    );
    assert!(check(&report, "readme").detail.contains("isn't UTF-8"));
}

#[test]
fn readme_rank_matches_the_published_order() {
    assert_eq!(readme_rank("README.md"), Some(0));
    assert_eq!(readme_rank("readme"), Some(1));
    assert_eq!(readme_rank("Readme.TXT"), Some(2));
    assert_eq!(readme_rank("README.markdown"), Some(3));
    assert_eq!(readme_rank("README.rst"), Some(4));
    assert_eq!(readme_rank("README.md~"), None);
    assert_eq!(readme_rank("docs/README.md"), None);
    assert_eq!(readme_rank("README."), None);
}

fn swift_manifest() -> Value {
    json!({
        "toolsVersion": { "_version": "6.0.0" },
        "platforms": [
            { "platformName": "macos", "version": "13.0", "options": [] },
            { "platformName": "ios", "version": "16.0", "options": [] }
        ],
        "swiftLanguageVersions": null,
        "products": [{ "name": "Lib", "type": { "library": ["automatic"] }, "targets": ["Lib"] }],
        "targets": [
            { "name": "Lib", "type": "regular", "path": null, "settings": [] },
            { "name": "LibTests", "type": "test", "path": null, "settings": [] }
        ],
        "dependencies": []
    })
}

fn swift_files() -> Vec<(&'static str, String)> {
    vec![
        (
            "package.json",
            json!({
                "name": "@lpm.dev/acme.lib",
                "version": "2.0.0",
                "description": "Renders Markdown into attributed strings",
                "keywords": ["markdown"],
                "license": "MIT",
                "repository": "github:acme/lib"
            })
            .to_string(),
        ),
        (
            "README.md",
            format!(
                "# Lib\n\n{PROSE}\n\n```swift\n.package(id: \"lpmdev.acme_lib\", from: \"2.0.0\")\n```\n\n```swift\nimport Lib\n\nlet text = Renderer().render(\"# hi\")\n```\n"
            ),
        ),
        ("CHANGELOG.md", "## 2.0.0\n".to_string()),
        ("LICENSE", "MIT".to_string()),
        ("Package.swift", "// swift-tools-version: 6.0\n".to_string()),
        (
            "Sources/Lib/Renderer.swift",
            "/// Renders Markdown source into an attributed string.\npublic struct Renderer {\n    /// Creates a renderer with the default styles.\n    public init() {}\n    /// Renders the Markdown text into an attributed string.\n    public func render(_ text: String) -> String { text }\n}\n".to_string(),
        ),
        (
            "Tests/LibTests/RendererTests.swift",
            "import XCTest\n@testable import Lib\nfinal class RendererTests: XCTestCase {\n    public func testRender() {}\n}\n".to_string(),
        ),
    ]
}

fn swift_report(files: &[(&'static str, String)], manifest: Option<&Value>) -> QualityReport {
    let files: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(path, text)| (*path, text.as_bytes()))
        .collect();
    report_with(QualityEcosystem::Swift, &files, manifest)
}

#[test]
fn a_well_made_swift_package_earns_every_archive_point() {
    let manifest = swift_manifest();
    let report = swift_report(&swift_files(), Some(&manifest));
    for result in &report.checks {
        assert_eq!(
            result.status,
            CheckStatus::Passed,
            "{}: {}",
            result.id,
            result.detail
        );
    }
    assert_eq!(
        check(&report, "api-docs").detail,
        "3 of 3 public declarations have doc comments (100%)"
    );
}

#[test]
fn a_public_member_of_an_extension_of_an_internal_type_is_no_public_api() {
    let mut files = swift_files();
    files.push((
        "Sources/Lib/Internal.swift",
        "struct Cache {}\nextension Cache {\n    /// Clears every entry the cache holds right now.\n    public func clear() {}\n}\nextension String {\n    /// Joins this string and another with a space between.\n    public func joined(_ other: String) -> String { self + other }\n}\n"
            .to_string(),
    ));
    let report = swift_report(&files, Some(&swift_manifest()));
    assert_eq!(
        check(&report, "api-docs").detail,
        "4 of 4 public declarations have doc comments (100%)"
    );
}

#[test]
fn swift_manifest_checks_wait_for_the_evaluated_manifest() {
    let report = swift_report(&swift_files(), None);
    for id in [
        "readme-example",
        "platforms",
        "swift-6",
        "versioned-deps",
        "no-unsafe-flags",
        "has-tests",
        "lean-deps",
    ] {
        assert_eq!(check(&report, id).status, CheckStatus::Pending, "{id}");
    }
    assert_eq!(check(&report, "public-api").status, CheckStatus::Passed);
}

#[test]
fn swift_5_mode_targets_and_unversioned_dependencies_cost_points() {
    let mut manifest = swift_manifest();
    manifest["targets"][0]["settings"] = json!([
        { "tool": "swift", "kind": { "swiftLanguageMode": { "_0": "5" } } },
        { "tool": "swift", "kind": { "unsafeFlags": { "_0": ["-Onone"] } } }
    ]);
    manifest["dependencies"] = json!([
        { "sourceControl": [{ "identity": "swift-log", "requirement": { "range": [{ "lowerBound": "1.5.0", "upperBound": "2.0.0" }] } }] },
        { "sourceControl": [{ "identity": "swift-nio", "requirement": { "branch": ["main"] } }] }
    ]);
    let report = swift_report(&swift_files(), Some(&manifest));
    assert_eq!(points(&report, "swift-6"), 3);
    assert_eq!(points(&report, "versioned-deps"), 0);
    assert!(
        check(&report, "versioned-deps")
            .detail
            .contains("swift-nio")
    );
    assert_eq!(points(&report, "no-unsafe-flags"), 0);
    assert_eq!(points(&report, "lean-deps"), 5);
}

#[test]
fn a_test_target_without_test_declarations_fails_has_tests() {
    let mut files = swift_files();
    replace(
        &mut files,
        "Tests/LibTests/RendererTests.swift",
        "import XCTest\n// XCTestCase\n",
    );
    assert_eq!(
        points(&swift_report(&files, Some(&swift_manifest())), "has-tests"),
        0
    );
}

#[test]
fn a_swift_example_must_use_the_modules_public_api_for_all_five_points() {
    let mut files = swift_files();
    let readme = files
        .iter()
        .find(|(path, _)| *path == "README.md")
        .unwrap()
        .1
        .clone();
    replace(
        &mut files,
        "README.md",
        readme.replace("Renderer().render", "Lib.Missing().render"),
    );
    let report = swift_report(&files, Some(&swift_manifest()));
    assert_eq!(points(&report, "readme-example"), 2);
    assert!(
        check(&report, "readme-example")
            .detail
            .contains("Lib.Missing")
    );
}

#[test]
fn swift_clean_archive_rejects_build_output() {
    let mut files = swift_files();
    files.push((".build/debug/Lib.o", String::new()));
    let report = swift_report(&files, Some(&swift_manifest()));
    assert_eq!(
        check(&report, "clean-archive").detail,
        "The package contains .build"
    );
}

#[test]
fn quality_reports_serialize_with_camel_case_fields() {
    let report = report_of(&good_package(&good_manifest()));
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["schemaVersion"], json!(QUALITY_SCHEMA_VERSION));
    assert_eq!(value["ecosystem"], json!("js"));
    assert_eq!(value["checks"][0]["maxPoints"], json!(6));
    assert_eq!(value["checks"][0]["category"], json!("documentation"));
    assert_eq!(value["checks"][0]["status"], json!("passed"));
    assert_eq!(value["facts"]["repository"], json!("github.com/acme/md"));
}

#[test]
fn repeated_changelog_entries_keep_bounded_memory() {
    let mut collector = QualityCollector::new(QualityEcosystem::Js);
    let chunk = vec![b'x'; 1024 * 1024];
    let mut read = 0u64;
    for _ in 0..64 {
        if let Some(limit) = collector.note_file("CHANGELOG.md", chunk.len() as u64) {
            read += limit;
            collector.add_content("CHANGELOG.md", &chunk[..usize::try_from(limit).unwrap()]);
        }
    }
    assert!(read <= MAX_CHANGELOGS_BYTES);
    assert_eq!(collector.changelogs.len(), 1);
}

#[test]
fn lean_install_counts_direct_dependencies_required_peers_and_optionals_once() {
    let mut manifest = good_manifest();
    manifest["dependencies"] = json!({ "a": "^1", "b": "^1" });
    manifest["optionalDependencies"] = json!({ "b": "^1", "c": "^1" });
    manifest["peerDependencies"] = json!({ "react": "^19", "vue": "^3" });
    manifest["peerDependenciesMeta"] = json!({ "vue": { "optional": true } });
    let report = report_of(&good_package(&manifest));
    assert_eq!(
        check(&report, "lean-install").detail,
        "4 direct dependencies"
    );
    assert_eq!(points(&report, "lean-install"), 4);
}

#[test]
fn the_repository_fact_names_host_owner_and_repository() {
    for (repository, expected) in [
        (json!("github:Acme/MD"), Some("github.com/acme/md")),
        (json!("acme/md"), Some("github.com/acme/md")),
        (
            json!("git@gitlab.com:acme/md.git"),
            Some("gitlab.com/acme/md"),
        ),
        (
            json!({ "type": "git", "url": "git+https://www.github.com/acme/md.git" }),
            Some("github.com/acme/md"),
        ),
        (
            json!("https://github.com/acme/md/tree/main/packages/x"),
            Some("github.com/acme/md"),
        ),
        (json!("gist:11081aaa281"), None),
        (json!("not a url"), None),
        (json!("git@git_host:acme/md.git"), None),
        (json!("git@github.com:acme corp/md.git"), None),
        (json!("git@github.com:acme/\u{feff}md"), None),
        (json!("github:acme/m\u{e9}"), None),
        (json!("https://github.com/acme/m%20d"), None),
        (json!("github:acme/.."), None),
        (
            json!("github:acme/my_lib.js-2"),
            Some("github.com/acme/my_lib.js-2"),
        ),
        (json!(format!("github:acme/{}", "m".repeat(300))), None),
    ] {
        let mut manifest = good_manifest();
        manifest["repository"] = repository.clone();
        let report = report_of(&good_package(&manifest));
        assert_eq!(report.facts.repository.as_deref(), expected, "{repository}");
    }
}

#[test]
fn a_root_file_with_a_multibyte_name_is_not_a_license_and_does_not_panic() {
    let mut files = good_package(&good_manifest());
    files.push(("abcdefé.txt", String::new()));
    files.push(("日本語.txt", String::new()));
    let report = report_of(&files);
    assert_eq!(points(&report, "license-file"), 2);
}

fn owned_report(files: &[(String, String)]) -> QualityReport {
    let borrowed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(path, text)| (path.as_str(), text.as_bytes()))
        .collect();
    report_with(QualityEcosystem::Js, &borrowed, None)
}

fn with_manifest(manifest: &Value, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = good_package(manifest)
        .into_iter()
        .map(|(path, text)| (path.to_string(), text))
        .collect();
    for (path, text) in extra {
        files.retain(|(existing, _)| existing != path);
        files.push(((*path).to_string(), (*text).to_string()));
    }
    files
}

#[test]
fn a_types_target_that_declares_nothing_earns_no_type_points() {
    let mut manifest = good_manifest();
    manifest["types"] = json!("README.md");
    manifest["exports"] = json!({
        ".": { "types": "./README.md", "import": "./dist/index.mjs", "require": "./dist/index.cjs" }
    });
    let report = owned_report(&with_manifest(&manifest, &[]));
    assert_eq!(
        points(&report, "types"),
        0,
        "{}",
        check(&report, "types").detail
    );

    manifest["exports"] = json!({
        ".": { "types": "./dist/index.mjs", "import": "./dist/index.mjs" }
    });
    let report = owned_report(&with_manifest(&manifest, &[]));
    assert_eq!(
        points(&report, "types"),
        0,
        "{}",
        check(&report, "types").detail
    );
}

#[test]
fn a_types_condition_naming_javascript_reads_the_declaration_beside_it() {
    let mut manifest = good_manifest();
    manifest["exports"] = json!({
        ".": { "types": "./dist/index.js", "import": "./dist/index.mjs", "require": "./dist/index.cjs" }
    });
    let report = owned_report(&with_manifest(&manifest, &[]));
    assert_eq!(
        points(&report, "types"),
        10,
        "{}",
        check(&report, "types").detail
    );
}

/// A TypeScript source of `size` bytes that declares nothing.
fn filler_typescript(size: usize) -> String {
    "// filler\n".repeat(size / 10)
}

#[test]
fn typescript_sources_no_export_reaches_leave_api_docs_whole() {
    let mut files: Vec<(String, String)> = ["src/a.ts", "src/b.ts", "src/c.ts"]
        .into_iter()
        .map(|path| (path.to_string(), filler_typescript(1_900_000)))
        .collect();
    files.extend(
        good_package(&good_manifest())
            .into_iter()
            .map(|(path, text)| (path.to_string(), text)),
    );
    let report = owned_report(&files);
    assert_eq!(
        check(&report, "api-docs").detail,
        "3 of 3 exports in the type declarations have doc comments (100%)"
    );
}

#[test]
fn a_types_source_that_re_exports_an_unread_file_says_so() {
    let mut manifest = good_manifest();
    manifest["types"] = json!("./src/index.ts");
    manifest["exports"]["."]["types"] = json!("./src/index.ts");
    let mut files: Vec<(String, String)> = ["src/a.ts", "src/b.ts", "src/c.ts"]
        .into_iter()
        .map(|path| (path.to_string(), filler_typescript(1_500_000)))
        .collect();
    files.extend(with_manifest(
        &manifest,
        &[(
            "src/index.ts",
            "/** Parses Markdown source into a syntax tree. */\nexport function parse(source: string): string { return source }\nexport * from './c'\n",
        )],
    ));
    let report = owned_report(&files);
    assert_eq!(
        check(&report, "api-docs").detail,
        "1 of 1 exports in the type declarations have doc comments (100%); 1 file over the read limit unchecked"
    );
}

#[test]
fn a_wildcard_types_target_finds_the_declarations_typescript_substitutes() {
    let mut manifest = good_manifest();
    manifest["types"] = Value::Null;
    manifest["main"] = Value::Null;
    manifest["exports"] = json!({
        "./*": { "types": "./types/*.js", "import": "./dist/*.js" }
    });
    let report = owned_report(&with_manifest(
        &manifest,
        &[
            ("dist/a.js", "export function parse(s) { return s }\n"),
            (
                "types/a.d.ts",
                "/** Parses Markdown source into a syntax tree. */\nexport declare function parse(source: string): string;\n",
            ),
        ],
    ));
    assert_eq!(
        points(&report, "api-docs"),
        10,
        "{}",
        check(&report, "api-docs").detail
    );
}

#[test]
fn a_null_subpath_keeps_its_files_out_of_api_docs() {
    let mut manifest = good_manifest();
    manifest["types"] = Value::Null;
    manifest["main"] = Value::Null;
    manifest["exports"] = json!({
        "./*": { "types": "./dist/*.d.ts", "import": "./dist/*.mjs" },
        "./internal/*": null
    });
    let report = owned_report(&with_manifest(
        &manifest,
        &[
            ("dist/a.mjs", "export function parse(s) { return s }\n"),
            (
                "dist/a.d.ts",
                "/** Parses Markdown source into a syntax tree. */\nexport declare function parse(source: string): string;\n",
            ),
            ("dist/internal/b.mjs", "export function hidden() {}\n"),
            (
                "dist/internal/b.d.ts",
                "export declare function hidden(): void;\n",
            ),
        ],
    ));
    assert_eq!(
        check(&report, "api-docs").detail,
        "4 of 4 exports in the type declarations have doc comments (100%)"
    );
}

#[test]
fn wildcard_exports_count_toward_api_docs_and_readme_imports() {
    let mut manifest = good_manifest();
    manifest["types"] = Value::Null;
    manifest["main"] = Value::Null;
    manifest["exports"] = json!({
        "./*": { "types": "./dist/*.d.ts", "import": "./dist/*.mjs" }
    });
    let readme = format!(
        "# Markdown\n\n{PROSE}\n\n```sh\nlpm install @lpm.dev/acme.md\n```\n\n```ts\nimport {{ parse }} from '@lpm.dev/acme.md/a'\n```\n"
    );
    let report = owned_report(&with_manifest(
        &manifest,
        &[
            ("README.md", &readme),
            ("dist/a.mjs", "export function parse(s) { return s }\n"),
            (
                "dist/a.d.ts",
                "/** Parses Markdown source into a syntax tree. */\nexport declare function parse(source: string): string;\n",
            ),
        ],
    ));
    assert_eq!(
        points(&report, "api-docs"),
        10,
        "{}",
        check(&report, "api-docs").detail
    );
    assert_eq!(
        points(&report, "readme-example"),
        5,
        "{}",
        check(&report, "readme-example").detail
    );
}

#[test]
fn a_name_two_star_exports_bind_differently_is_ambiguous() {
    let readme =
        format!("# Markdown\n\n{PROSE}\n\n```ts\nimport {{ x }} from '@lpm.dev/acme.md'\n```\n");
    let ambiguous = "export * from './a'\nexport * from './b'\n";
    let report = owned_report(&with_manifest(
        &good_manifest(),
        &[
            ("README.md", &readme),
            ("dist/index.d.ts", ambiguous),
            (
                "dist/a.d.ts",
                "/** The first x of the package here. */\nexport declare const x: number;\n",
            ),
            (
                "dist/b.d.ts",
                "/** The second x of the package here. */\nexport declare const x: string;\n",
            ),
        ],
    ));
    assert_eq!(points(&report, "readme-example"), 2);
    assert!(
        check(&report, "readme-example")
            .detail
            .contains("imports x"),
        "{}",
        check(&report, "readme-example").detail
    );

    let resolved = "export * from './a'\nexport * from './b'\nexport { x } from './a'\n";
    let report = owned_report(&with_manifest(
        &good_manifest(),
        &[
            ("README.md", &readme),
            ("dist/index.d.ts", resolved),
            (
                "dist/a.d.ts",
                "/** The first x of the package here. */\nexport declare const x: number;\n",
            ),
            (
                "dist/b.d.ts",
                "/** The second x of the package here. */\nexport declare const x: string;\n",
            ),
        ],
    ));
    assert_eq!(points(&report, "readme-example"), 5);
}

#[test]
fn barrels_re_exporting_each_other_stay_within_the_export_budget() {
    let names: String = (0..1_000)
        .map(|index| format!("export declare const n{index}: number;\n"))
        .collect();
    let mut index = String::new();
    let mut extra: Vec<(String, String)> = vec![("dist/base.d.ts".to_string(), names)];
    for barrel in 0..300 {
        index.push_str(&format!("export * from './barrel{barrel}'\n"));
        extra.push((
            format!("dist/barrel{barrel}.d.ts"),
            "export * from './base'\n".to_string(),
        ));
    }
    extra.push(("dist/index.d.ts".to_string(), index));
    let mut files = with_manifest(&good_manifest(), &[]);
    files.retain(|(path, _)| path != "dist/index.d.ts");
    files.extend(extra);
    let report = owned_report(&files);
    assert_eq!(points(&report, "api-docs"), 0);
    assert!(
        check(&report, "api-docs")
            .detail
            .contains("re-exports more than")
    );
}

#[test]
fn exports_follow_node_rules_for_invalid_targets_numeric_keys_and_null_fallbacks() {
    let mut manifest = good_manifest();
    manifest["exports"] = json!("./dist/../dist/index.mjs");
    let report = owned_report(&with_manifest(&manifest, &[]));
    assert_eq!(points(&report, "exports-map"), 0);
    assert_eq!(points(&report, "esm"), 0);

    manifest["exports"] =
        json!({ ".": { "0": "./dist/index.mjs", "default": "./dist/index.mjs" } });
    let report = owned_report(&with_manifest(&manifest, &[]));
    assert_eq!(points(&report, "exports-map"), 0);

    manifest["exports"] = json!({ ".": [null, "./dist/index.mjs"] });
    let report = owned_report(&with_manifest(&manifest, &[]));
    assert_eq!(
        points(&report, "esm"),
        4,
        "{}",
        check(&report, "esm").detail
    );
}

#[test]
fn the_nearest_package_json_decides_whether_a_js_file_is_esm() {
    let mut manifest = good_manifest();
    manifest["type"] = json!("commonjs");
    manifest["exports"] = json!({ ".": { "import": "./dist/index.js" } });
    let report = owned_report(&with_manifest(
        &manifest,
        &[
            ("dist/package.json", "{\"type\": \"module\"}"),
            ("dist/index.js", "export function parse(s) { return s }\n"),
        ],
    ));
    assert_eq!(
        points(&report, "esm"),
        4,
        "{}",
        check(&report, "esm").detail
    );

    manifest["type"] = json!("module");
    let report = owned_report(&with_manifest(
        &manifest,
        &[
            ("dist/package.json", "{\"type\": \"commonjs\"}"),
            ("dist/index.js", "export function parse(s) { return s }\n"),
        ],
    ));
    assert_eq!(points(&report, "esm"), 0);
}

#[test]
fn a_typeless_main_with_esm_syntax_is_an_es_module() {
    let manifest = json!({
        "name": "@lpm.dev/acme.md",
        "version": "1.2.3",
        "main": "index.js"
    });
    let report = owned_report(&with_manifest(
        &manifest,
        &[("index.js", "export const x = 1\n")],
    ));
    assert_eq!(
        points(&report, "esm"),
        4,
        "{}",
        check(&report, "esm").detail
    );
}

#[test]
fn jsx_in_a_js_entry_is_not_an_es_module_node_can_run() {
    let mut manifest = good_manifest();
    manifest["exports"] = json!({ ".": { "import": "./dist/index.js" } });
    let report = owned_report(&with_manifest(
        &manifest,
        &[("dist/index.js", "export const x = <div />\n")],
    ));
    assert_eq!(points(&report, "esm"), 0);
    assert!(check(&report, "esm").detail.contains("JSX"));
}

#[test]
fn a_readme_that_is_also_a_module_is_read_as_both() {
    let mut manifest = good_manifest();
    manifest["types"] = Value::Null;
    manifest["exports"] = json!("./README.js");
    let files = with_manifest(
        &manifest,
        &[(
            "README.js",
            "/** Parses Markdown source into a syntax tree. */\nexport function parse(s) { return s }\n",
        )],
    )
    .into_iter()
    .filter(|(path, _)| path != "README.md")
    .collect::<Vec<_>>();
    let report = owned_report(&files);
    assert_eq!(
        points(&report, "esm"),
        4,
        "{}",
        check(&report, "esm").detail
    );
    assert_eq!(
        points(&report, "api-docs"),
        10,
        "{}",
        check(&report, "api-docs").detail
    );
}

#[test]
fn a_byte_order_mark_doesnt_hide_the_first_install_command() {
    let readme =
        format!("\u{feff}```sh\nlpm install @lpm.dev/acme.md\n```\n\n# Markdown\n\n{PROSE}\n");
    let report = owned_report(&with_manifest(&good_manifest(), &[("README.md", &readme)]));
    assert_eq!(points(&report, "readme-install"), 3);
}

#[test]
fn swift_targets_at_the_package_root_count_their_listed_sources() {
    let manifest = json!({
        "toolsVersion": { "_version": "6.0.0" },
        "platforms": [{ "platformName": "macos", "version": "13.0", "options": [] }],
        "products": [{ "name": "Lib", "type": { "library": ["automatic"] }, "targets": ["Lib"] }],
        "targets": [
            { "name": "Lib", "type": "regular", "path": ".", "sources": ["Renderer.swift"], "exclude": [], "settings": [] },
            { "name": "LibTests", "type": "test", "path": ".", "sources": ["RendererTests.swift"], "exclude": [], "settings": [] }
        ],
        "dependencies": []
    });
    let mut files = swift_files();
    for (from, to) in [
        ("Sources/Lib/Renderer.swift", "Renderer.swift"),
        ("Tests/LibTests/RendererTests.swift", "RendererTests.swift"),
    ] {
        let index = files.iter().position(|(path, _)| *path == from).unwrap();
        files[index].0 = to;
    }
    let report = swift_report(&files, Some(&manifest));
    assert_eq!(
        points(&report, "has-tests"),
        6,
        "{}",
        check(&report, "has-tests").detail
    );
    assert_eq!(
        points(&report, "readme-example"),
        5,
        "{}",
        check(&report, "readme-example").detail
    );
    assert_eq!(
        check(&report, "api-docs").detail,
        "3 of 3 public declarations have doc comments (100%)"
    );
}

#[test]
fn a_javascript_package_manager_doesnt_install_a_swift_package() {
    let mut files = swift_files();
    replace(
        &mut files,
        "README.md",
        format!("# Lib\n\n{PROSE}\n\n```sh\nnpm install @lpm.dev/acme.lib\n```\n"),
    );
    let report = swift_report(&files, Some(&swift_manifest()));
    assert_eq!(points(&report, "readme-install"), 0);

    replace(
        &mut files,
        "README.md",
        format!("# Lib\n\n{PROSE}\n\n```sh\nlpm install @lpm.dev/acme.lib\n```\n"),
    );
    let report = swift_report(&files, Some(&swift_manifest()));
    assert_eq!(points(&report, "readme-install"), 3);
}

#[test]
fn lpm_add_installs_a_source_package_but_not_another() {
    let readme = format!("# Markdown\n\n{PROSE}\n\n```sh\nlpm add @lpm.dev/acme.md\n```\n");
    let report = owned_report(&with_manifest(&good_manifest(), &[("README.md", &readme)]));
    assert_eq!(points(&report, "readme-install"), 0);

    let report = owned_report(&with_manifest(
        &good_manifest(),
        &[("README.md", &readme), ("lpm.config.json", "{}")],
    ));
    assert_eq!(points(&report, "readme-install"), 3);

    let mut manifest = good_manifest();
    manifest["lpm"] = json!({ "source": "src" });
    let report = owned_report(&with_manifest(&manifest, &[("README.md", &readme)]));
    assert_eq!(points(&report, "readme-install"), 3);
}

#[test]
fn many_exports_patterns_stay_within_the_lookup_budget() {
    let mut exports = serde_json::Map::new();
    exports.insert(
        ".".to_string(),
        json!({ "types": "./dist/index.d.ts", "import": "./dist/index.mjs" }),
    );
    for index in 0..100_000 {
        exports.insert(format!("./k{index}/*"), json!("./dist/*.mjs"));
    }
    let mut manifest = good_manifest();
    manifest["exports"] = Value::Object(exports);
    let mut files = with_manifest(&manifest, &[]);
    for index in 0..2_000 {
        files.push((
            format!("dist/m{index}.mjs"),
            "export const x = 1\n".to_string(),
        ));
    }
    let started = std::time::Instant::now();
    let report = owned_report(&files);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(
        points(&report, "types"),
        5,
        "{}",
        check(&report, "types").detail
    );
    assert!(
        check(&report, "types")
            .detail
            .starts_with("1 of 200001 entries have type declarations"),
        "{}",
        check(&report, "types").detail
    );
}

fn full(report: &QualityReport, id: &str) -> bool {
    let check = check(report, id);
    check.points == check.max_points
}

#[test]
fn a_typescript_source_named_by_types_earns_api_docs_for_its_documented_exports() {
    let mut manifest = good_manifest();
    manifest["types"] = json!("./src/index.ts");
    manifest["exports"] = json!({
        ".": {
            "types": "./src/index.ts",
            "import": "./dist/index.mjs",
            "require": "./dist/index.cjs"
        }
    });
    let mut files = with_manifest(
        &manifest,
        &[
            (
                "src/index.ts",
                "import { identity } from './identity.js'\n/** Parses Markdown source into a syntax tree. */\nexport function parse(source: string): string { return identity(source) }\n/** Renders a syntax tree into sanitized HTML. */\nexport function render(tree: string): string { return tree }\n",
            ),
            (
                "src/identity.ts",
                "export function identity(value: string): string { return value }\n",
            ),
        ],
    );
    files.retain(|(path, _)| path != "dist/index.d.ts");
    let report = owned_report(&files);
    for id in ["types", "api-docs", "readme-example"] {
        assert!(full(&report, id), "{id}: {}", check(&report, id).detail);
    }
}

#[test]
fn a_types_path_naming_javascript_finds_the_declaration_typescript_reads() {
    let mut manifest = good_manifest();
    manifest["types"] = json!("./types/index.js");
    manifest["exports"] = json!({
        ".": {
            "types": "./types/index.js",
            "import": "./dist/index.mjs",
            "require": "./dist/index.cjs"
        },
        "./package.json": "./package.json"
    });
    let mut files = with_manifest(&manifest, &[("types/index.d.ts", DOCUMENTED_DTS)]);
    files.retain(|(path, _)| path != "dist/index.d.ts");
    let report = owned_report(&files);
    for id in ["entry-points", "types", "exports-map", "api-docs"] {
        assert!(full(&report, id), "{id}: {}", check(&report, id).detail);
    }
}

#[test]
fn every_star_of_an_exports_target_takes_the_same_match() {
    let mut manifest = good_manifest();
    manifest["types"] = Value::Null;
    manifest["main"] = Value::Null;
    manifest["exports"] = json!({
        "./*": { "types": "./dist/*-*.d.ts", "import": "./dist/*-*.mjs" }
    });
    let report = owned_report(&with_manifest(
        &manifest,
        &[
            ("dist/a-a.mjs", "export function parse(s) { return s }\n"),
            (
                "dist/a-a.d.ts",
                "/** Parses Markdown source into a syntax tree. */\nexport declare function parse(source: string): string;\n",
            ),
        ],
    ));
    for id in ["exports-map", "types", "entry-points"] {
        assert!(full(&report, id), "{id}: {}", check(&report, id).detail);
    }
}

#[test]
fn a_null_pattern_keeps_its_files_out_of_type_coverage() {
    let mut manifest = good_manifest();
    manifest["types"] = Value::Null;
    manifest["main"] = Value::Null;
    manifest["exports"] = json!({
        "./*": { "types": "./dist/*.d.ts", "import": "./dist/*.mjs" },
        "./private/*": null
    });
    let report = owned_report(&with_manifest(
        &manifest,
        &[
            ("dist/a.mjs", "export function parse(s) { return s }\n"),
            (
                "dist/a.d.ts",
                "/** Parses Markdown source into a syntax tree. */\nexport declare function parse(source: string): string;\n",
            ),
            ("dist/private/b.mjs", "export const hidden = 1\n"),
        ],
    ));
    assert!(full(&report, "types"), "{}", check(&report, "types").detail);
}

#[test]
fn exports_null_reads_as_no_exports() {
    let mut without = good_manifest();
    without.as_object_mut().unwrap().remove("exports");
    let mut null = good_manifest();
    null["exports"] = Value::Null;
    let without = owned_report(&with_manifest(&without, &[]));
    let null = owned_report(&with_manifest(&null, &[]));
    for id in ["entry-points", "types", "esm", "exports-map", "api-docs"] {
        assert_eq!(
            (check(&null, id).points, &check(&null, id).detail),
            (check(&without, id).points, &check(&without, id).detail),
            "{id}"
        );
    }
    assert!(
        full(&null, "entry-points"),
        "{}",
        check(&null, "entry-points").detail
    );
}
