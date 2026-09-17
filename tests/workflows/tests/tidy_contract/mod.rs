use super::*;

fn assert_clean(project: &TempProject) {
    let output = lpm(project).args(["tidy", "--json"]).output().unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output.status.success(), "{report}");
    assert_eq!(report["counts"]["remaining"], 0);
}

#[test]
fn tidy_retains_dependencies_used_outside_common_source_directories() {
    let project = TempProject::empty(
        r#"{"name":"root-usage","version":"1.0.0","dependencies":{"root-used":"1.0.0","script-used":"1.0.0","test-used":"1.0.0"}}"#,
    );
    project.write_file("src/index.js", "export const value = 1;");
    project.write_file("server.js", "require('root-used');");
    project.write_file("scripts/check.mjs", "import 'script-used';");
    project.write_file("tests/example.mjs", "import 'test-used';");
    assert_clean(&project);
}

#[test]
fn tidy_retains_tools_used_by_lpm_json_commands() {
    for section in ["services", "tasks"] {
        let project = TempProject::empty(
            r#"{"name":"task-usage","version":"1.0.0","devDependencies":{"tsx":"1.0.0"}}"#,
        );
        project.write_file("src/index.js", "export const value = 1;");
        project.write_file(
            "lpm.json",
            &serde_json::json!({section:{"check":{"command":"tsx scripts/check.ts"}}}).to_string(),
        );
        assert_clean(&project);
    }
}

#[test]
fn tidy_retains_dependencies_reexported_from_type_declarations() {
    for extension in ["d.ts", "d.cts", "d.mts"] {
        let project = TempProject::empty(
            r#"{"name":"declaration-usage","version":"1.0.0","dependencies":{"type-used":"1.0.0"}}"#,
        );
        project.write_file("src/index.js", "export const value = 1;");
        project.write_file(
            &format!("index.{extension}"),
            "export type { Options } from 'type-used';",
        );
        assert_clean(&project);
    }
}

#[test]
fn tidy_retains_node_types_for_node_protocol_imports() {
    let project = TempProject::empty(
        r#"{"name":"node-types","version":"1.0.0","devDependencies":{"@types/node":"1.0.0"}}"#,
    );
    project.write_file("src/index.ts", "import { readFile } from 'node:fs';");
    assert_clean(&project);
}

#[test]
fn tidy_retains_node_types_for_protocol_only_builtins() {
    for specifier in [
        "node:test",
        "node:test/reporters",
        "node:fs/promises",
        "node:sqlite",
    ] {
        let project = TempProject::empty(
            r#"{"name":"node-protocol","version":"1.0.0","devDependencies":{"@types/node":"1.0.0"}}"#,
        );
        project.write_file("src/index.ts", &format!("import '{specifier}';"));
        assert_clean(&project);
    }
}

#[test]
fn tidy_retains_dependencies_used_by_import_types() {
    let project = TempProject::empty(
        r#"{"name":"import-type","version":"1.0.0","dependencies":{"type-used":"1.0.0"}}"#,
    );
    project.write_file(
        "src/index.ts",
        "export type Options = import('type-used').Options;",
    );
    assert_clean(&project);
}

#[test]
fn tidy_retains_type_packages_used_by_reference_directives() {
    let project = TempProject::empty(
        r#"{"name":"type-reference","version":"1.0.0","devDependencies":{"@types/node":"1.0.0","vite":"1.0.0"}}"#,
    );
    project.write_file(
        "src/env.d.ts",
        "/// <reference types=\"node\" />\n/// <reference types='vite/client' />\n",
    );
    assert_clean(&project);
}

#[test]
fn tidy_ignores_invalid_source_before_parsing_it() {
    let project = TempProject::empty(r#"{"name":"ignored-source","version":"1.0.0"}"#);
    project.write_file("lpm.toml", "[tidy]\nignore-paths = ['src/fixtures/**']\n");
    project.write_file("src/index.js", "export const value = 1;");
    project.write_file("src/fixtures/invalid.js", "function {");
    assert_clean(&project);
}

#[test]
fn tidy_rejects_a_non_table_configuration() {
    let project = TempProject::empty(r#"{"name":"bad-config","version":"1.0.0"}"#);
    project.write_file("lpm.toml", "tidy = 'bad'\n");
    let output = lpm(&project).args(["tidy", "--json"]).output().unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!output.status.success(), "{report}");
    assert!(report["error"].as_str().unwrap().contains("tidy"));
}

#[test]
fn tidy_accepts_a_bom_in_the_root_manifest() {
    let project = TempProject::empty("\u{feff}{\"name\":\"bom-tidy\",\"version\":\"1.0.0\"}");
    assert_clean(&project);
}

#[test]
fn tidy_accepts_a_bom_in_an_installed_manifest() {
    let project = TempProject::empty(
        r#"{"name":"bom-tidy","version":"1.0.0","scripts":{"build":"fixture-bin"},"devDependencies":{"fixture-tool":"1.0.0"}}"#,
    );
    project.write_file("node_modules/fixture-tool/package.json", "\u{feff}{\"name\":\"fixture-tool\",\"version\":\"1.0.0\",\"bin\":{\"fixture-bin\":\"index.js\"}}");
    assert_clean(&project);
}

#[tokio::test]
async fn tidy_fix_json_contains_one_report_when_install_scripts_write_stdout() {
    let mock = MockRegistry::start().await;
    mount_basic_packages(&mock).await;
    let project = TempProject::empty(
        r#"{"name":"json-fix","version":"1.0.0","scripts":{"postinstall":"echo lifecycle-output"},"dependencies":{"react":"18.2.0","lodash":"4.17.21"}}"#,
    );
    project.write_file("src/index.js", "import 'react';");
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    let output = lpm_with_registry(&project, &mock.url())
        .args(["tidy", "--fix", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert_eq!(report["counts"]["removed"], 1);
    assert_eq!(report["success"], true);
}

#[tokio::test]
async fn tidy_fix_json_contains_one_report_when_install_applies_overrides() {
    let mock = MockRegistry::start().await;
    mock.with_package_and_deps(
        "parent",
        "1.0.0",
        &make_tarball("parent", "1.0.0"),
        serde_json::json!({"leaf":"1.0.0"}),
    )
    .await;
    mock.with_full_package_metadata(
        "leaf",
        "2.0.0",
        &[
            (
                "1.0.0",
                serde_json::json!({}),
                Some(make_tarball("leaf", "1.0.0")),
            ),
            (
                "2.0.0",
                serde_json::json!({}),
                Some(make_tarball("leaf", "2.0.0")),
            ),
        ],
    )
    .await;
    mock.with_package("unused", "1.0.0", &make_tarball("unused", "1.0.0"))
        .await;
    let project = TempProject::empty(
        r#"{"name":"override-json","version":"1.0.0","dependencies":{"parent":"1.0.0","unused":"1.0.0"},"overrides":{"leaf":"2.0.0"}}"#,
    );
    project.write_file("src/index.js", "import 'parent';");
    lpm_with_registry(&project, &mock.url())
        .args([
            "install",
            "--no-security-summary",
            "--no-skills",
            "--no-editor-setup",
        ])
        .assert()
        .success();
    let output = lpm_with_registry(&project, &mock.url())
        .args(["tidy", "--fix", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert_eq!(report["counts"]["removed"], 1);
    assert_eq!(report["success"], true);
}

#[cfg(unix)]
#[test]
fn tidy_rejects_a_special_installed_manifest_without_blocking() {
    let project = TempProject::empty(
        r#"{"name":"fifo-tidy","version":"1.0.0","dependencies":{"fixture":"1.0.0"}}"#,
    );
    std::fs::create_dir_all(project.path().join("node_modules/fixture")).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(project.path().join("node_modules/fixture/package.json"))
            .status()
            .unwrap()
            .success()
    );
    let output = lpm(&project)
        .args(["tidy", "--fix", "--json"])
        .timeout(std::time::Duration::from_secs(5))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["error"].as_str().unwrap().contains("package.json"));
    assert!(manifest(&project)["dependencies"].get("fixture").is_some());
}

#[test]
fn tidy_retains_dependencies_used_by_import_equals() {
    let project = TempProject::empty(
        r#"{"name":"import-equals","version":"1.0.0","dependencies":{"type-used":"1.0.0"}}"#,
    );
    project.write_file(
        "src/index.ts",
        "import dep = require('type-used'); export = dep;",
    );
    assert_clean(&project);
}

#[test]
fn tidy_retains_dependencies_from_published_generated_entrypoints() {
    for field in ["types", "typings", "main", "module", "exports", "bin"] {
        let project = TempProject::empty(&serde_json::json!({"name":"published-types","version":"1.0.0",field:"dist/index.d.ts","dependencies":{"type-used":"1.0.0"}}).to_string());
        project.write_file("src/index.js", "export const value = 1;");
        project.write_file(
            "dist/index.d.ts",
            "export type { Options } from 'type-used';",
        );
        assert_clean(&project);
    }
}

#[test]
fn tidy_retains_loader_packages_in_command_options() {
    for command in [
        "node --import=tsx src/index.ts",
        "node --loader=tsx/esm src/index.ts",
        "node --require=tsx/cjs src/index.ts",
        "node -r tsx/cjs src/index.ts",
    ] {
        let project = TempProject::empty(&serde_json::json!({"name":"loader-usage","version":"1.0.0","scripts":{"check":command},"devDependencies":{"tsx":"1.0.0"}}).to_string());
        project.write_file("src/index.ts", "export const value = 1;");
        assert_clean(&project);
    }
}

#[test]
fn tidy_accepts_a_bom_in_a_workspace_member_manifest() {
    let project = TempProject::empty(
        r#"{"name":"bom-workspace","version":"1.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/member/package.json",
        "\u{feff}{\"name\":\"member\",\"version\":\"1.0.0\"}",
    );
    assert_clean(&project);
}

#[cfg(unix)]
fn assert_special_input_rejected(path: &str) {
    let project = TempProject::empty(
        r#"{"name":"fifo-input","version":"1.0.0","workspaces":["packages/*"]}"#,
    );
    project.write_file("src/index.js", "export const value = 1;");
    let input = project.path().join(path);
    std::fs::create_dir_all(input.parent().unwrap()).unwrap();
    if input.exists() {
        std::fs::remove_file(&input).unwrap();
    }
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&input)
            .status()
            .unwrap()
            .success()
    );
    let output = lpm(&project)
        .args(["tidy", "--json"])
        .timeout(std::time::Duration::from_secs(10))
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{path}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains(input.file_name().unwrap().to_str().unwrap()),
        "{report}"
    );
}

#[cfg(unix)]
#[test]
fn tidy_rejects_special_root_manifest_without_blocking() {
    assert_special_input_rejected("package.json");
}
#[cfg(unix)]
#[test]
fn tidy_rejects_special_toml_without_blocking() {
    assert_special_input_rejected("lpm.toml");
}
#[cfg(unix)]
#[test]
fn tidy_rejects_special_known_config_without_blocking() {
    assert_special_input_rejected("eslint.config.js");
}
#[cfg(unix)]
#[test]
fn tidy_rejects_special_lpm_json_without_blocking() {
    assert_special_input_rejected("lpm.json");
}
#[cfg(unix)]
#[test]
fn tidy_rejects_special_alias_config_without_blocking() {
    assert_special_input_rejected("jsconfig.json");
}
#[cfg(unix)]
#[test]
fn tidy_rejects_special_workspace_manifest_without_blocking() {
    assert_special_input_rejected("packages/member/package.json");
}

#[test]
fn tidy_retains_dependencies_in_published_output_with_module_manifest() {
    let project = TempProject::empty(
        r#"{"name":"esm-output","version":"1.0.0","main":"dist/index.js","dependencies":{"runtime-used":"1.0.0"}}"#,
    );
    project.write_file("src/index.js", "export const value = 1;");
    project.write_file("dist/package.json", r#"{"type":"module"}"#);
    project.write_file("dist/index.js", "import 'runtime-used';");
    assert_clean(&project);
}

#[test]
fn tidy_recognizes_aliases_in_bom_prefixed_configuration() {
    for filename in ["tsconfig.json", "jsconfig.json", "lpm.config.json"] {
        let project = TempProject::empty(r#"{"name":"bom-alias","version":"1.0.0"}"#);
        let config = if filename == "lpm.config.json" {
            r#"{"importAlias":"app/"}"#
        } else {
            r#"{"compilerOptions":{"paths":{"app/*":["./src/*"]}}}"#
        };
        project.write_file(filename, &format!("\u{feff}{config}"));
        project.write_file("src/index.ts", "import 'app/value';");
        project.write_file("src/value.ts", "export const value = 1;");
        assert_clean(&project);
    }
}
