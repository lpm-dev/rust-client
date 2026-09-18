//! npm-compatible script status and execution context.
mod support;

use support::mock_registry::MockRegistry;
use support::{TempProject, lpm, lpm_with_registry_and_npm};

fn registry_command(project: &TempProject, registry: &MockRegistry) -> assert_cmd::Command {
    let mut command = lpm_with_registry_and_npm(project, &registry.url());
    command.env("LPM_STORE_VERSION", "v2");
    command
}

const PHASE_SCRIPT: &str = r#"const fs=require('fs');
const keys=['npm_lifecycle_event','npm_lifecycle_script','npm_package_name','npm_package_version','npm_package_json','INIT_CWD'];
const context=Object.fromEntries(keys.map(k=>[k,process.env[k]]));
context.cwd=process.cwd();context.phase=process.argv[2];
fs.appendFileSync('phases.jsonl',JSON.stringify(context)+'\n');
process.exit(Number(process.argv[3]||0));
"#;

fn project_with_phases(phases: &[&str], failed: Option<&str>, cache: bool) -> TempProject {
    let scripts = phases
        .iter()
        .map(|phase| {
            (
                (*phase).to_string(),
                serde_json::json!(format!(
                    "node phase.cjs {phase} {}",
                    if Some(*phase) == failed { 42 } else { 0 }
                )),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let project = TempProject::empty(
        &serde_json::json!({"name":"lifecycle-fixture","version":"1.2.3","scripts":scripts})
            .to_string(),
    );
    project.write_file("phase.cjs", PHASE_SCRIPT);
    if cache {
        project.write_file(
            "lpm.json",
            r#"{"tasks":{"probe":{"cache":true,"outputs":["phases.jsonl"]}}}"#,
        );
    }
    project
}

fn phases(project: &TempProject) -> Vec<serde_json::Value> {
    project
        .read_file("phases.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn script_failures_keep_child_exit_codes_and_stop_later_phases() {
    let names = ["preprobe", "probe", "postprobe"];
    for (json, cache) in [(false, false), (true, false), (false, true)] {
        for (index, failed) in names.iter().enumerate() {
            let project = project_with_phases(&names, Some(failed), cache);
            let mut command = lpm(&project);
            command.args(["run", "probe"]);
            if json {
                command.arg("--json");
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(42),
                "{failed} json={json} cache={cache}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let actual = phases(&project);
            assert_eq!(actual.len(), index + 1);
            assert_eq!(actual.last().unwrap()["phase"], *failed);
        }
    }
}

#[tokio::test]
async fn root_install_failures_keep_child_exit_codes_and_stop_later_phases() {
    let names = [
        "pnpm:devPreinstall",
        "preinstall",
        "install",
        "postinstall",
        "preprepare",
        "prepare",
        "postprepare",
    ];
    for json in [false, true] {
        for (index, failed) in names.iter().enumerate() {
            let project = project_with_phases(&names, Some(failed), false);
            let registry = MockRegistry::start().await;
            let mut command = registry_command(&project, &registry);
            command.args([
                "install",
                "--no-skills",
                "--no-editor-setup",
                "--no-security-summary",
            ]);
            if json {
                command.arg("--json");
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(42),
                "{failed} json={json}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(phases(&project).len(), index + 1);
            assert!(
                registry
                    .server()
                    .received_requests()
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

const CONTEXT_KEYS: &[&str] = &[
    "npm_lifecycle_event",
    "npm_lifecycle_script",
    "npm_package_name",
    "npm_package_version",
    "npm_package_json",
    "INIT_CWD",
];

fn assert_context(project: &TempProject, entries: &[serde_json::Value]) {
    for entry in entries {
        let phase = entry["phase"].as_str().unwrap();
        assert_eq!(entry["npm_lifecycle_event"], phase);
        assert_eq!(
            entry["npm_lifecycle_script"],
            format!("node phase.cjs {phase} 0")
        );
        assert_eq!(entry["npm_package_name"], "lifecycle-fixture");
        assert_eq!(entry["npm_package_version"], "1.2.3");
        assert_eq!(
            std::path::Path::new(entry["npm_package_json"].as_str().unwrap())
                .canonicalize()
                .unwrap(),
            project.path().join("package.json").canonicalize().unwrap()
        );
        assert_eq!(
            std::path::Path::new(entry["INIT_CWD"].as_str().unwrap())
                .canonicalize()
                .unwrap(),
            project.path().canonicalize().unwrap()
        );
    }
}

#[test]
fn each_script_phase_gets_its_own_npm_context_over_inherited_values() {
    for (json, cache) in [(false, false), (true, false), (false, true)] {
        let project = project_with_phases(&["preprobe", "probe", "postprobe"], None, cache);
        project.write_file(
            ".env",
            &CONTEXT_KEYS
                .iter()
                .map(|key| format!("{key}=dotenv-poison\n"))
                .collect::<String>(),
        );
        let mut command = lpm(&project);
        command.args(["run", "probe"]);
        for key in CONTEXT_KEYS {
            command.env(key, "inherited-poison");
        }
        if json {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let entries = phases(&project);
        assert_eq!(entries.len(), 3);
        assert_context(&project, &entries);
    }
}

#[tokio::test]
async fn each_root_install_phase_gets_fresh_npm_context() {
    let names = [
        "pnpm:devPreinstall",
        "preinstall",
        "install",
        "postinstall",
        "preprepare",
        "prepare",
        "postprepare",
    ];
    let project = project_with_phases(&names, None, false);
    project.write_file(
        ".env",
        &CONTEXT_KEYS
            .iter()
            .map(|key| {
                format!(
                    "{}=dotenv-poison\n",
                    if *key == "INIT_CWD" {
                        key.to_lowercase()
                    } else {
                        key.to_uppercase()
                    }
                )
            })
            .collect::<String>(),
    );

    let registry = MockRegistry::start().await;
    let mut command = registry_command(&project, &registry);
    command.args([
        "install",
        "--no-skills",
        "--no-editor-setup",
        "--no-security-summary",
    ]);
    for key in CONTEXT_KEYS {
        command.env(key, "inherited-poison");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let entries = phases(&project);
    assert_eq!(entries.len(), 7);
    assert_context(&project, &entries);
}

#[test]
fn parallel_script_modes_run_hooks_and_stop_after_a_failed_phase() {
    for stream in [false, true] {
        for failed in [None, Some("preprobe"), Some("postprobe")] {
            let project = project_with_phases(&["preprobe", "probe", "postprobe"], failed, false);
            let mut manifest: serde_json::Value =
                serde_json::from_str(&project.read_file("package.json")).unwrap();
            manifest["scripts"]["other"] = serde_json::json!("node -e \"process.exit(0)\"");
            project.write_file("package.json", &manifest.to_string());
            let mut command = lpm(&project);
            command.args(["run", "probe", "other", "--parallel"]);
            if stream {
                command.arg("--stream");
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.success(),
                failed.is_none(),
                "stream={stream} failed={failed:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let actual = phases(&project);
            assert_eq!(
                actual.len(),
                if failed == Some("preprobe") { 1 } else { 3 },
                "stream={stream} failed={failed:?}"
            );
        }
    }
}

#[tokio::test]
async fn dependency_lifecycle_phases_receive_the_installed_package_context() {
    let registry = MockRegistry::start().await;
    registry.with_manifest_package(serde_json::json!({"name":"build-probe","version":"1.2.3","scripts":{"preinstall":"node phase.cjs preinstall 0","install":"node phase.cjs install 0","postinstall":"node phase.cjs postinstall 0"}}),&[("phase.cjs",PHASE_SCRIPT.as_bytes())]).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"build-probe":"1.2.3"}}"#,
    );
    support::write_signed_unlock_for(&project, project.path(), &["scripts-allow", "sandbox-none"]);
    registry_command(&project, &registry)
        .args([
            "install",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .assert()
        .success();
    let mut command = registry_command(&project, &registry);
    command.args(["rebuild", "--all", "--no-sandbox"]);
    for key in CONTEXT_KEYS {
        command.env(key, "inherited-poison");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let package_dir = project
        .path()
        .join("node_modules/build-probe")
        .canonicalize()
        .unwrap();
    let entries = std::fs::read_to_string(package_dir.join("phases.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 3);
    for entry in entries {
        let phase = entry["phase"].as_str().unwrap();
        assert_eq!(entry["npm_lifecycle_event"], phase);
        assert_eq!(
            entry["npm_lifecycle_script"],
            format!("node phase.cjs {phase} 0")
        );
        assert_eq!(entry["npm_package_name"], "build-probe");
        assert_eq!(entry["npm_package_version"], "1.2.3");
        assert_eq!(
            std::path::Path::new(entry["npm_package_json"].as_str().unwrap())
                .canonicalize()
                .unwrap(),
            package_dir.join("package.json")
        );
        assert_eq!(
            std::path::Path::new(entry["INIT_CWD"].as_str().unwrap())
                .canonicalize()
                .unwrap(),
            project.path().canonicalize().unwrap()
        );
    }
}

async fn dependency_binary_fixture(linker: &str, root_conflict: bool) {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({"name":"own-tool","version":"1.0.0","bin":{"build-tool":"bin.cjs"}}),
            &[(
                "bin.cjs",
                b"#!/usr/bin/env node\nrequire('fs').writeFileSync('tool.txt','own');\n",
            )],
        )
        .await;
    registry.with_manifest_package(serde_json::json!({"name":"builder","version":"1.0.0","dependencies":{"own-tool":"1.0.0"},"scripts":{"postinstall":"build-tool"}}),&[]).await;
    let mut manifest =
        serde_json::json!({"name":"consumer","version":"1.0.0","dependencies":{"builder":"1.0.0"}});
    if root_conflict {
        registry.with_manifest_package(serde_json::json!({"name":"root-tool","version":"2.0.0","bin":{"build-tool":"bin.cjs"}}),&[("bin.cjs",b"#!/usr/bin/env node\nrequire('fs').writeFileSync('tool.txt','root');\n")]).await;
        manifest["dependencies"]["root-tool"] = serde_json::json!("2.0.0");
    }
    let project = TempProject::empty(&manifest.to_string());
    support::write_signed_unlock_for(&project, project.path(), &["scripts-allow", "sandbox-none"]);
    registry_command(&project, &registry)
        .args([
            "install",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
            "--linker",
            linker,
        ])
        .assert()
        .success();
    let output = registry_command(&project, &registry)
        .args(["rebuild", "--all", "--no-sandbox"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{linker} root_conflict={root_conflict}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        project.read_file("node_modules/builder/tool.txt"),
        "own",
        "{linker} root_conflict={root_conflict}"
    );
    assert_eq!(
        project
            .path()
            .join(if cfg!(windows) {
                "node_modules/.bin/build-tool.cmd"
            } else {
                "node_modules/.bin/build-tool"
            })
            .exists(),
        root_conflict
    );
}

#[tokio::test]
async fn dependency_scripts_can_run_their_declared_transitive_binaries() {
    for linker in ["hoisted", "isolated"] {
        dependency_binary_fixture(linker, false).await;
    }
}

#[tokio::test]
async fn dependency_binary_versions_take_precedence_over_root_tools() {
    for linker in ["hoisted", "isolated"] {
        dependency_binary_fixture(linker, true).await;
    }
}

#[test]
fn json_runs_keep_stdout_parseable_for_scripts_raw_tasks_and_cache_hits() {
    for raw in [false, true] {
        for cache in [false, true] {
            for parallel in [false, true] {
                let project = project_with_phases(&["preprobe", "probe", "postprobe"], None, false);
                project.write_file(
                    "phase.cjs",
                    &format!("{PHASE_SCRIPT}\nconsole.log('phase-out:'+process.argv[2]);\n"),
                );
                // The normal fixture exits explicitly. This fixture must reach console.log.
                project.write_file(
                    "phase.cjs",
                    &project
                        .read_file("phase.cjs")
                        .replace("process.exit(Number(process.argv[3]||0));", ""),
                );
                let mut task = serde_json::json!({"cache":cache,"outputs":["phases.jsonl"]});
                if raw {
                    task["command"] = "node phase.cjs probe 0".into();
                }
                project.write_file(
                    "lpm.json",
                    &serde_json::json!({"tasks":{"probe":task}}).to_string(),
                );
                for attempt in 0..2 {
                    let mut command = lpm(&project);
                    command.args(["run", "probe", "--json"]);
                    if parallel {
                        command.args(["--parallel", "--stream"]);
                    }
                    let output = command.output().unwrap();
                    assert!(
                        output.status.success(),
                        "{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
                        .expect("one JSON envelope, without child output");
                    assert_eq!(envelope["success"], true);
                    if cache && attempt == 1 {
                        assert_eq!(envelope["cached"], 1);
                    }
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    for phase in if raw {
                        vec!["probe"]
                    } else {
                        vec!["preprobe", "probe", "postprobe"]
                    } {
                        assert_eq!(
                            stderr.matches(&format!("phase-out:{phase}\n")).count(),
                            1,
                            "raw={raw} cache={cache} attempt={attempt}: {stderr}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn json_script_failure_identifies_hook_and_child_status() {
    let project = project_with_phases(&["preprobe", "probe", "postprobe"], Some("preprobe"), false);
    let output = lpm(&project)
        .args(["run", "probe", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(42));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["tasks"][0]["exit_code"], 42);
    assert_eq!(envelope["tasks"][0]["phase"], "preprobe");
    insta::assert_json_snapshot!("script_phase_failure",envelope,{".duration_ms"=>"<ms>",".tasks[].duration_ms"=>"<ms>"});
}

#[tokio::test]
async fn json_root_failure_reports_phase_and_child_status() {
    let registry = MockRegistry::start().await;
    let project = project_with_phases(&["preinstall"], Some("preinstall"), false);
    let output = registry_command(&project, &registry)
        .args([
            "install",
            "--json",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(42));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["exit_code"], 42);
    assert_eq!(envelope["phase"], "preinstall");
    insta::assert_json_snapshot!("root_phase_failure", envelope);
}

#[test]
fn raw_single_tasks_preserve_child_status_but_multi_task_plans_count_failures() {
    let project = TempProject::empty(r#"{"name":"raw-task","version":"1.0.0"}"#);
    project.write_file("lpm.json",r#"{"tasks":{"fail":{"command":"node -e \"process.exit(42)\""},"ok":{"command":"node -e \"process.exit(0)\""}}}"#);
    for json in [false, true] {
        for parallel in [false, true] {
            for multiple in [false, true] {
                let mut command = lpm(&project);
                command.args(["run", "fail"]);
                if multiple {
                    command.arg("ok");
                }
                if json {
                    command.arg("--json");
                }
                if parallel {
                    command.arg("--parallel");
                }
                assert_eq!(
                    command.output().unwrap().status.code(),
                    Some(if multiple { 1 } else { 42 })
                );
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn cached_tasks_track_distinct_case_sensitive_inherited_variables() {
    let project = TempProject::empty(
        r#"{"name":"context-cache","version":"1.0.0","scripts":{"probe":"node capture.cjs"}}"#,
    );
    project.write_file(
        "capture.cjs",
        "require('fs').writeFileSync('output.txt', process.env.NPM_PACKAGE_NAME)",
    );
    project.write_file("lpm.json",r#"{"tasks":{"probe":{"cache":true,"outputs":["output.txt"],"cacheEnv":["NPM_PACKAGE_NAME"]}}}"#);
    for value in ["first", "second"] {
        lpm(&project)
            .args(["run", "probe"])
            .env("NPM_PACKAGE_NAME", value)
            .assert()
            .success();
        assert_eq!(project.read_file("output.txt"), value);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn dependency_tools_keep_cache_keys_stable_and_track_live_helper_inputs() {
    let registry = MockRegistry::start().await;
    registry.with_manifest_package(serde_json::json!({"name":"own-tool","version":"1.0.0","bin":{"build-tool":"bin.cjs"}}),&[("bin.cjs",b"#!/usr/bin/env node\nrequire('fs').writeFileSync('tool.txt',require('./lib.cjs'));\n"),("lib.cjs",b"module.exports='first';\n")]).await;
    registry.with_manifest_package(serde_json::json!({"name":"esbuild","version":"1.0.0","dependencies":{"own-tool":"1.0.0"},"scripts":{"postinstall":"node install.js"}}),&[("install.js",b"require('child_process').execFileSync('build-tool');\n")]).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"esbuild":"1.0.0"}}"#,
    );
    support::write_signed_unlock_for(&project, project.path(), &["scripts-allow"]);
    registry_command(&project, &registry)
        .args([
            "install",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .assert()
        .success();
    let rebuild = || {
        let output = registry_command(&project, &registry)
            .args(["rebuild", "--all", "--strict-sandbox", "--json"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    assert_eq!(rebuild()["build_cache"]["misses"], 1);
    assert_eq!(rebuild()["build_cache"]["local_state_hits"], 1);
    let consumer = project
        .path()
        .join("node_modules/esbuild")
        .canonicalize()
        .unwrap();
    std::fs::remove_file(consumer.join(".lpm-built")).unwrap();
    std::fs::remove_file(consumer.join("tool.txt")).unwrap();
    assert_eq!(rebuild()["build_cache"]["hits"], 1);
    assert_eq!(
        std::fs::read_to_string(consumer.join("tool.txt")).unwrap(),
        "first"
    );
    let provider = consumer
        .parent()
        .unwrap()
        .join("own-tool")
        .canonicalize()
        .unwrap();
    std::fs::write(provider.join("lib.cjs"), "module.exports='second';\n").unwrap();
    assert_eq!(rebuild()["build_cache"]["misses"], 1);
    assert_eq!(
        std::fs::read_to_string(consumer.join("tool.txt")).unwrap(),
        "second"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn native_rebuild_preserves_same_name_dependency_links() {
    let registry = MockRegistry::start().await;
    let older = serde_json::json!({"name":"esbuild","version":"1.0.0"});
    let newer = serde_json::json!({"name":"esbuild","version":"2.0.0","dependencies":{"esbuild":"1.0.0"},"scripts":{"postinstall":"node install.js"}});
    let old_tar = support::mock_registry::make_tarball_from_pkg_json(older.clone(), &[]);
    let new_tar=support::mock_registry::make_tarball_from_pkg_json(newer.clone(),&[("install.js",b"require('fs').writeFileSync('version.txt',require('esbuild/package.json').version);\n")]);
    let mut versions = serde_json::Map::new();
    for (mut manifest, tar) in [(older, &old_tar), (newer, &new_tar)] {
        let version = manifest["version"].as_str().unwrap().to_string();
        manifest["dist"] = serde_json::json!({"tarball":registry.tarball_url("esbuild",&version),"integrity":support::mock_registry::compute_integrity(tar)});
        versions.insert(version, manifest);
    }
    registry.with_package_metadata_and_tarballs("esbuild",serde_json::json!({"name":"esbuild","dist-tags":{"latest":"2.0.0"},"versions":versions}),&[("1.0.0",old_tar),("2.0.0",new_tar)]).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"esbuild":"2.0.0"}}"#,
    );
    support::write_signed_unlock_for(&project, project.path(), &["scripts-allow"]);
    registry_command(&project, &registry)
        .args([
            "install",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .assert()
        .success();
    registry_command(&project, &registry)
        .args(["rebuild", "--all", "--strict-sandbox"])
        .assert()
        .success();
    assert_eq!(
        project.read_file("node_modules/esbuild/version.txt"),
        "1.0.0"
    );
    assert!(
        project
            .path()
            .join("node_modules/esbuild/node_modules/esbuild/package.json")
            .exists()
    );
}

#[tokio::test]
async fn lifecycle_order_includes_scripted_dependencies_behind_unscripted_tools() {
    let registry = MockRegistry::start().await;
    registry.with_manifest_package(serde_json::json!({"name":"generated-input","version":"1.0.0","scripts":{"postinstall":"node generate.cjs"}}),&[("generate.cjs",b"setTimeout(()=>require('fs').writeFileSync('generated.cjs',\"module.exports='ready';\"),500);\n")]).await;
    registry.with_manifest_package(serde_json::json!({"name":"middle-tool","version":"1.0.0","dependencies":{"generated-input":"1.0.0"},"bin":{"build-tool":"bin.cjs"}}),&[("bin.cjs",b"#!/usr/bin/env node\nrequire('fs').writeFileSync('result.txt',require('generated-input/generated.cjs'));\n")]).await;
    registry.with_manifest_package(serde_json::json!({"name":"aaa-consumer","version":"1.0.0","dependencies":{"middle-tool":"1.0.0"},"scripts":{"postinstall":"build-tool"}}),&[]).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"aaa-consumer":"1.0.0"}}"#,
    );
    support::write_signed_unlock_for(&project, project.path(), &["scripts-allow", "sandbox-none"]);
    registry_command(&project, &registry)
        .args([
            "install",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .assert()
        .success();
    registry_command(&project, &registry)
        .args(["rebuild", "--all", "--no-sandbox"])
        .assert()
        .success();
    assert_eq!(
        project.read_file("node_modules/aaa-consumer/result.txt"),
        "ready"
    );
}

#[test]
fn workspace_scripts_keep_invocation_directory_and_reserve_json_stdout() {
    let project =
        TempProject::empty(r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#);
    for name in ["one", "two"] {
        project.write_file(&format!("packages/{name}/package.json"), &serde_json::json!({"name":name,"version":"2.3.4","scripts":{"probe":"node phase.cjs probe 0"}}).to_string());
        project.write_file(
            &format!("packages/{name}/phase.cjs"),
            &format!("console.log('child-output');\n{PHASE_SCRIPT}"),
        );
    }
    let output = lpm(&project)
        .args(["run", "probe", "--all", "--parallel", "--stream", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["success"], true);
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .matches("child-output")
            .count(),
        2
    );
    for name in ["one", "two"] {
        let entry: serde_json::Value = serde_json::from_str(
            project
                .read_file(&format!("packages/{name}/phases.jsonl"))
                .trim(),
        )
        .unwrap();
        assert_eq!(entry["npm_package_name"], name);
        assert_eq!(entry["npm_package_version"], "2.3.4");
        assert_eq!(
            std::path::Path::new(entry["INIT_CWD"].as_str().unwrap())
                .canonicalize()
                .unwrap(),
            project.path().canonicalize().unwrap()
        );
    }
}

#[tokio::test]
async fn aliased_string_bins_use_the_provider_name_and_broken_edges_do_not_fall_back() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({"name":"real-tool","version":"1.0.0","bin":"bin.cjs"}),
            &[(
                "bin.cjs",
                b"#!/usr/bin/env node\nrequire('fs').writeFileSync('tool.txt','own');\n",
            )],
        )
        .await;
    registry.with_manifest_package(serde_json::json!({"name":"builder","version":"1.0.0","dependencies":{"tool-alias":"npm:real-tool@1.0.0"},"scripts":{"postinstall":"real-tool"}}),&[]).await;
    registry
        .with_manifest_package(
            serde_json::json!({"name":"root-tool","version":"1.0.0","bin":{"real-tool":"bin.cjs"}}),
            &[(
                "bin.cjs",
                b"#!/usr/bin/env node\nrequire('fs').writeFileSync('tool.txt','root');\n",
            )],
        )
        .await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"builder":"1.0.0","root-tool":"1.0.0"}}"#,
    );
    support::write_signed_unlock_for(&project, project.path(), &["scripts-allow", "sandbox-none"]);
    registry_command(&project, &registry)
        .args([
            "install",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .assert()
        .success();
    registry_command(&project, &registry)
        .args(["rebuild", "--all", "--no-sandbox"])
        .assert()
        .success();
    assert_eq!(project.read_file("node_modules/builder/tool.txt"), "own");
    let consumer = project
        .path()
        .join("node_modules/builder")
        .canonicalize()
        .unwrap();
    let slot = consumer.parent().unwrap().join("tool-alias");
    #[cfg(unix)]
    std::fs::remove_file(slot).unwrap();
    #[cfg(windows)]
    std::fs::remove_dir(slot).unwrap();
    let output = registry_command(&project, &registry)
        .args(["rebuild", "--all", "--no-sandbox", "--force"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(project.read_file("node_modules/builder/tool.txt"), "own");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn dependency_tools_can_read_helpers_but_cannot_write_providers_or_shims() {
    let registry = MockRegistry::start().await;
    registry
        .with_manifest_package(
            serde_json::json!({"name":"helper","version":"1.0.0","main":"index.cjs"}),
            &[("index.cjs", b"module.exports='helper';\n")],
        )
        .await;
    let tool=br#"#!/usr/bin/env node
const fs=require('fs'),path=require('path');
if(require('helper')!=='helper')throw Error('helper missing');
for(const target of [path.join(__dirname,'forbidden'),require.resolve('helper'),path.join(process.env.PATH.split(path.delimiter)[0],'forbidden')]){
 let denied=false;try{fs.writeFileSync(target,'changed');}catch(e){denied=true;}if(!denied)throw Error('unexpected write:'+target);
}
fs.writeFileSync(path.join(process.env.TMPDIR,'allowed'),'ok');
fs.writeFileSync('result.txt','ok');
"#;
    registry.with_manifest_package(serde_json::json!({"name":"own-tool","version":"1.0.0","dependencies":{"helper":"1.0.0"},"bin":{"build-tool":"bin.cjs"}}),&[("bin.cjs",tool)]).await;
    registry.with_manifest_package(serde_json::json!({"name":"builder","version":"1.0.0","dependencies":{"own-tool":"1.0.0"},"scripts":{"postinstall":"build-tool"}}),&[]).await;
    let project = TempProject::empty(
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"builder":"1.0.0"}}"#,
    );
    support::write_signed_unlock_for(&project, project.path(), &["scripts-allow"]);
    registry_command(&project, &registry)
        .args([
            "install",
            "--no-skills",
            "--no-editor-setup",
            "--no-security-summary",
        ])
        .assert()
        .success();
    registry_command(&project, &registry)
        .args(["rebuild", "--all", "--strict-sandbox"])
        .assert()
        .success();
    assert_eq!(project.read_file("node_modules/builder/result.txt"), "ok");
}

#[test]
fn parallel_failures_emit_hook_output_once_and_report_the_actual_status() {
    for stream in [false, true] {
        let project = project_with_phases(
            &["preprobe", "probe", "postprobe"],
            Some("postprobe"),
            false,
        );
        let mut manifest: serde_json::Value =
            serde_json::from_str(&project.read_file("package.json")).unwrap();
        manifest["scripts"]["other"] = "node -e \"process.exit(0)\"".into();
        project.write_file("package.json", &manifest.to_string());
        project.write_file(
            "phase.cjs",
            &format!("console.error('PHASE:'+process.argv[2]);\n{PHASE_SCRIPT}"),
        );
        let mut command = lpm(&project);
        command.args(["run", "probe", "other", "--parallel"]);
        if stream {
            command.arg("--stream");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr);
        for phase in ["preprobe", "probe", "postprobe"] {
            assert_eq!(
                stderr.matches(&format!("PHASE:{phase}")).count(),
                1,
                "{stderr}"
            );
        }
        assert!(stderr.contains("exit 42"), "{stderr}");
        assert!(stderr.contains("postprobe"));
    }
}

#[test]
fn missing_package_metadata_clears_inherited_context_without_changing_declared_command() {
    let project = TempProject::empty(r#"{"scripts":{"probe":"node context.cjs"}}"#);
    project.write_file("context.cjs","require('fs').writeFileSync('context.json',JSON.stringify({name:process.env.npm_package_name,version:process.env.npm_package_version,script:process.env.npm_lifecycle_script,args:process.argv.slice(2)}));");
    lpm(&project)
        .args(["run", "probe", "--", "one argument", "two"])
        .env("npm_package_name", "poison")
        .env("npm_package_version", "poison")
        .assert()
        .success();
    let context: serde_json::Value =
        serde_json::from_str(&project.read_file("context.json")).unwrap();
    assert_eq!(
        context,
        serde_json::json!({"name":"","version":"","script":"node context.cjs","args":["one argument","two"]})
    );
}

#[test]
fn parallel_streamed_cache_hits_replay_each_task_output_once() {
    let project = TempProject::empty(
        r#"{"scripts":{"first":"node task.cjs first","second":"node task.cjs second"}}"#,
    );
    project.write_file("task.cjs", "const name=process.argv[2];require('fs').writeFileSync(name+'.txt',name);console.log('STDOUT_'+name);console.error('STDERR_'+name);");
    project.write_file("lpm.json", r#"{"tasks":{"first":{"cache":true,"outputs":["first.txt"],"inputs":["task.cjs"]},"second":{"cache":true,"outputs":["second.txt"],"inputs":["task.cjs"]}}}"#);
    for attempt in 0..2 {
        let output = lpm(&project)
            .args(["run", "first", "second", "--parallel", "--stream"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");
        for name in ["first", "second"] {
            assert_eq!(
                combined.matches(&format!("STDOUT_{name}")).count(),
                1,
                "attempt {attempt}: {stdout}"
            );
            assert_eq!(
                combined.matches(&format!("STDERR_{name}")).count(),
                1,
                "attempt {attempt}: {stderr}"
            );
        }
        if attempt == 1 {
            assert!(stderr.contains("cached") || stdout.contains("cached"));
        }
    }
}

#[test]
fn parallel_streamed_setup_failures_report_the_diagnostic_without_starting_scripts() {
    let project = TempProject::empty(
        r#"{"scripts":{"one":"node should-not-run.cjs","two":"node should-not-run.cjs"}}"#,
    );
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"TOKEN":{"pattern":"("}}}}"#,
    );
    project.write_file(
        "should-not-run.cjs",
        "require('fs').writeFileSync('spawned.txt','yes');",
    );
    let output = lpm(&project)
        .args(["run", "one", "two", "--parallel", "--stream", "--no-cache"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid regex"), "{stderr}");
    assert!(stderr.contains("TOKEN"), "{stderr}");
    assert!(!project.file_exists("spawned.txt"));
}
