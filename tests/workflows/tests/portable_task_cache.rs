//! Portable task artifacts across independent checkouts and runtime installations.

mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use support::mock_registry::MockRegistry;
use support::{TempProject, lpm};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

#[derive(Clone)]
struct Artifact {
    bytes: Vec<u8>,
    tag: String,
    sha: String,
}

enum RuntimeMutation {
    TouchMetadata(std::path::PathBuf),
    AddProjectLauncher {
        project: std::path::PathBuf,
        node: std::path::PathBuf,
    },
}

#[derive(Clone, Default)]
struct Artifacts(
    Arc<Mutex<HashMap<String, Artifact>>>,
    Arc<Mutex<Option<RuntimeMutation>>>,
);

impl Respond for Artifacts {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut artifacts = self.0.lock().unwrap();
        let key = request.url.path().to_string();
        if request.method == "PUT" {
            artifacts.insert(
                key,
                Artifact {
                    bytes: request.body.clone(),
                    tag: request.headers["x-artifact-tag"]
                        .to_str()
                        .unwrap()
                        .to_string(),
                    sha: request.headers["x-artifact-sha"]
                        .to_str()
                        .unwrap()
                        .to_string(),
                },
            );
            return ResponseTemplate::new(200).set_body_json(serde_json::json!({"urls": []}));
        }
        if artifacts.contains_key(&key)
            && let Some(mutation) = self.1.lock().unwrap().take()
        {
            match mutation {
                RuntimeMutation::TouchMetadata(binary) => {
                    let modified = binary.metadata().unwrap().modified().unwrap()
                        + std::time::Duration::from_secs(10);
                    std::fs::File::options()
                        .write(true)
                        .open(binary)
                        .unwrap()
                        .set_times(std::fs::FileTimes::new().set_modified(modified))
                        .unwrap();
                }
                RuntimeMutation::AddProjectLauncher { project, node } => {
                    let bin = project.join("node_modules/.bin");
                    std::fs::create_dir_all(&bin).unwrap();
                    let node = node.to_str().unwrap();
                    let launcher = if cfg!(windows) {
                        bin.join("node.cmd")
                    } else {
                        bin.join("node")
                    };
                    let content = if cfg!(windows) {
                        format!(
                            "@echo off\r\n> runtime-marker echo selected\r\n\"{}\" %*\r\n",
                            node.replace('%', "%%")
                        )
                    } else {
                        format!(
                            "#!/bin/sh\nprintf selected > runtime-marker\nexec '{}' \"$@\"\n",
                            node.replace('\'', "'\"'\"'")
                        )
                    };
                    std::fs::write(&launcher, content).unwrap();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(launcher, std::fs::Permissions::from_mode(0o755))
                            .unwrap();
                    }
                }
            }
        }
        match artifacts.get(&key) {
            Some(artifact) => ResponseTemplate::new(200)
                .insert_header("x-artifact-tag", artifact.tag.as_str())
                .insert_header("x-artifact-sha", artifact.sha.as_str())
                .set_body_bytes(artifact.bytes.clone()),
            None => ResponseTemplate::new(404),
        }
    }
}

async fn remote_cache() -> (MockRegistry, Artifacts) {
    let registry = MockRegistry::start().await;
    let artifacts = Artifacts::default();
    for verb in ["GET", "PUT"] {
        Mock::given(method(verb))
            .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
            .respond_with(artifacts.clone())
            .mount(registry.server())
            .await;
    }
    (registry, artifacts)
}

fn project(registry: &MockRegistry, portable: bool) -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"portable-build","version":"1.0.0","scripts":{"build":"node build.js"}}"#,
    );
    project.write_file("build.js", "const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',fs.readFileSync('src/value.txt')); fs.writeFileSync('executed-marker','ran'); fs.writeFileSync('context.json',JSON.stringify({manifest:process.env.npm_package_json,cwd:process.env.INIT_CWD}));");
    project.write_file("src/value.txt", "portable-output");
    let mut config = serde_json::json!({
        "remoteCache":{"enabled":true,"url":format!("{}/v8",registry.server().uri())},
        "tasks":{"build":{"cache":true,"cachePortable":portable,"cacheEnv":[],"outputs":["dist/**"]}}
    });
    if !portable {
        config["tasks"]["build"]
            .as_object_mut()
            .unwrap()
            .remove("cachePortable");
    }
    project.write_file("lpm.json", &config.to_string());
    project
}

fn cache_command(project: &TempProject) -> assert_cmd::Command {
    let mut command = lpm(project);
    let isolated_env: Vec<_> = command
        .get_envs()
        .filter_map(|(name, value)| value.map(|value| (name.to_owned(), value.to_owned())))
        .collect();
    command.env_clear();
    for name in [
        "PATH",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "SystemRoot",
        "WINDIR",
        "SystemDrive",
        "ComSpec",
        "PATHEXT",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.envs(isolated_env);
    command
}

fn build(project: &TempProject) {
    let result = cache_command(project)
        .env("LPM_REMOTE_CACHE_TOKEN", "remote-token")
        .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
        .args(["run", "build"])
        .assert()
        .success();
    let output = result.get_output();
    eprintln!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn location_sensitive_cache_does_not_restore_in_another_checkout() {
    let (registry, artifacts) = remote_cache().await;
    let producer = project(&registry, false);
    let consumer = project(&registry, false);
    build(&producer);
    build(&consumer);
    assert!(consumer.file_exists("executed-marker"));
    assert_eq!(artifacts.0.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn portable_cache_tracks_source_and_declared_environment_changes() {
    let (registry, artifacts) = remote_cache().await;
    let producer = project(&registry, true);
    let consumer = project(&registry, true);
    for project in [&producer, &consumer] {
        let mut config: serde_json::Value =
            serde_json::from_str(&project.read_file("lpm.json")).unwrap();
        config["tasks"]["build"]["cacheEnv"] = serde_json::json!(["BUILD_TARGET"]);
        project.write_file("lpm.json", &config.to_string());
    }
    let run = |project: &TempProject, target: &str| {
        cache_command(project)
            .env("BUILD_TARGET", target)
            .env("LPM_REMOTE_CACHE_TOKEN", "remote-token")
            .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
            .args(["run", "build"])
            .assert()
            .success();
    };
    run(&producer, "web");
    run(&consumer, "web");
    assert!(!consumer.file_exists("executed-marker"));
    run(&consumer, "mobile");
    assert!(consumer.file_exists("executed-marker"));
    std::fs::remove_file(consumer.path().join("executed-marker")).unwrap();
    consumer.write_file("src/value.txt", "changed-output");
    run(&consumer, "mobile");
    assert_eq!(consumer.read_file("dist/value.txt"), "changed-output");
    assert!(consumer.file_exists("executed-marker"));
    assert_eq!(artifacts.0.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn portable_cache_reuses_identical_native_runtime_installations() {
    let (registry, artifacts) = remote_cache().await;
    let producer = project(&registry, true);
    let consumer = project(&registry, true);
    for project in [&producer, &consumer] {
        let (_, path) = copied_node_path(project);
        build_with_path(project, &path);
    }
    assert!(!consumer.file_exists("executed-marker"));
    assert_eq!(artifacts.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn portable_cache_restores_across_checkout_roots_and_isolated_homes() {
    let (registry, artifacts) = remote_cache().await;
    let producer = project(&registry, true);
    let consumer = project(&registry, true);
    build(&producer);
    assert!(producer.file_exists("executed-marker"));
    assert_eq!(artifacts.0.lock().unwrap().len(), 1);
    let context: serde_json::Value =
        serde_json::from_str(&producer.read_file("context.json")).unwrap();
    assert_eq!(
        std::path::Path::new(context["manifest"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        producer.path().join("package.json").canonicalize().unwrap()
    );
    assert_eq!(
        std::path::Path::new(context["cwd"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        producer.path().canonicalize().unwrap()
    );
    build(&consumer);
    assert_eq!(consumer.read_file("dist/value.txt"), "portable-output");
    assert!(
        !consumer.file_exists("executed-marker"),
        "the independent checkout must restore the remote artifact without executing"
    );
    assert_eq!(
        artifacts.0.lock().unwrap().len(),
        1,
        "both checkouts must address the same artifact key"
    );
}

#[tokio::test]
async fn portable_workspace_cache_reuses_prerequisites_and_tracks_their_changes() {
    for flags in [
        &[][..],
        &["--parallel"][..],
        &["--stream"][..],
        &["--json"][..],
    ] {
        let (registry, artifacts) = remote_cache().await;
        let producer = project(&registry, true);
        let consumer = project(&registry, true);
        for project in [&producer, &consumer] {
            project.write_file(
                "package.json",
                r#"{"name":"workspace","private":true,"workspaces":["packages/*"]}"#,
            );
            let build_script = project.read_file("build.js");
            for (name, dependencies) in [
                ("lib", serde_json::json!({})),
                ("app", serde_json::json!({"lib":"workspace:*"})),
            ] {
                project.write_file(&format!("packages/{name}/package.json"), &serde_json::json!({"name":name,"version":"1.0.0","dependencies":dependencies,"scripts":{"build":"node build.js"}}).to_string());
                project.write_file(&format!("packages/{name}/build.js"), &build_script);
                project.write_file(&format!("packages/{name}/src/value.txt"), name);
            }
            let mut config: serde_json::Value =
                serde_json::from_str(&project.read_file("lpm.json")).unwrap();
            config["tasks"]["build"]["dependsOn"] = serde_json::json!(["^build"]);
            project.write_file("lpm.json", &config.to_string());
            project.write_file("packages/app/lpm.json", &config.to_string());
            config["tasks"]["build"]["dependsOn"] = serde_json::json!([]);
            project.write_file("packages/lib/lpm.json", &config.to_string());
        }
        let run = |project: &TempProject| {
            cache_command(project)
                .env("LPM_REMOTE_CACHE_TOKEN", "remote-token")
                .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
                .args(["run", "build", "--filter", "app"])
                .args(flags)
                .assert()
                .success();
        };
        run(&producer);
        run(&consumer);
        for name in ["lib", "app"] {
            assert_eq!(
                consumer.read_file(&format!("packages/{name}/dist/value.txt")),
                name
            );
            assert!(
                !consumer.file_exists(&format!("packages/{name}/executed-marker")),
                "{name} executed with {flags:?}"
            );
        }
        assert_eq!(artifacts.0.lock().unwrap().len(), 2);
        consumer.write_file("packages/lib/src/value.txt", "changed-lib");
        run(&consumer);
        assert!(consumer.file_exists("packages/lib/executed-marker"));
        assert!(
            consumer.file_exists("packages/app/executed-marker"),
            "upstream identity must invalidate app with {flags:?}"
        );
        assert_eq!(artifacts.0.lock().unwrap().len(), 4);
    }
}

fn copied_node_path(project: &TempProject) -> (std::path::PathBuf, std::ffi::OsString) {
    let node = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .unwrap();
    assert!(node.status.success());
    let node_path = String::from_utf8(node.stdout).unwrap();
    let bin = project.home().join("runtime/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let executable = bin.join(if cfg!(windows) { "node.exe" } else { "node" });
    std::fs::copy(node_path.trim(), &executable).unwrap();
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    (executable, path)
}

fn build_with_path(project: &TempProject, path: &std::ffi::OsStr) {
    cache_command(project)
        .env("PATH", path)
        .env("LPM_REMOTE_CACHE_TOKEN", "remote-token")
        .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
        .args(["run", "build"])
        .assert()
        .success();
}

#[tokio::test]
async fn portable_cache_rejects_restore_when_runtime_changes_during_download() {
    let (registry, artifacts) = remote_cache().await;
    let producer = project(&registry, true);
    let consumer = project(&registry, true);
    build(&producer);
    let (binary, path) = copied_node_path(&consumer);
    *artifacts.1.lock().unwrap() = Some(RuntimeMutation::TouchMetadata(binary));
    build_with_path(&consumer, &path);
    assert!(
        artifacts.1.lock().unwrap().is_none(),
        "the keyed remote artifact must have been requested"
    );
    assert!(
        consumer.file_exists("executed-marker"),
        "runtime mutation must reject the prepared hit"
    );
    let requests = registry.server().received_requests().await.unwrap();
    let uploads = requests
        .iter()
        .filter(|request| {
            request.method == "PUT" && request.url.path().starts_with("/v8/artifacts/")
        })
        .count();
    assert_eq!(uploads, 1, "a changed execution context must not publish");
}

#[tokio::test]
async fn portable_cache_rejects_restore_when_a_new_project_bin_changes_runtime_selection() {
    let (registry, artifacts) = remote_cache().await;
    let producer = project(&registry, true);
    let consumer = project(&registry, true);
    for project in [&producer, &consumer] {
        let mut config: serde_json::Value =
            serde_json::from_str(&project.read_file("lpm.json")).unwrap();
        config["tasks"]["build"]["inputs"] = serde_json::json!(["build.js", "src/**"]);
        project.write_file("lpm.json", &config.to_string());
    }
    build(&producer);
    let (node, _) = copied_node_path(&consumer);
    *artifacts.1.lock().unwrap() = Some(RuntimeMutation::AddProjectLauncher {
        project: consumer.path().to_path_buf(),
        node,
    });
    build(&consumer);
    assert!(artifacts.1.lock().unwrap().is_none());
    assert!(
        consumer.file_exists("executed-marker"),
        "a new effective runtime selection must reject the prepared hit"
    );
    assert!(
        consumer.file_exists("runtime-marker"),
        "execution must select the new project launcher"
    );
    let requests = registry.server().received_requests().await.unwrap();
    let uploads = requests
        .iter()
        .filter(|request| {
            request.method == "PUT" && request.url.path().starts_with("/v8/artifacts/")
        })
        .count();
    assert_eq!(uploads, 1, "a stale runtime selection must not publish");
}

#[cfg(unix)]
#[tokio::test]
async fn portable_cache_keeps_opaque_launchers_location_sensitive() {
    use std::os::unix::fs::PermissionsExt;
    let (registry, artifacts) = remote_cache().await;
    let producer = project(&registry, true);
    let consumer = project(&registry, true);
    let node = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .unwrap();
    let node_path = String::from_utf8(node.stdout).unwrap();
    for project in [&producer, &consumer] {
        let bin = project.home().join("launcher/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let launcher = bin.join("node");
        std::fs::write(
            &launcher,
            format!(
                "#!/bin/sh\nexec '{}' \"$@\"\n",
                node_path.trim().replace('\'', "'\"'\"'")
            ),
        )
        .unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths(
            std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        build_with_path(project, &path);
        assert!(project.file_exists("executed-marker"));
        std::fs::remove_file(project.path().join("executed-marker")).unwrap();
        build_with_path(project, &path);
        assert!(
            !project.file_exists("executed-marker"),
            "unchanged local launcher must retain local cache reuse"
        );
    }
    assert_eq!(artifacts.0.lock().unwrap().len(), 2);
}
