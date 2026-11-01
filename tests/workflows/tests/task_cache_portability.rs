//! Task-cache keys that two machines share: checkouts at other paths, separate
//! LPM homes, and the same runtime version installed elsewhere.
//!
//! Each `TempProject` has its own directory and home, so a producer and a
//! consumer stand in for two machines that share one remote cache.

mod support;

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use support::{TempProject, lpm};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[derive(Clone)]
struct Artifact {
    bytes: Vec<u8>,
    tag: String,
    sha: String,
}

/// A change the cache server makes to the consumer's machine while it serves a
/// stored artifact, to race the restore.
enum MidDownloadChange {
    TouchRuntime(PathBuf),
    AddProjectNode { project: PathBuf, node: PathBuf },
}

#[derive(Clone, Default)]
struct RemoteCache {
    artifacts: Arc<Mutex<HashMap<String, Artifact>>>,
    mid_download: Arc<Mutex<Option<MidDownloadChange>>>,
}

impl RemoteCache {
    async fn start() -> (MockServer, Self) {
        let server = MockServer::start().await;
        let cache = Self::default();
        for verb in ["GET", "PUT"] {
            Mock::given(method(verb))
                .and(path_regex(r"^/v8/artifacts/[a-fA-F0-9]+$"))
                .respond_with(cache.clone())
                .mount(&server)
                .await;
        }
        (server, cache)
    }

    fn stored(&self) -> usize {
        self.artifacts.lock().unwrap().len()
    }

    fn change_mid_download(&self, change: MidDownloadChange) {
        *self.mid_download.lock().unwrap() = Some(change);
    }

    fn mid_download_change_happened(&self) -> bool {
        self.mid_download.lock().unwrap().is_none()
    }
}

impl Respond for RemoteCache {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut artifacts = self.artifacts.lock().unwrap();
        let key = request.url.path().to_string();
        if request.method == "PUT" {
            let header = |name: &str| request.headers[name].to_str().unwrap().to_string();
            artifacts.insert(
                key,
                Artifact {
                    bytes: request.body.clone(),
                    tag: header("x-artifact-tag"),
                    sha: header("x-artifact-sha"),
                },
            );
            return ResponseTemplate::new(200).set_body_json(serde_json::json!({"urls": []}));
        }
        if artifacts.contains_key(&key)
            && let Some(change) = self.mid_download.lock().unwrap().take()
        {
            match change {
                MidDownloadChange::TouchRuntime(binary) => {
                    let modified = binary.metadata().unwrap().modified().unwrap()
                        + std::time::Duration::from_secs(10);
                    std::fs::File::options()
                        .write(true)
                        .open(binary)
                        .unwrap()
                        .set_times(std::fs::FileTimes::new().set_modified(modified))
                        .unwrap();
                }
                MidDownloadChange::AddProjectNode { project, node } => {
                    write_launcher(
                        &project.join("node_modules/.bin"),
                        &node,
                        LauncherVersion::Real,
                        Some("runtime-marker"),
                    );
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

const BUILD_SCRIPT: &str = "const fs=require('fs'); fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('dist/value.txt',fs.readFileSync('src/value.txt')); fs.writeFileSync('executed-marker','ran'); fs.writeFileSync('context.json',JSON.stringify({manifest:process.env.npm_package_json,cwd:process.env.INIT_CWD}));";

fn checkout(server: &MockServer, cache_portable: Option<bool>) -> TempProject {
    let project = TempProject::empty(
        r#"{"name":"portable-build","version":"1.0.0","scripts":{"build":"node build.js"}}"#,
    );
    project.write_file("build.js", BUILD_SCRIPT);
    project.write_file("src/value.txt", "portable-output");
    let mut task = serde_json::json!({"cache": true, "cacheEnv": [], "outputs": ["dist/**"]});
    if let Some(portable) = cache_portable {
        task["cachePortable"] = portable.into();
    }
    project.write_file(
        "lpm.json",
        &serde_json::json!({
            "remoteCache": {"enabled": true, "url": format!("{}/v8", server.uri())},
            "tasks": {"build": task},
        })
        .to_string(),
    );
    project
}

fn edit_task(project: &TempProject, edit: impl FnOnce(&mut serde_json::Value)) {
    let mut config: serde_json::Value =
        serde_json::from_str(&project.read_file("lpm.json")).unwrap();
    edit(&mut config["tasks"]["build"]);
    project.write_file("lpm.json", &config.to_string());
}

fn run_build(project: &TempProject, path: Option<&OsString>, envs: &[(&str, &str)]) -> String {
    let mut command = lpm(project);
    command
        .env("LPM_REMOTE_CACHE_TOKEN", "remote-token")
        .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key")
        .args(["run", "build"]);
    if let Some(path) = path {
        command.env("PATH", path);
    }
    for (name, value) in envs {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "lpm run build failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    format!("{stdout}{stderr}")
}

fn build(project: &TempProject) -> String {
    run_build(project, None, &[])
}

fn executed(project: &TempProject) -> bool {
    project.file_exists("executed-marker")
}

fn forget_execution(project: &TempProject) {
    std::fs::remove_file(project.path().join("executed-marker")).unwrap();
}

fn real_node() -> PathBuf {
    let output = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .unwrap();
    assert!(output.status.success());
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

fn path_with(bin: &Path) -> OsString {
    std::env::join_paths(
        std::iter::once(bin.to_path_buf())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap()
}

/// Copy the Node binary into this machine's home, so each machine runs the
/// same release from its own path and inode.
fn install_node_copy(project: &TempProject) -> (PathBuf, OsString) {
    let bin = project.home().join("runtime/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let executable = bin.join(if cfg!(windows) { "node.exe" } else { "node" });
    std::fs::copy(real_node(), &executable).unwrap();
    (executable, path_with(&bin))
}

enum LauncherVersion {
    Real,
    #[cfg(unix)]
    Reports(&'static str),
}

/// A version-manager-style launcher: a small script named `node` that runs
/// the real binary, optionally reporting another version to `--version`.
fn write_launcher(bin: &Path, node: &Path, version: LauncherVersion, marker: Option<&str>) {
    std::fs::create_dir_all(bin).unwrap();
    let node = node.to_str().unwrap();
    let launcher = bin.join(if cfg!(windows) { "node.cmd" } else { "node" });
    let content = if cfg!(windows) {
        let marker = marker
            .map(|marker| format!("> {marker} echo selected\r\n"))
            .unwrap_or_default();
        format!(
            "@echo off\r\n{marker}\"{}\" %*\r\n",
            node.replace('%', "%%")
        )
    } else {
        let marker = marker
            .map(|marker| format!("printf selected > {marker}\n"))
            .unwrap_or_default();
        let version = match version {
            LauncherVersion::Real => String::new(),
            #[cfg(unix)]
            LauncherVersion::Reports(version) => {
                format!("if [ \"$1\" = --version ]; then echo {version}; exit 0; fi\n")
            }
        };
        format!(
            "#!/bin/sh\n{version}{marker}exec '{}' \"$@\"\n",
            node.replace('\'', "'\"'\"'")
        )
    };
    std::fs::write(&launcher, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn uploads(requests: &[Request]) -> usize {
    requests
        .iter()
        .filter(|request| request.method == "PUT")
        .count()
}

#[tokio::test]
async fn remote_cache_restores_a_task_in_a_checkout_at_another_path_and_home() {
    let (server, cache) = RemoteCache::start().await;
    let producer = checkout(&server, None);
    let consumer = checkout(&server, None);

    build(&producer);
    assert!(executed(&producer));
    assert_eq!(cache.stored(), 1);
    let context: serde_json::Value =
        serde_json::from_str(&producer.read_file("context.json")).unwrap();
    assert_eq!(
        Path::new(context["manifest"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        producer.path().join("package.json").canonicalize().unwrap(),
        "the task still sees its real manifest path"
    );
    assert_eq!(
        Path::new(context["cwd"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        producer.path().canonicalize().unwrap(),
        "the task still sees its real INIT_CWD"
    );

    build(&consumer);
    assert_eq!(consumer.read_file("dist/value.txt"), "portable-output");
    assert!(
        !executed(&consumer),
        "a checkout at another path must restore the producer's artifact"
    );
    assert_eq!(cache.stored(), 1, "both checkouts must use one cache key");
}

#[tokio::test]
async fn remote_cache_restores_with_the_same_node_release_installed_elsewhere() {
    let (server, cache) = RemoteCache::start().await;
    let producer = checkout(&server, None);
    let consumer = checkout(&server, None);
    for project in [&producer, &consumer] {
        let (_, path) = install_node_copy(project);
        run_build(project, Some(&path), &[]);
    }
    assert!(
        !executed(&consumer),
        "the same Node release at another path and inode must share the key"
    );
    assert_eq!(cache.stored(), 1);
}

#[tokio::test]
async fn cache_portable_false_ties_entries_to_the_checkout_path() {
    let (server, cache) = RemoteCache::start().await;
    let producer = checkout(&server, Some(false));
    let consumer = checkout(&server, Some(false));
    build(&producer);
    build(&consumer);
    assert!(executed(&consumer));
    assert_eq!(cache.stored(), 2);

    forget_execution(&consumer);
    build(&consumer);
    assert!(
        !executed(&consumer),
        "a non-portable task still hits its own checkout's cache"
    );
}

#[tokio::test]
async fn portable_cache_key_still_tracks_sources_and_cache_env() {
    let (server, cache) = RemoteCache::start().await;
    let producer = checkout(&server, None);
    let consumer = checkout(&server, None);
    for project in [&producer, &consumer] {
        edit_task(project, |task| {
            task["cacheEnv"] = serde_json::json!(["BUILD_TARGET"]);
        });
    }

    run_build(&producer, None, &[("BUILD_TARGET", "web")]);
    run_build(&consumer, None, &[("BUILD_TARGET", "web")]);
    assert!(!executed(&consumer));

    run_build(&consumer, None, &[("BUILD_TARGET", "mobile")]);
    assert!(executed(&consumer), "a cacheEnv value change must miss");

    forget_execution(&consumer);
    consumer.write_file("src/value.txt", "changed-output");
    run_build(&consumer, None, &[("BUILD_TARGET", "mobile")]);
    assert_eq!(consumer.read_file("dist/value.txt"), "changed-output");
    assert!(executed(&consumer), "a source change must miss");
    assert_eq!(cache.stored(), 3);
}

#[cfg(unix)]
#[tokio::test]
async fn portable_cache_key_follows_the_version_a_version_manager_shim_reports() {
    let (server, cache) = RemoteCache::start().await;
    let node = real_node();
    let producer = checkout(&server, None);
    let same_version = checkout(&server, None);
    let other_version = checkout(&server, None);
    for (project, version) in [
        (&producer, "v99.1.0"),
        (&same_version, "v99.1.0"),
        (&other_version, "v99.2.0"),
    ] {
        // Each machine's HOME is its own, so each has its own asdf shims.
        let shims = project.home().join(".asdf/shims");
        write_launcher(&shims, &node, LauncherVersion::Reports(version), None);
        run_build(project, Some(&path_with(&shims)), &[]);
    }
    assert!(executed(&producer));
    assert!(
        !executed(&same_version),
        "shims on other machines that select the same version must share the key"
    );
    assert!(
        executed(&other_version),
        "a shim that selects another version must miss"
    );
    assert_eq!(cache.stored(), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn other_launchers_keep_task_cache_entries_on_their_machine() {
    let (server, cache) = RemoteCache::start().await;
    let node = real_node();
    let producer = checkout(&server, None);
    let consumer = checkout(&server, None);
    for project in [&producer, &consumer] {
        let bin = project.home().join("launcher/bin");
        write_launcher(&bin, &node, LauncherVersion::Real, None);
        let path = path_with(&bin);
        run_build(project, Some(&path), &[]);
        assert!(
            executed(project),
            "a launcher that is not a version manager's shim must not share entries"
        );
        forget_execution(project);
        run_build(project, Some(&path), &[]);
        assert!(
            !executed(project),
            "an unchanged launcher still reuses its own machine's entry"
        );
    }
    assert_eq!(cache.stored(), 2);
}

#[tokio::test]
async fn portable_workspace_cache_restores_prerequisites_in_another_checkout() {
    for flags in [
        &[][..],
        &["--parallel"][..],
        &["--stream"][..],
        &["--json"][..],
    ] {
        let (server, cache) = RemoteCache::start().await;
        let producer = checkout(&server, None);
        let consumer = checkout(&server, None);
        for project in [&producer, &consumer] {
            project.write_file(
                "package.json",
                r#"{"name":"workspace","private":true,"workspaces":["packages/*"]}"#,
            );
            for (name, dependencies) in [
                ("lib", serde_json::json!({})),
                ("app", serde_json::json!({"lib": "workspace:*"})),
            ] {
                project.write_file(
                    &format!("packages/{name}/package.json"),
                    &serde_json::json!({
                        "name": name,
                        "version": "1.0.0",
                        "dependencies": dependencies,
                        "scripts": {"build": "node build.js"},
                    })
                    .to_string(),
                );
                project.write_file(&format!("packages/{name}/build.js"), BUILD_SCRIPT);
                project.write_file(&format!("packages/{name}/src/value.txt"), name);
            }
            edit_task(project, |task| {
                task["dependsOn"] = serde_json::json!(["^build"]);
            });
            project.write_file("packages/app/lpm.json", &project.read_file("lpm.json"));
            edit_task(project, |task| {
                task["dependsOn"] = serde_json::json!([]);
            });
            project.write_file("packages/lib/lpm.json", &project.read_file("lpm.json"));
        }
        let run = |project: &TempProject| {
            lpm(project)
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
        assert_eq!(cache.stored(), 2);

        consumer.write_file("packages/lib/src/value.txt", "changed-lib");
        run(&consumer);
        assert!(consumer.file_exists("packages/lib/executed-marker"));
        assert!(
            consumer.file_exists("packages/app/executed-marker"),
            "an upstream change must invalidate app with {flags:?}"
        );
        assert_eq!(cache.stored(), 4);
    }
}

#[tokio::test]
async fn remote_restore_is_rejected_when_the_runtime_changes_during_download() {
    let (server, cache) = RemoteCache::start().await;
    let producer = checkout(&server, None);
    let consumer = checkout(&server, None);
    build(&producer);

    let (binary, path) = install_node_copy(&consumer);
    cache.change_mid_download(MidDownloadChange::TouchRuntime(binary));
    run_build(&consumer, Some(&path), &[]);
    assert!(
        cache.mid_download_change_happened(),
        "the consumer must have requested the stored artifact"
    );
    assert!(
        executed(&consumer),
        "a runtime change during the download must reject the hit"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        uploads(&requests),
        1,
        "a run whose runtime changed must not publish"
    );
}

#[tokio::test]
async fn remote_restore_is_rejected_when_a_new_project_node_changes_the_runtime() {
    let (server, cache) = RemoteCache::start().await;
    let producer = checkout(&server, None);
    let consumer = checkout(&server, None);
    for project in [&producer, &consumer] {
        edit_task(project, |task| {
            task["inputs"] = serde_json::json!(["build.js", "src/**"]);
        });
    }
    build(&producer);

    cache.change_mid_download(MidDownloadChange::AddProjectNode {
        project: consumer.path().to_path_buf(),
        node: real_node(),
    });
    build(&consumer);
    assert!(cache.mid_download_change_happened());
    assert!(
        executed(&consumer),
        "a new runtime selection during the download must reject the hit"
    );
    assert!(
        consumer.file_exists("runtime-marker"),
        "the task must run with the newly selected node"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        uploads(&requests),
        1,
        "a run whose runtime selection changed must not publish"
    );
}

#[tokio::test]
async fn remote_cache_warns_once_about_cached_tasks_without_cache_env() {
    let (server, _cache) = RemoteCache::start().await;
    let project = checkout(&server, None);
    project.write_file(
        "package.json",
        r#"{"name":"portable-build","version":"1.0.0","scripts":{"build":"node build.js","gen":"node build.js"}}"#,
    );
    let mut config: serde_json::Value =
        serde_json::from_str(&project.read_file("lpm.json")).unwrap();
    for task in ["build", "gen"] {
        config["tasks"][task] = serde_json::json!({"cache": true, "outputs": ["dist/**"]});
    }
    config["tasks"]["build"]["dependsOn"] = serde_json::json!(["gen"]);
    project.write_file("lpm.json", &config.to_string());

    let output = build(&project);
    assert_eq!(
        output.matches("has no cacheEnv").count(),
        1,
        "two tasks without cacheEnv must give one hint, got:\n{output}"
    );
    assert!(output.contains("tasks.gen.cacheEnv"), "{output}");

    for task in ["build", "gen"] {
        config["tasks"][task]["cacheEnv"] = serde_json::json!([]);
    }
    project.write_file("lpm.json", &config.to_string());
    let output = build(&project);
    assert!(
        !output.contains("has no cacheEnv"),
        "tasks with cacheEnv get no hint:\n{output}"
    );

    for task in ["build", "gen"] {
        let task = config["tasks"][task].as_object_mut().unwrap();
        task.remove("cacheEnv");
        task.insert("cachePortable".into(), false.into());
    }
    project.write_file("lpm.json", &config.to_string());
    let output = build(&project);
    assert!(
        !output.contains("has no cacheEnv"),
        "a task that doesn't share its entries gets no hint:\n{output}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_version_manager_variable_from_the_project_env_selects_what_the_key_names() {
    let (server, cache) = RemoteCache::start().await;
    let node = real_node();
    let producer = checkout(&server, None);
    let consumer = checkout(&server, None);
    for (project, release) in [(&producer, "A"), (&consumer, "B")] {
        // Each machine resolves NODENV_VERSION=18 to a release of its own.
        let shims = project.home().join(".asdf/shims");
        std::fs::create_dir_all(&shims).unwrap();
        let shim = shims.join("node");
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\nif [ -n \"$NODENV_VERSION\" ]; then v=\"v$NODENV_VERSION.0.{release}\"; else v=v99.0.0; fi\nif [ \"$1\" = --version ]; then echo \"$v\" | tr AB 12; exit 0; fi\nexec '{}' \"$@\"\n",
                node.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        project.write_file(".env", "NODENV_VERSION=18\n");
        run_build(project, Some(&path_with(&shims)), &[]);
    }
    assert!(
        executed(&consumer),
        "machines whose project env selects different releases must not share the key"
    );
    assert_eq!(cache.stored(), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn bun_installed_from_npm_keeps_task_keys_portable() {
    let (server, cache) = RemoteCache::start().await;
    let producer = checkout(&server, None);
    let consumer = checkout(&server, None);
    for project in [&producer, &consumer] {
        // The npm package installs bin/bun.exe on every platform; a copy of
        // the Node binary stands in for it, as a real native executable.
        let package = project.path().join("node_modules/bun/bin");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::copy(real_node(), package.join("bun.exe")).unwrap();
        let bin = project.path().join("node_modules/.bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink("../bun/bin/bun.exe", bin.join("bun")).unwrap();
        build(project);
    }
    assert!(
        !executed(&consumer),
        "a Bun binary named bun.exe must be identified by version"
    );
    assert_eq!(cache.stored(), 1);
}

fn workspace_checkout(server: &MockServer) -> TempProject {
    let project = checkout(server, None);
    let config = project.read_file("lpm.json");
    project.write_file(
        "package.json",
        r#"{"name":"workspace","private":true,"workspaces":["packages/*"]}"#,
    );
    project.write_file(
        "packages/app/package.json",
        r#"{"name":"app","version":"1.0.0","scripts":{"build":"node build.js"}}"#,
    );
    project.write_file("packages/app/build.js", BUILD_SCRIPT);
    project.write_file("packages/app/src/value.txt", "app");
    project.write_file("packages/app/lpm.json", &config);
    project
}

fn lpm_in(project: &TempProject, dir: &str) -> assert_cmd::Command {
    let mut command = lpm(project);
    command
        .current_dir(project.path().join(dir))
        .env("LPM_REMOTE_CACHE_TOKEN", "remote-token")
        .env("LPM_REMOTE_CACHE_SIGNATURE_KEY", "signing-key");
    command
}

#[tokio::test]
async fn a_member_directory_run_shares_keys_with_a_filtered_run_from_the_root() {
    let (server, cache) = RemoteCache::start().await;
    let producer = workspace_checkout(&server);
    let consumer = workspace_checkout(&server);
    lpm_in(&producer, ".")
        .args(["run", "build", "--filter", "app"])
        .assert()
        .success();
    assert!(producer.file_exists("packages/app/executed-marker"));

    lpm_in(&consumer, "packages/app/src")
        .args(["run", "build"])
        .assert()
        .success();
    assert_eq!(consumer.read_file("packages/app/dist/value.txt"), "app");
    assert!(
        !consumer.file_exists("packages/app/executed-marker"),
        "a run from a member's subdirectory must restore the root run's artifact"
    );
    assert_eq!(cache.stored(), 1);
}

#[tokio::test]
async fn a_root_lockfile_change_invalidates_a_member_directory_run() {
    let (server, _cache) = RemoteCache::start().await;
    let project = workspace_checkout(&server);
    let run = || {
        lpm_in(&project, "packages/app")
            .args(["run", "build"])
            .env("LPM_REMOTE_CACHE", "0")
            .assert()
            .success();
    };
    project.write_file(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{}}"#,
    );
    run();
    std::fs::remove_file(project.path().join("packages/app/executed-marker")).unwrap();
    run();
    assert!(!project.file_exists("packages/app/executed-marker"));

    project.write_file(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}"#,
    );
    run();
    assert!(
        project.file_exists("packages/app/executed-marker"),
        "the workspace lockfile decides the member's dependencies, so it must be in the key"
    );
}

#[tokio::test]
async fn local_only_task_cache_gives_no_cache_env_hint() {
    let (server, _cache) = RemoteCache::start().await;
    let project = checkout(&server, None);
    edit_task(&project, |task| {
        task.as_object_mut().unwrap().remove("cacheEnv");
    });
    let output = run_build(&project, None, &[("LPM_REMOTE_CACHE", "0")]);
    assert!(!output.contains("has no cacheEnv"), "{output}");
}
