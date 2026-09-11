//! Lifecycle capability and execution-lifetime contracts against the real CLI.
#![cfg(unix)]

mod support;

use std::path::PathBuf;
use std::process::{Child, Output, Stdio};
use std::time::{Duration, Instant};
use support::{TempProject, lpm, lpm_spawnable, write_signed_unlock};

const PACKAGE: &str = "lifecycle-probe";

struct Fixture {
    project: TempProject,
    package: PathBuf,
    store: PathBuf,
}

impl Fixture {
    fn new(script: &str, capabilities: serde_json::Value) -> Self {
        let home = std::env::var_os("HOME").expect("HOME for filesystem fixture");
        Self::new_in(std::path::Path::new(&home), script, capabilities)
    }

    fn new_in(parent: &std::path::Path, script: &str, capabilities: serde_json::Value) -> Self {
        let project = TempProject::empty_in(
            parent,
            &serde_json::json!({
                "name": "lifecycle-test", "version": "1.0.0",
                "lpm": { "scripts": capabilities }
            })
            .to_string(),
        );
        project.write_file("lpm.lock", &format!(
            "[metadata]\nlockfile-version = 2\nresolved-with = \"pubgrub\"\n\n[[packages]]\nname = \"{PACKAGE}\"\nversion = \"1.0.0\"\n"
        ));
        let store = project
            .store_dir()
            .join("v1")
            .join(format!("{PACKAGE}@1.0.0"));
        let package = project.path().join(format!(
            ".lpm/wrappers/{PACKAGE}@1.0.0/node_modules/{PACKAGE}"
        ));
        support::build_state::seed_blocked_build_state_with_real_hash(&project, PACKAGE, "1.0.0");
        for path in [&store, &package] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(
                path.join("package.json"),
                serde_json::json!({
                    "name": PACKAGE, "version": "1.0.0", "scripts": {"postinstall": "node probe.js"}
                })
                .to_string(),
            )
            .unwrap();
            std::fs::write(path.join(".integrity"), "sha512-fixture-skip-verify").unwrap();
            std::fs::write(path.join("probe.js"), script).unwrap();
        }
        let mut state: serde_json::Value =
            serde_json::from_str(&project.read_file(".lpm/build-state.json")).unwrap();
        state["blocked_packages"][0]["script_hash"] =
            serde_json::json!(lpm_security::script_hash::compute_script_hash(&store).unwrap());
        project.write_file(".lpm/build-state.json", &state.to_string());
        support::build_state::authenticate_project_build_state(&project);
        write_signed_unlock(
            &project,
            &["capability-widen", "scripts-allow", "trust-bulk-approve"],
        );
        let output = lpm(&project)
            .args(["approve-scripts", PACKAGE])
            .output()
            .unwrap();
        assert_success(&output);
        Self {
            project,
            package,
            store,
        }
    }

    fn result(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.package.join("result.json")).unwrap()).unwrap()
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

const READ_PROBE: &str = r#"
const fs=require('fs'), p=require('path'), result={};
for (const name of ['package.json','tsconfig.json','plain.txt','.env','.env.preview','config/.env','apps/web/.npmrc']) {
    try { fs.readFileSync(p.join(process.env.INIT_CWD,name)); result[name]=true }
    catch(e) { result[name]=e.code }
}
fs.writeFileSync('result.json',JSON.stringify(result));
"#;

fn read_probe(mode: &str) -> serde_json::Value {
    let fixture = Fixture::new(READ_PROBE, serde_json::json!({"readProject":mode}));
    for name in [
        "tsconfig.json",
        "plain.txt",
        ".env",
        ".env.preview",
        "config/.env",
        "apps/web/.npmrc",
    ] {
        fixture.project.write_file(name, "DUMMY ONLY");
    }
    assert_success(&lpm(&fixture.project).arg("rebuild").output().unwrap());
    fixture.result()
}

#[test]
fn narrow_project_reads_allow_build_metadata_but_deny_source_and_secrets() {
    let result = read_probe("narrow");
    assert_eq!(result["package.json"], true);
    assert_eq!(result["tsconfig.json"], true);
    for name in [
        "plain.txt",
        ".env",
        ".env.preview",
        "config/.env",
        "apps/web/.npmrc",
    ] {
        assert!(
            matches!(result[name].as_str(), Some("EPERM" | "EACCES")),
            "{name} must be denied: {result}"
        );
    }
}

#[test]
fn approved_full_project_reads_include_explicitly_authorized_secrets() {
    let result = read_probe("full");
    for name in [
        "plain.txt",
        ".env",
        ".env.preview",
        "config/.env",
        "apps/web/.npmrc",
    ] {
        assert_eq!(
            result[name], true,
            "full project access must include {name}: {result}"
        );
    }
}

#[test]
fn lifecycle_environment_contains_only_baseline_and_approved_names() {
    let fixture = Fixture::new(
        r#"
const keys=['PATH','INIT_CWD','QA_APPROVED_TOKEN','QA_UNDECLARED','PASSWORD','TOKEN','AUTHORIZATION','NODE_OPTIONS'];
require('fs').writeFileSync('result.json',JSON.stringify(Object.fromEntries(keys.map(k=>[k,process.env[k]??null]))));
"#,
        serde_json::json!({"passEnv":["QA_APPROVED_TOKEN"]}),
    );
    let mut command = lpm(&fixture.project);
    command.arg("rebuild");
    for name in [
        "QA_APPROVED_TOKEN",
        "QA_UNDECLARED",
        "PASSWORD",
        "TOKEN",
        "AUTHORIZATION",
    ] {
        command.env(name, "DUMMY ONLY");
    }
    command.env("NODE_OPTIONS", "--no-warnings");
    assert_success(&command.output().unwrap());
    let result = fixture.result();
    assert_eq!(
        result["QA_APPROVED_TOKEN"], "DUMMY ONLY",
        "approved value: {result}"
    );
    assert!(result["PATH"].is_string());
    assert!(result["INIT_CWD"].is_string());
    for name in [
        "QA_UNDECLARED",
        "PASSWORD",
        "TOKEN",
        "AUTHORIZATION",
        "NODE_OPTIONS",
    ] {
        assert!(result[name].is_null(), "undeclared {name} leaked: {result}");
    }
}

struct ProcessGuard(u32);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        // SAFETY: this PID belongs to a bounded fixture child, retained until cleanup.
        unsafe {
            libc::kill(self.0 as i32, libc::SIGKILL);
        }
    }
}

fn wait_for_file(path: &std::path::Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && !text.is_empty()
        {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "fixture did not become ready: {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn detached_probe(reparent: bool) {
    let leaf = "setTimeout(()=>require('fs').writeFileSync('late.txt','survived'),1800);setTimeout(()=>process.exit(0),2800)";
    let spawn = format!(
        "const fs=require('fs'), c=require('child_process').spawn(process.execPath,['-e',{}],{{detached:true,stdio:'ignore'}});c.on('error',e=>fs.writeFileSync('child.pid',e.code));if(c.pid)fs.writeFileSync('child.pid',String(c.pid));c.unref();",
        serde_json::to_string(leaf).unwrap()
    );
    let script = if reparent {
        format!(
            "require('child_process').spawnSync(process.execPath,['-e',{}],{{stdio:'ignore'}});setTimeout(()=>process.exit(0),4000);",
            serde_json::to_string(&spawn).unwrap()
        )
    } else {
        spawn
    };
    let fixture = Fixture::new(&script, serde_json::json!({}));
    let output = lpm(&fixture.project)
        .args(["rebuild", "--timeout", "1"])
        .output()
        .unwrap();
    let child_state = wait_for_file(&fixture.package.join("child.pid"));
    let _guard = match child_state.parse() {
        Ok(pid) => Some(ProcessGuard(pid)),
        Err(_) => {
            assert!(matches!(child_state.as_str(), "EPERM" | "EACCES"));
            None
        }
    };
    if reparent {
        assert!(!output.status.success());
    } else {
        assert_success(&output);
    }
    std::thread::sleep(Duration::from_millis(2000));
    assert!(
        !fixture.package.join("late.txt").exists(),
        "descendant survived lifecycle completion (reparent={reparent})"
    );
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "macOS native compatibility permits detached descendants; see sandbox limitations"
)]
fn successful_lifecycle_terminates_detached_children() {
    detached_probe(false);
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "macOS native compatibility permits reparented descendants; see sandbox limitations"
)]
fn timed_out_lifecycle_terminates_reparented_grandchildren() {
    detached_probe(true);
}

fn interrupt_probe(signal: i32) {
    let fixture = Fixture::new(
        r#"
const fs=require('fs');fs.writeFileSync('ready.pid',String(process.pid));
setTimeout(()=>fs.writeFileSync('late.txt','not cancelled'),1800);
setTimeout(()=>process.exit(0),4000);
"#,
        serde_json::json!({}),
    );
    let mut child: Child = lpm_spawnable(&fixture.project)
        .args(["rebuild", "--timeout", "8"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _cli_guard = ProcessGuard(child.id());
    let pid = wait_for_file(&fixture.package.join("ready.pid"))
        .parse()
        .unwrap();
    let _script_guard = ProcessGuard(pid);
    let start = Instant::now();
    // SAFETY: signal only the CLI subprocess created by this test.
    assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(6),
            "CLI ignored cancellation"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        !status.success(),
        "interrupted lifecycle reported success for signal {signal}"
    );
    assert!(
        start.elapsed() < Duration::from_millis(1500),
        "cancellation waited for script completion"
    );
    std::thread::sleep(Duration::from_millis(1900));
    assert!(!fixture.package.join("late.txt").exists());
    assert!(!fixture.store.join(".lpm-built").exists());
    assert!(!fixture.package.join(".lpm-built").exists());
}

#[test]
fn sigint_cancels_lifecycle_without_recording_success() {
    interrupt_probe(libc::SIGINT);
}

#[test]
fn sigterm_cancels_lifecycle_without_recording_success() {
    interrupt_probe(libc::SIGTERM);
}

#[test]
fn narrow_project_under_system_temp_does_not_inherit_scratch_access() {
    let fixture = Fixture::new_in(&std::env::temp_dir(), READ_PROBE, serde_json::json!({}));
    fixture.project.write_file("plain.txt", "DUMMY ONLY");
    assert_success(
        &lpm(&fixture.project)
            .arg("rebuild")
            .env("TMPDIR", std::env::temp_dir())
            .output()
            .unwrap(),
    );
    assert!(matches!(
        fixture.result()["plain.txt"].as_str(),
        Some("EPERM" | "EACCES")
    ));
}

#[test]
fn changing_read_allow_requires_new_approval() {
    changed_path_request_requires_approval("sandboxReadAllow", "plain.txt");
}

#[test]
fn changing_write_dirs_requires_new_approval() {
    changed_path_request_requires_approval("sandboxWriteDirs", "output");
}

fn changed_path_request_requires_approval(field: &str, path: &str) {
    let fixture = Fixture::new(READ_PROBE, serde_json::json!({}));
    fixture.project.write_file("plain.txt", "DUMMY ONLY");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fixture.project.read_file("package.json")).unwrap();
    manifest["lpm"]["scripts"][field] = serde_json::json!([path]);
    fixture
        .project
        .write_file("package.json", &manifest.to_string());
    std::fs::remove_dir_all(fixture.project.home().join(".lpm/security/unlocks")).unwrap();
    let output = lpm(&fixture.project).arg("rebuild").output().unwrap();
    assert!(
        !output.status.success(),
        "unapproved path request ran: {:?}",
        output
    );
    assert!(!fixture.package.join("result.json").exists());
}

#[test]
fn approved_file_and_output_directory_grants_are_enforced() {
    let fixture = Fixture::new(
        r#"const fs=require('fs'),p=require('path'),root=process.env.INIT_CWD;
fs.writeFileSync(p.join(root,'output/result.txt'),'output');
fs.writeFileSync('result.json',JSON.stringify({secret:fs.readFileSync(p.join(root,'.env'),'utf8'),output:fs.readFileSync(p.join(root,'output/result.txt'),'utf8')}));"#,
        serde_json::json!({"sandboxReadAllow":[".env"],"sandboxWriteDirs":["output"]}),
    );
    fixture.project.write_file(".env", "DUMMY ONLY");
    assert_success(&lpm(&fixture.project).arg("rebuild").output().unwrap());
    assert_eq!(
        fixture.result(),
        serde_json::json!({"secret":"DUMMY ONLY","output":"output"})
    );
}

#[test]
fn changed_global_read_request_requires_new_approval() {
    let fixture = Fixture::new(READ_PROBE, serde_json::json!({}));
    fixture.project.write_file("plain.txt", "DUMMY ONLY");
    std::fs::write(
        fixture.project.home().join(".lpm/config.toml"),
        "script-read-allow = [\"plain.txt\"]\n",
    )
    .unwrap();
    std::fs::remove_dir_all(fixture.project.home().join(".lpm/security/unlocks")).unwrap();
    let output = lpm(&fixture.project).arg("rebuild").output().unwrap();
    assert!(
        !output.status.success(),
        "unapproved global read ran: {output:?}"
    );
    assert!(!fixture.package.join("result.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_install_preserves_manifest_and_user_files_and_retry_builds() {
    let registry = support::mock_registry::MockRegistry::start().await;
    registry.with_manifest_package(serde_json::json!({
        "name": PACKAGE, "version":"1.0.0", "scripts":{"postinstall":"node probe.js"}
    }), &[("probe.js", br#"const fs=require('fs');fs.writeFileSync('ready.pid',String(process.pid));setTimeout(()=>fs.writeFileSync('finished.txt','usable'),2400);"#)]).await;
    let project = TempProject::empty(r#"{"name":"cancel-install","version":"1.0.0"}"#);
    project.write_file("user.txt", "preserve me");
    let before = project.read_file("package.json");
    write_signed_unlock(&project, &["scripts-allow"]);
    let args = [
        "install",
        PACKAGE,
        "--policy",
        "allow",
        "--no-skills",
        "--no-editor-setup",
    ];
    let mut child = support::lpm_spawnable_with_registry(&project, &registry.url())
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _cli_guard = ProcessGuard(child.id());
    let package = project.path().join("node_modules").join(PACKAGE);
    let pid = wait_for_file(&package.join("ready.pid")).parse().unwrap();
    let _script_guard = ProcessGuard(pid);
    // SAFETY: signal only the test's CLI process after its script starts.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(6),
            "cancelled install did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(!status.success());
    assert_eq!(project.read_file("package.json"), before);
    assert_eq!(project.read_file("user.txt"), "preserve me");
    assert!(!project.path().join("lpm.lock").exists());
    assert!(!package.join(".lpm-built").exists());
    assert!(!package.join("finished.txt").exists());
    let retry = support::lpm_with_registry(&project, &registry.url())
        .args(args)
        .output()
        .unwrap();
    assert_success(&retry);
    assert_eq!(
        std::fs::read_to_string(package.join("finished.txt")).unwrap(),
        "usable"
    );
    assert!(package.join(".lpm-built").exists());
    assert_eq!(project.read_file("user.txt"), "preserve me");
}

#[test]
fn no_sandbox_explicitly_allows_symlinked_project_directories() {
    let fixture = Fixture::new(
        "require('fs').writeFileSync('result.json','true')",
        serde_json::json!({}),
    );
    write_signed_unlock(&fixture.project, &["sandbox-none"]);
    let outside = tempfile::tempdir().unwrap();
    let husky = fixture.project.path().join(".husky");
    if husky.exists() {
        std::fs::remove_dir(&husky).unwrap();
    }
    std::os::unix::fs::symlink(outside.path(), husky).unwrap();
    let output = lpm(&fixture.project)
        .args(["rebuild", "--no-sandbox"])
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(fixture.result(), true);
}
