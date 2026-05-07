mod support;

use lpm_common::LpmRoot;
use std::time::{Duration, SystemTime};
use support::{TempProject, lpm};

fn seed_dlx_cache(project: &TempProject, spec: &str) -> std::path::PathBuf {
    let root = LpmRoot::from_dir(project.home().join(".lpm"));
    let cache_dir = lpm_runner::dlx::dlx_cache_dir_at(&root, spec);
    let bin_dir = cache_dir.join("node_modules").join(".bin");
    std::fs::create_dir_all(&bin_dir).expect("failed to create dlx bin dir");
    std::fs::write(cache_dir.join("package.json"), r#"{"private":true}"#)
        .expect("failed to seed dlx package.json");
    cache_dir
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = std::fs::metadata(path)
        .expect("script must exist")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("failed to mark script executable");
}

#[test]
fn dlx_cache_hit_executes_cached_binary_and_refreshes_ttl() {
    let project = TempProject::empty(r#"{"name":"dlx-test","version":"1.0.0"}"#);
    let spec = "cowsay@1.0.0";
    let cache_dir = seed_dlx_cache(&project, spec);
    let bin_path = cache_dir.join("node_modules").join(".bin").join("cowsay");

    std::fs::write(
        &bin_path,
        "#!/bin/sh\nprintf 'cwd:%s\\nargs:%s\\n' \"$PWD\" \"$*\"\n",
    )
    .expect("failed to write cached dlx binary");
    #[cfg(unix)]
    make_executable(&bin_path);

    let package_json = cache_dir.join("package.json");
    let before = SystemTime::now() - Duration::from_secs(60);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&package_json)
        .expect("seeded package.json must exist");
    file.set_modified(before)
        .expect("failed to backdate package.json");

    let output = lpm(&project)
        .args(["dlx", spec, "--", "--loud", "hello"])
        .output()
        .expect("failed to run lpm dlx");

    assert!(
        output.status.success(),
        "lpm dlx failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected_cwd = project
        .path()
        .canonicalize()
        .expect("project path must canonicalize");
    assert!(
        stdout.contains(&format!("cwd:{}", expected_cwd.display())),
        "dlx must execute from the caller project directory, got:\n{stdout}"
    );
    assert!(
        stdout.contains("args:--loud hello"),
        "dlx must forward extra args to the cached binary, got:\n{stdout}"
    );

    let after = std::fs::metadata(&package_json)
        .expect("package.json must still exist")
        .modified()
        .expect("package.json mtime must be readable");
    assert!(
        after > before,
        "successful dlx invocations must refresh the cache mtime"
    );
}
