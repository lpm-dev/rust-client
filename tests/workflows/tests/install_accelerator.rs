mod support;

use support::{TempProject, lpm};

#[test]
fn install_accelerated_offline_fails_before_install_work() {
    let project = TempProject::empty(
        r#"{
        "name": "accelerated-offline",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["install", "--accelerated", "--offline"])
        .output()
        .expect("spawn lpm install --accelerated --offline");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`--accelerated`"), "stderr:\n{stderr}");
    assert!(stderr.contains("`--offline`"), "stderr:\n{stderr}");
}

#[test]
fn install_accelerated_without_login_fails_before_network() {
    let project = TempProject::empty(
        r#"{
        "name": "accelerated-no-login",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );

    let output = lpm(&project)
        .args(["install", "--accelerated"])
        .output()
        .expect("spawn lpm install --accelerated");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("authentication required") || stderr.contains("lpm login"),
        "stderr:\n{stderr}",
    );
}

#[test]
fn install_accelerated_rejects_custom_npmrc_registry() {
    let project = TempProject::empty(
        r#"{
        "name": "accelerated-custom-registry",
        "version": "1.0.0",
        "dependencies": {
            "ms": "^2.1.3"
        }
    }"#,
    );
    project.write_file(".npmrc", "registry=https://registry.internal.example/\n");

    let output = lpm(&project)
        .args(["install", "--accelerated"])
        .output()
        .expect("spawn lpm install --accelerated");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("custom `.npmrc` registries"),
        "stderr:\n{stderr}",
    );
}

#[test]
fn install_accelerated_rejects_package_add_before_auth() {
    let project = TempProject::empty(
        r#"{
        "name": "accelerated-add",
        "version": "1.0.0"
    }"#,
    );

    let output = lpm(&project)
        .args(["install", "ms", "--accelerated"])
        .output()
        .expect("spawn lpm install ms --accelerated");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bare project installs only"),
        "stderr:\n{stderr}",
    );
    assert!(
        !stderr.contains("authentication required") && !stderr.contains("lpm login"),
        "stderr:\n{stderr}",
    );
}
