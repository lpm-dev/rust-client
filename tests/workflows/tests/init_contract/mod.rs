use super::blank_project_dir;
use crate::support::{TempProject, lpm_with_registry};

fn init(project: &TempProject, args: &[&str]) -> std::process::Output {
    lpm_with_registry(project, "http://127.0.0.1:1")
        .args(["init", "--json"])
        .args(args)
        .timeout(std::time::Duration::from_secs(5))
        .output()
        .unwrap()
}

fn assert_no_manifest(project: &TempProject) {
    assert!(!project.file_exists("package.json"));
    assert!(!project.file_exists("lpm.json"));
}

#[test]
fn init_requires_yes_before_any_noninteractive_prompt() {
    for args in [
        vec![],
        vec!["--npm", "--name", "widget"],
        vec!["--lpm", "--owner", "acme", "--name", "widget"],
    ] {
        let project = blank_project_dir();
        let out = init(&project, &args);
        assert!(!out.status.success());
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(json["error"].as_str().unwrap().contains("--yes"), "{json}");
        assert_no_manifest(&project);
    }
}

#[test]
fn init_npm_rejects_names_rejected_by_publish() {
    for name in ["pkg~name", "-pkg"] {
        let project = blank_project_dir();
        let out = init(&project, &["--npm", "-y", &format!("--name={name}")]);
        assert!(!out.status.success(), "accepted {name}");
        assert_no_manifest(&project);
    }
}

#[test]
fn init_npm_accepts_supported_scoped_names() {
    for name in ["@scope/_pkg", "@_scope/widget", "@scope/-pkg"] {
        let project = blank_project_dir();
        let out = init(&project, &["--npm", "-y", "--name", name]);
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let manifest: serde_json::Value =
            serde_json::from_str(&project.read_file("package.json")).unwrap();
        assert_eq!(manifest["name"], name);
    }
}

#[test]
fn init_lpm_short_name_accepts_a_matching_explicit_owner() {
    let project = blank_project_dir();
    let out = init(
        &project,
        &["--lpm", "-y", "--owner", "acme", "--name", "acme.widget"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    assert_eq!(manifest["name"], "@lpm.dev/acme.widget");
}

#[test]
fn init_rejects_selectors_in_lpm_package_names() {
    for name in [
        "@lpm.dev/acme.widget@2.0.0",
        "acme.widget?foo=bar",
        "widget@2.0.0",
    ] {
        let project = blank_project_dir();
        let out = init(
            &project,
            &["--lpm", "-y", "--owner", "acme", "--name", name],
        );
        assert!(!out.status.success(), "silently normalized {name}");
        assert_no_manifest(&project);
    }
}

#[cfg(unix)]
#[test]
fn init_rejects_dangling_manifest_links_without_writing_the_target() {
    let project = blank_project_dir();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("new.json");
    std::os::unix::fs::symlink(&target, project.path().join("package.json")).unwrap();
    let out = init(&project, &["--npm", "-y"]);
    assert!(!out.status.success());
    assert!(!target.exists());
    assert!(!project.file_exists("lpm.json"));
}

#[cfg(unix)]
#[test]
fn init_rejects_agents_links_before_creating_project_files() {
    for existing in [true, false] {
        let project = blank_project_dir();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("rules.md");
        if existing {
            std::fs::write(&target, "outside rules\n").unwrap();
        }
        std::os::unix::fs::symlink(&target, project.path().join("AGENTS.md")).unwrap();
        let out = init(&project, &["--npm", "-y"]);
        assert!(!out.status.success());
        assert_no_manifest(&project);
        if existing {
            assert_eq!(std::fs::read_to_string(target).unwrap(), "outside rules\n");
        } else {
            assert!(!target.exists());
        }
    }
}

#[test]
fn init_replaces_agents_hardlinks_without_changing_other_names() {
    let project = blank_project_dir();
    project.write_file("outside.md", "original rules\n");
    std::fs::hard_link(
        project.path().join("outside.md"),
        project.path().join("AGENTS.md"),
    )
    .unwrap();
    let out = init(&project, &["--npm", "-y"]);
    assert!(out.status.success());
    assert_eq!(project.read_file("outside.md"), "original rules\n");
    assert!(project.read_file("AGENTS.md").contains("lpm install"));
}

#[test]
fn init_invalid_agents_preserves_existing_config_and_allows_retry() {
    let project = blank_project_dir();
    let config = "{\"dev\":{\"port\":4321}}\n";
    project.write_file("lpm.json", config);
    project.write_file("AGENTS.md", "<!-- lpm:init:start -->\nbroken\n");
    let out = init(&project, &["--npm", "-y"]);
    assert!(!out.status.success());
    assert!(!project.file_exists("package.json"));
    assert_eq!(project.read_file("lpm.json"), config);
    project.write_file("AGENTS.md", "fixed\n");
    assert!(init(&project, &["--npm", "-y"]).status.success());
}

#[test]
fn init_preserves_unmanaged_markdown_around_its_agents_block() {
    let project = blank_project_dir();
    let prefix = "# Rules\n\n";
    let suffix = "\n\n    first example\n    second example\n";
    project.write_file(
        "AGENTS.md",
        &format!("{prefix}<!-- lpm:init:start -->\nold\n<!-- lpm:init:end -->{suffix}"),
    );
    assert!(init(&project, &["--npm", "-y"]).status.success());
    let result = project.read_file("AGENTS.md");
    assert!(result.starts_with(prefix));
    assert!(result.ends_with(suffix), "{result:?}");
}

#[test]
fn init_rejects_oversized_agents_before_writing_project_files() {
    let project = blank_project_dir();
    let file = std::fs::File::create(project.path().join("AGENTS.md")).unwrap();
    file.set_len(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1)
        .unwrap();
    let out = init(&project, &["--npm", "-y"]);
    assert!(!out.status.success());
    assert_no_manifest(&project);
}

#[cfg(unix)]
#[test]
fn init_rejects_agents_fifo_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let project = blank_project_dir();
    let path =
        std::ffi::CString::new(project.path().join("AGENTS.md").as_os_str().as_bytes()).unwrap();
    // SAFETY: path is a valid NUL-terminated string for this call.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let out = init(&project, &["--npm", "-y"]);
    assert!(!out.status.success());
    assert_no_manifest(&project);
}

#[test]
fn init_lpm_preserves_existing_publish_configuration() {
    let project = blank_project_dir();
    let config = "{\"publish\":{\"registries\":[\"npm\"]}}\n";
    project.write_file("lpm.json", config);
    assert!(
        init(&project, &["--lpm", "-y", "--owner", "acme"])
            .status
            .success()
    );
    assert_eq!(project.read_file("lpm.json"), config);
}

#[test]
fn init_config_failure_rolls_back_the_manifest_and_agents_update() {
    let project = blank_project_dir();
    let agents = "# Keep these rules\n";
    project.write_file("AGENTS.md", agents);
    std::fs::create_dir(project.path().join("lpm.json")).unwrap();
    let out = init(&project, &["--npm", "-y"]);
    assert!(!out.status.success());
    assert!(!project.file_exists("package.json"));
    assert_eq!(project.read_file("AGENTS.md"), agents);
    assert!(project.path().join("lpm.json").is_dir());
}

#[test]
fn init_no_agents_does_not_inspect_an_unsafe_agents_entry() {
    let project = blank_project_dir();
    std::fs::create_dir(project.path().join("AGENTS.md")).unwrap();
    let out = init(&project, &["--npm", "-y", "--no-agents"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(project.path().join("AGENTS.md").is_dir());
}

#[cfg(unix)]
#[test]
fn init_agents_replacement_preserves_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let project = blank_project_dir();
    project.write_file("AGENTS.md", "private project guidance\n");
    let path = project.path().join("AGENTS.md");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(init(&project, &["--npm", "-y"]).status.success());
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[test]
fn init_refuses_conflicting_owners_and_invalid_npm_configuration() {
    for name in ["acme.widget", "@lpm.dev/acme.widget"] {
        let project = blank_project_dir();
        let out = init(
            &project,
            &["--lpm", "-y", "--owner", "another", "--name", name],
        );
        assert!(!out.status.success());
        assert_no_manifest(&project);
    }
    let project = blank_project_dir();
    let config = "{\"publish\":{\"registries\":[\"lpm\"]}}\n";
    project.write_file("lpm.json", config);
    assert!(!init(&project, &["--npm", "-y"]).status.success());
    assert!(!project.file_exists("package.json"));
    assert!(!project.file_exists("AGENTS.md"));
    assert_eq!(project.read_file("lpm.json"), config);
}
