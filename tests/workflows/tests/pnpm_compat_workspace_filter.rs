//! PNPM compatibility contracts for workspace filtering and recursive runs.

mod support;

use support::{TempProject, lpm};

fn seed_workspace_with_no_bail_scripts(project: &TempProject) {
    for member in ["app", "core", "utils"] {
        let pkg_path = format!("packages/{member}/package.json");
        let pkg_content = project.read_file(&pkg_path);
        let mut pkg: serde_json::Value =
            serde_json::from_str(&pkg_content).expect("parse member package.json");

        let command = if member == "utils" {
            format!(
                "node -e \"require('fs').writeFileSync('ran-{member}.txt','failed'); process.exit(1)\""
            )
        } else {
            format!("node -e \"require('fs').writeFileSync('ran-{member}.txt','ok')\"")
        };

        pkg["scripts"] = serde_json::json!({
            "check": command,
        });
        project.write_file(&pkg_path, &serde_json::to_string_pretty(&pkg).unwrap());
    }
}

fn member_ran(project: &TempProject, member: &str) -> bool {
    project.file_exists(&format!("packages/{member}/ran-{member}.txt"))
}

#[test]
fn run_filter_no_bail_continues_after_failed_workspace_member() {
    let project = TempProject::from_fixture("workspace-monorepo");
    seed_workspace_with_no_bail_scripts(&project);

    let output = lpm(&project)
        .args(["run", "check", "--filter", "@test/*", "--no-bail"])
        .output()
        .expect("failed to run lpm run --filter --no-bail");

    assert!(
        !output.status.success(),
        "--no-bail must still report the filtered batch failure"
    );
    for member in ["utils", "core", "app"] {
        assert!(
            member_ran(&project, member),
            "{member} must execute even though utils fails under --no-bail\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
