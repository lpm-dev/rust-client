//! Workflow coverage for env folder links: a folder uses the local values of
//! the env project its lpm.json names only once it is linked to that
//! project on this machine. The file vault backend stands in for the
//! macOS Keychain.

mod support;

use std::path::{Path, PathBuf};
use support::{TempProject, lpm};

const MARKER: &str = "MARKER_A_123";

fn manifest(name: &str) -> String {
    format!(
        r#"{{"name":"{name}","version":"1.0.0","scripts":{{"dev":"node -e \"console.log('LEAK=' + process.env.A_SECRET)\""}}}}"#
    )
}

/// Project A, which stores a value in its env project.
fn project_with_a_value() -> TempProject {
    let project = TempProject::empty(&manifest("proj-a"));
    lpm(&project)
        .args(["env", "set", &format!("A_SECRET={MARKER}")])
        .assert()
        .success();
    project
}

/// A second folder, sharing A's home, whose lpm.json names A's env project.
fn copied_checkout(project: &TempProject, name: &str) -> PathBuf {
    let folder = project.path().join(name);
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("package.json"), manifest(name)).unwrap();
    std::fs::copy(project.path().join("lpm.json"), folder.join("lpm.json")).unwrap();
    folder
}

fn lpm_in(project: &TempProject, folder: &Path, args: &[&str]) -> std::process::Output {
    let mut command = lpm(project);
    command.current_dir(folder).args(args);
    command.output().unwrap()
}

fn output_of(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_folder_that_isn_t_linked_uses_none_of_the_project_s_values() {
    let project = project_with_a_value();
    let other = copied_checkout(&project, "other-checkout");

    for args in [
        &["run", "dev"][..],
        &["env", "get", "A_SECRET", "--reveal"],
        &["env", "list", "--reveal"],
        &["env", "print"],
        &["env", "history", "--reveal"],
        &["env", "set", "A_SECRET=OVERWRITTEN"],
    ] {
        let output = lpm_in(&project, &other, args);

        let text = output_of(&output);
        assert!(!output.status.success(), "{args:?}: {text}");
        assert!(!text.contains(MARKER), "{args:?}: {text}");
        assert!(text.contains("lpm env link"), "{args:?}: {text}");
    }
    let own = lpm_in(
        &project,
        project.path(),
        &["env", "get", "A_SECRET", "--reveal"],
    );
    assert!(output_of(&own).contains(MARKER), "{}", output_of(&own));
}

#[test]
fn commands_that_sync_list_or_compare_values_refuse_an_unlinked_folder() {
    let project = project_with_a_value();
    let other = copied_checkout(&project, "other-checkout");
    std::fs::write(other.join(".env.example"), "A_SECRET=\n").unwrap();

    for args in [
        &["env", "ls"][..],
        &["env", "init"],
        &["env", "diff", "default", "staging"],
        &["env", "log"],
        &["env", "push", "--yes"],
        &["env", "pull", "--yes"],
        &["env", "share", "--org", "acme"],
        &["env", "push", "--to", "vercel", "--yes"],
        &["env", "pull", "--from", "vercel", "--yes"],
        &["env", "status"],
        &["env", "validate", "--strict"],
    ] {
        let output = lpm_in(&project, &other, args);

        let text = output_of(&output);
        assert!(!output.status.success(), "{args:?}: {text}");
        assert!(!text.contains(MARKER), "{args:?}: {text}");
        assert!(text.contains("lpm env link"), "{args:?}: {text}");
    }
}

#[test]
fn an_unlinked_folder_s_refusal_has_its_own_json_error_code() {
    let project = project_with_a_value();
    let other = copied_checkout(&project, "other-checkout");

    let output = lpm_in(&project, &other, &["--json", "env", "get", "A_SECRET"]);

    assert!(!output.status.success());
    let text = output_of(&output);
    assert!(text.contains("env_project_refused"), "{text}");
    assert!(!text.contains(MARKER), "{text}");
}

#[test]
fn a_linked_checkout_of_the_same_project_uses_its_values() {
    let project = project_with_a_value();
    let checkout = copied_checkout(&project, "second-checkout");

    let link = lpm_in(&project, &checkout, &["env", "link", "--yes"]);
    assert!(link.status.success(), "{}", output_of(&link));

    let get = lpm_in(&project, &checkout, &["env", "get", "A_SECRET", "--reveal"]);
    assert!(output_of(&get).contains(MARKER), "{}", output_of(&get));
    let run = lpm_in(&project, &checkout, &["run", "dev"]);
    assert!(
        output_of(&run).contains(&format!("LEAK={MARKER}")),
        "{}",
        output_of(&run)
    );
    let links = lpm_in(&project, project.path(), &["--json", "env", "links"]);
    let report: serde_json::Value = serde_json::from_slice(&links.stdout).unwrap();
    let folders: Vec<PathBuf> = report["folders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|folder| PathBuf::from(folder.as_str().unwrap()))
        .collect();
    assert_eq!(
        folders,
        [
            project.path().canonicalize().unwrap(),
            checkout.canonicalize().unwrap()
        ]
    );
    assert_eq!(report["this_folder_linked"], true);
}

#[test]
fn env_link_asks_first_and_refuses_without_a_terminal() {
    let project = project_with_a_value();
    let other = copied_checkout(&project, "other-checkout");

    let link = lpm_in(&project, &other, &["env", "link"]);

    assert!(!link.status.success());
    assert!(output_of(&link).contains("--yes"), "{}", output_of(&link));
    let get = lpm_in(&project, &other, &["env", "get", "A_SECRET", "--reveal"]);
    assert!(!output_of(&get).contains(MARKER));
}

#[test]
fn env_unlink_stops_a_folder_from_using_the_project() {
    let project = project_with_a_value();
    let checkout = copied_checkout(&project, "second-checkout");
    assert!(
        lpm_in(&project, &checkout, &["env", "link", "--yes"])
            .status
            .success()
    );

    let unlink = lpm_in(&project, &checkout, &["env", "unlink"]);

    assert!(unlink.status.success(), "{}", output_of(&unlink));
    let get = lpm_in(&project, &checkout, &["env", "get", "A_SECRET", "--reveal"]);
    assert!(!get.status.success());
    assert!(!output_of(&get).contains(MARKER));
}

#[test]
fn a_vault_from_before_links_lets_no_folder_use_it_until_one_is_linked() {
    let project = project_with_a_value();
    let vaults = project.home().join(".lpm").join("vaults");
    let mut removed = 0;
    for entry in std::fs::read_dir(&vaults).unwrap() {
        let path = entry.unwrap().path();
        if path
            .extension()
            .is_some_and(|extension| extension == "links")
        {
            std::fs::remove_file(path).unwrap();
            removed += 1;
        }
    }
    assert_eq!(
        removed, 1,
        "the creating folder's link must have been recorded"
    );

    let refused = lpm_in(
        &project,
        project.path(),
        &["env", "get", "A_SECRET", "--reveal"],
    );
    let link = lpm_in(&project, project.path(), &["env", "link", "--yes"]);
    let get = lpm_in(
        &project,
        project.path(),
        &["env", "get", "A_SECRET", "--reveal"],
    );

    assert!(!refused.status.success(), "{}", output_of(&refused));
    assert!(!output_of(&refused).contains(MARKER));
    assert!(link.status.success(), "{}", output_of(&link));
    assert!(output_of(&get).contains(MARKER), "{}", output_of(&get));
}

#[test]
fn a_folder_that_names_a_vault_this_machine_holds_no_values_for_is_not_refused() {
    let project = TempProject::empty(&manifest("fresh-clone"));
    project.write_file(
        "lpm.json",
        r#"{"vault":"0f2a2f6e-6f2b-4b8e-9d55-2f6c0c1b7a10"}"#,
    );

    let list = lpm(&project).args(["env", "list"]).output().unwrap();
    let set = lpm(&project)
        .args(["env", "set", "LOCAL=1"])
        .output()
        .unwrap();

    assert!(list.status.success(), "{}", output_of(&list));
    assert!(set.status.success(), "{}", output_of(&set));
    let links = lpm(&project)
        .args(["--json", "env", "links"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&links.stdout).unwrap();
    assert_eq!(report["this_folder_linked"], true, "{report}");
}

/// `value` with the project's folders and vault ID replaced by placeholders.
fn redacted(project: &TempProject, value: &serde_json::Value) -> serde_json::Value {
    let vault_id = std::fs::read_to_string(project.path().join("lpm.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|config| config["vault"].as_str().map(str::to_owned))
        .expect("the project names its vault");
    let root = project.path().canonicalize().unwrap();
    let text = value
        .to_string()
        .replace(&vault_id, "[VAULT_ID]")
        .replace(
            &root.join("second-checkout").display().to_string(),
            "[CHECKOUT]",
        )
        .replace(&root.display().to_string(), "[PROJECT]");
    serde_json::from_str(&text).unwrap()
}

fn json_of(output: &std::process::Output) -> serde_json::Value {
    assert!(output.status.success(), "{}", output_of(output));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn env_link_links_and_unlink_report_json_envelopes() {
    let project = project_with_a_value();
    let checkout = copied_checkout(&project, "second-checkout");

    let link = json_of(&lpm_in(
        &project,
        &checkout,
        &["--json", "env", "link", "--yes"],
    ));
    let links = json_of(&lpm_in(&project, &checkout, &["--json", "env", "links"]));
    let unlink = json_of(&lpm_in(&project, &checkout, &["--json", "env", "unlink"]));

    assert_eq!(link["already_linked"], false);
    assert_eq!(unlink["unlinked"], true);
    insta::assert_json_snapshot!("env_link_json_envelope", redacted(&project, &link));
    insta::assert_json_snapshot!("env_links_json_envelope", redacted(&project, &links));
    insta::assert_json_snapshot!("env_unlink_json_envelope", redacted(&project, &unlink));
}
