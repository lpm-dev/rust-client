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
        r#"{{"name":"{name}","version":"1.0.0","scripts":{{"dev":"node -e \"console.log('VALUE=' + process.env.A_SECRET)\""}}}}"#
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
    std::fs::write(other.join("local.env"), "A_SECRET=OVERWRITTEN\n").unwrap();

    for args in [
        &["run", "dev"][..],
        &["env", "get", "A_SECRET", "--reveal"],
        &["env", "list", "--reveal"],
        &["env", "print"],
        &["env", "history", "--reveal"],
        &["env", "set", "A_SECRET=OVERWRITTEN"],
        &[
            "exec",
            "node",
            "-e",
            "console.log('VALUE=' + process.env.A_SECRET)",
        ],
        &["env", "copy", "default", "staging"],
        &["env", "import", "local.env"],
        &["env", "rollback", "--to", "1", "--yes"],
        &["env", "repair", "--yes"],
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
fn invalid_value_arguments_are_refused_before_an_unlinked_folder_is_asked_about() {
    let project = project_with_a_value();
    let other = copied_checkout(&project, "other-checkout");

    for (args, said) in [
        (
            &["env", "set", "--from-file", "NOT-A-KEY=./value"][..],
            "--from-file",
        ),
        (&["env", "set", "--from-file", "A_SECRET"], "--from-file"),
        (
            &["env", "override", "set", "--from-file", "NOT-A-KEY=./value"],
            "--from-file",
        ),
        (
            &["env", "override", "unset", "NOT-A-KEY"],
            "env keys must match",
        ),
        (
            &["env", "override", "unset", "NODE_OPTIONS"],
            "NODE_OPTIONS",
        ),
        (
            &[
                "env",
                "override",
                "remove",
                "--env",
                "not an environment",
                "A",
            ],
            "environment",
        ),
    ] {
        let output = lpm_in(&project, &other, args);

        let text = output_of(&output);
        assert!(!output.status.success(), "{args:?}: {text}");
        assert!(text.contains(said), "{args:?}: {text}");
        assert!(
            !text.contains("lpm env link"),
            "the arguments are wrong whichever folder runs them: {args:?}: {text}"
        );
    }
}

#[test]
fn commands_that_sync_list_or_compare_values_refuse_an_unlinked_folder() {
    let project = project_with_a_value();
    let other = copied_checkout(&project, "other-checkout");
    std::fs::write(other.join(".env.example"), "A_SECRET=\n").unwrap();

    for args in [
        &["env", "connect", "vercel"][..],
        &["env", "ls"],
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
    assert!(!text.contains(MARKER), "{text}");
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    insta::assert_json_snapshot!(
        "env_unlinked_folder_refusal_json_envelope",
        redacted(&project, &envelope)
    );
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
        output_of(&run).contains(&format!("VALUE={MARKER}")),
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
fn env_init_in_a_fresh_clone_links_the_folder_it_imports_into() {
    let project = TempProject::empty(&manifest("fresh-clone"));
    project.write_file(
        "lpm.json",
        r#"{"vault":"0f2a2f6e-6f2b-4b8e-9d55-2f6c0c1b7a10"}"#,
    );
    project.write_file(".env", &format!("A_SECRET={MARKER}\n"));

    let init = lpm(&project).args(["env", "init"]).output().unwrap();
    let list = lpm(&project)
        .args(["env", "list", "--reveal"])
        .output()
        .unwrap();

    assert!(init.status.success(), "{}", output_of(&init));
    assert!(output_of(&list).contains(MARKER), "{}", output_of(&list));
}

#[test]
fn a_workspace_run_refuses_a_member_that_isn_t_linked() {
    let project = project_with_a_value();
    let mut root: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    root["workspaces"] = serde_json::json!(["packages/*"]);
    root["private"] = serde_json::json!(true);
    project.write_file("package.json", &root.to_string());
    let member = copied_checkout(&project, "packages/member");

    let run = lpm(&project)
        .args(["run", "dev", "--all"])
        .output()
        .unwrap();

    let text = output_of(&run);
    assert!(!run.status.success(), "{text}");
    assert!(!text.contains(&format!("VALUE={MARKER}")), "{text}");
    assert!(text.contains("lpm env link"), "{text}");
    assert!(member.exists());
}

#[test]
fn a_deleted_folder_can_be_unlinked_by_its_path() {
    let project = project_with_a_value();
    let checkout = copied_checkout(&project, "second-checkout");
    assert!(
        lpm_in(&project, &checkout, &["env", "link", "--yes"])
            .status
            .success()
    );
    std::fs::remove_dir_all(&checkout).unwrap();
    // Another spelling of the deleted folder's path, through a link to its
    // parent. Windows grants symbolic links only with a privilege, so it
    // unlinks the path as linked.
    #[cfg(unix)]
    let spelled = {
        let alias = project.path().join("alias");
        std::os::unix::fs::symlink(project.path(), &alias).unwrap();
        alias.join("second-checkout")
    };
    #[cfg(not(unix))]
    let spelled = checkout;

    let unlink = lpm_in(
        &project,
        project.path(),
        &["--json", "env", "unlink", spelled.to_str().unwrap()],
    );

    let report = json_of(&unlink);
    assert_eq!(report["unlinked"], true, "{report}");
    assert_eq!(
        PathBuf::from(report["folder"].as_str().unwrap()),
        project
            .path()
            .canonicalize()
            .unwrap()
            .join("second-checkout"),
        "the folder as linked, not as typed"
    );
    let links = json_of(&lpm_in(
        &project,
        project.path(),
        &["--json", "env", "links"],
    ));
    assert_eq!(links["folders"].as_array().unwrap().len(), 1, "{links}");
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

/// `value` with the project's folders and vault ID replaced by placeholders
/// in its strings, before any escaping a serializer adds.
fn redacted(project: &TempProject, value: &serde_json::Value) -> serde_json::Value {
    let vault_id = std::fs::read_to_string(project.path().join("lpm.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|config| config["vault"].as_str().map(str::to_owned))
        .expect("the project names its vault");
    let root = project.path().canonicalize().unwrap();
    let replacements = [
        (vault_id, "[VAULT_ID]"),
        (
            root.join("second-checkout").display().to_string(),
            "[CHECKOUT]",
        ),
        (
            root.join("other-checkout").display().to_string(),
            "[OTHER_CHECKOUT]",
        ),
        (root.display().to_string(), "[PROJECT]"),
    ];
    fn redact(value: &serde_json::Value, replacements: &[(String, &str)]) -> serde_json::Value {
        match value {
            serde_json::Value::String(text) => serde_json::Value::String(
                replacements
                    .iter()
                    .fold(text.clone(), |text, (from, to)| text.replace(from, to)),
            ),
            serde_json::Value::Array(items) => serde_json::Value::Array(
                items
                    .iter()
                    .map(|item| redact(item, replacements))
                    .collect(),
            ),
            serde_json::Value::Object(fields) => serde_json::Value::Object(
                fields
                    .iter()
                    .map(|(key, field)| (key.clone(), redact(field, replacements)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }
    redact(value, &replacements)
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
    let relink = json_of(&lpm_in(
        &project,
        &checkout,
        &["--json", "env", "link", "--yes"],
    ));
    let again = json_of(&lpm_in(
        &project,
        &checkout,
        &["--json", "env", "link", "--yes"],
    ));
    assert_eq!(relink["already_linked"], false, "{relink}");
    assert_eq!(again["already_linked"], true, "{again}");
    let other = copied_checkout(&project, "never-linked");
    let not_linked = json_of(&lpm_in(&project, &other, &["--json", "env", "unlink"]));
    assert_eq!(not_linked["unlinked"], false, "{not_linked}");
    insta::assert_json_snapshot!("env_link_json_envelope", redacted(&project, &link));
    insta::assert_json_snapshot!("env_links_json_envelope", redacted(&project, &links));
    insta::assert_json_snapshot!("env_unlink_json_envelope", redacted(&project, &unlink));
}

#[test]
fn env_unlink_resolves_a_relative_folder_from_where_it_runs() {
    let project = project_with_a_value();
    let checkout = copied_checkout(&project, "second-checkout");
    assert!(
        lpm_in(&project, &checkout, &["env", "link", "--yes"])
            .status
            .success()
    );
    let src = project.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    let unlink = json_of(&lpm_in(
        &project,
        &src,
        &["--json", "env", "unlink", "../second-checkout"],
    ));

    assert_eq!(unlink["unlinked"], true, "{unlink}");
    let links = json_of(&lpm_in(
        &project,
        project.path(),
        &["--json", "env", "links"],
    ));
    assert_eq!(links["folders"].as_array().unwrap().len(), 1, "{links}");
}

#[test]
fn every_way_to_run_a_script_refuses_a_folder_that_isn_t_linked_as_a_refusal() {
    let project = project_with_a_value();
    let other = copied_checkout(&project, "other-checkout");
    std::fs::write(
        other.join("show.js"),
        "console.log('VALUE=' + process.env.A_SECRET)\n",
    )
    .unwrap();
    let mut root: serde_json::Value =
        serde_json::from_str(&project.read_file("package.json")).unwrap();
    root["workspaces"] = serde_json::json!(["other-checkout"]);
    root["private"] = serde_json::json!(true);
    project.write_file("package.json", &root.to_string());

    for (folder, args) in [
        (other.as_path(), &["--json", "dev"][..]),
        (other.as_path(), &["--json", "show.js"]),
        (project.path(), &["--json", "run", "dev", "--all"]),
    ] {
        let output = lpm_in(&project, folder, args);

        let text = output_of(&output);
        assert!(!output.status.success(), "{args:?}: {text}");
        assert!(!text.contains(MARKER), "{args:?}: {text}");
        assert!(text.contains("env_project_refused"), "{args:?}: {text}");
    }
}

#[test]
fn a_run_checks_its_folder_s_link_once() {
    let project = project_with_a_value();
    let log = project.path().join("vault-transactions.log");

    let run = lpm(&project)
        .env("LPM_TEST_VAULT_TRANSACTION_LOG", &log)
        .args(["run", "dev"])
        .output()
        .unwrap();

    assert!(run.status.success(), "{}", output_of(&run));
    let log = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        log.lines().filter(|line| *line == "link check").count(),
        1,
        "{log}"
    );
}

#[test]
fn env_link_replaces_folder_links_that_can_t_be_read() {
    let project = project_with_a_value();
    let vaults = project.home().join(".lpm").join("vaults");
    let links = std::fs::read_dir(&vaults)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "links")
        })
        .expect("the project's folder links");
    std::fs::write(&links, "{not json").unwrap();

    let refused = lpm_in(
        &project,
        project.path(),
        &["--json", "env", "get", "A_SECRET", "--reveal"],
    );
    let refusal = output_of(&refused);
    assert!(!refused.status.success(), "{refusal}");
    assert!(refusal.contains("env_project_refused"), "{refusal}");
    assert!(refusal.contains("lpm env link --yes"), "{refusal}");

    let link = lpm_in(&project, project.path(), &["env", "link", "--yes"]);
    let get = lpm_in(
        &project,
        project.path(),
        &["env", "get", "A_SECRET", "--reveal"],
    );

    assert!(link.status.success(), "{}", output_of(&link));
    assert!(output_of(&get).contains(MARKER), "{}", output_of(&get));
}
