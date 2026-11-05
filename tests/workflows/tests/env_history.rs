#![cfg(debug_assertions)]

//! Workflow tests for local history: `lpm env history`, its `show`,
//! `status`, `on`, `off` and `forget`, `lpm env rollback`, and the notice
//! commands that write values give when a change isn't recorded.

mod support;

use support::assertions::parse_json_output;
use support::{TempProject, lpm};

fn project() -> TempProject {
    TempProject::empty(r#"{"name":"history-app"}"#)
}

fn json(project: &TempProject, args: &[&str]) -> (bool, serde_json::Value) {
    let output = lpm(project).args(args).output().unwrap();
    (output.status.success(), parse_json_output(&output.stdout))
}

fn set(project: &TempProject, assignment: &str) {
    let (success, response) = json(project, &["env", "set", assignment, "--json"]);
    assert!(success, "{response}");
    assert!(response.get("history").is_none(), "{response}");
}

fn entry_ids(project: &TempProject) -> Vec<String> {
    let (success, response) = json(project, &["env", "history", "--json"]);
    assert!(success, "{response}");
    response["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["short_id"].as_str().map(str::to_owned))
        .collect()
}

fn stored(project: &TempProject, key: &str) -> String {
    let output = lpm(project)
        .args(["env", "get", key, "--reveal"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
fn env_history_lists_each_change_newest_first_with_values_hidden() {
    let project = project();
    set(&project, "API_URL=https://one.example");
    set(&project, "API_URL=https://two.example");
    let (success, response) = json(&project, &["env", "history", "--json"]);
    assert!(success, "{response}");
    insta::assert_json_snapshot!("env_history_list", response, {
        ".entries[].id" => "[id]",
        ".entries[].short_id" => "[short id]",
        ".entries[].time" => "[time]",
        ".oldest" => "[time]",
    });
    let text = response.to_string();
    assert!(!text.contains("one.example"), "values stay hidden: {text}");

    let (success, revealed) = json(&project, &["env", "history", "--reveal", "--json"]);
    assert!(success);
    assert_eq!(
        revealed["entries"][0]["environments"][0]["keys"][0]["before"]["value"],
        "https://one.example"
    );
    assert_eq!(
        revealed["entries"][0]["environments"][0]["keys"][0]["after"]["value"],
        "https://two.example"
    );

    let human = lpm(&project).args(["env", "history"]).output().unwrap();
    let human = String::from_utf8_lossy(&human.stdout);
    assert!(human.contains("Values are hidden"), "{human}");
    assert!(human.contains("LPM CLI · set"), "{human}");
    assert!(human.contains("2 changes kept since"), "{human}");
}

#[test]
fn env_history_show_finds_an_entry_by_its_short_id_and_reports_unknown_ones() {
    let project = project();
    set(&project, "TOKEN=first");
    set(&project, "TOKEN=second");
    let ids = entry_ids(&project);
    let (success, response) = json(&project, &["env", "history", "show", &ids[0], "--json"]);
    assert!(success, "{response}");
    assert_eq!(
        response["entry"]["environments"][0]["keys"][0]["key"],
        "TOKEN"
    );
    assert!(
        response["entry"]["environments"][0]["keys"][0]["after"]
            .get("value")
            .is_none()
    );

    let (success, response) = json(&project, &["env", "history", "show", "abcdef", "--json"]);
    assert!(!success);
    assert_eq!(response["error_code"], "history.entry_not_found");
}

#[test]
fn env_rollback_to_values_the_environment_already_has_changes_nothing() {
    let project = project();
    set(&project, "DB_URL=postgres://one");
    set(&project, "DB_URL=postgres://two");
    let newest = entry_ids(&project).first().unwrap().clone();

    let (success, response) = json(&project, &["env", "rollback", "--to", &newest, "--json"]);
    assert!(success, "{response}");
    assert_eq!(response["rolled_back"], serde_json::json!([]));
    assert_eq!(entry_ids(&project).len(), 2, "nothing was recorded");

    let output = lpm(&project)
        .args(["env", "rollback", "--to", &newest])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("nothing to roll back: default already has the values it had at"),
        "{text}"
    );
}

#[test]
fn env_rollback_reviews_first_and_needs_yes_without_a_terminal() {
    let project = project();
    set(&project, "DB_URL=postgres://one");
    set(&project, "DB_URL=postgres://two");
    set(&project, "EXTRA=added");
    let ids = entry_ids(&project);
    let first = ids.last().unwrap().clone();

    let (success, response) = json(&project, &["env", "rollback", "--to", &first, "--json"]);
    assert!(!success);
    assert_eq!(response["error_code"], "confirmation_required");
    let rows = response["review"]["environments"][0]["rows"]
        .as_array()
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        stored(&project, "DB_URL"),
        "postgres://two",
        "nothing changed"
    );

    let (success, response) = json(
        &project,
        &["env", "rollback", "--to", &first, "--yes", "--json"],
    );
    assert!(success, "{response}");
    assert_eq!(response["rolled_back"], serde_json::json!(["default"]));
    assert_eq!(stored(&project, "DB_URL"), "postgres://one");
    let (_, history) = json(&project, &["env", "history", "--json"]);
    assert_eq!(history["entries"][0]["source"]["action"], "rollback");
    assert_eq!(history["entries"][0]["related"]["side"], "after");
}

#[test]
fn env_rollback_before_with_one_key_restores_that_key_only() {
    let project = project();
    set(&project, "A=1");
    set(&project, "B=1");
    set(&project, "A=2");
    let newest = entry_ids(&project)[0].clone();
    let (success, response) = json(
        &project,
        &[
            "env", "rollback", "--before", &newest, "--key", "A", "--yes", "--json",
        ],
    );
    assert!(success, "{response}");
    assert_eq!(response["rollback"]["kind"], "key");
    assert_eq!(stored(&project, "A"), "1");
    assert_eq!(stored(&project, "B"), "1");
}

#[test]
fn env_history_off_deletes_history_and_on_starts_it_again_empty() {
    let project = project();
    set(&project, "A=1");
    let (success, response) = json(&project, &["env", "history", "off", "--json"]);
    assert!(!success);
    assert_eq!(response["error_code"], "confirmation_required");

    let (success, _) = json(&project, &["env", "history", "off", "--yes", "--json"]);
    assert!(success);
    let (_, status) = json(&project, &["env", "history", "status", "--json"]);
    assert_eq!(status["state"], "off");
    set(&project, "A=2");
    let (success, response) = json(&project, &["env", "history", "--json"]);
    assert!(!success);
    assert_eq!(response["error_code"], "history.off");

    let (success, _) = json(&project, &["env", "history", "on", "--json"]);
    assert!(success);
    let (_, status) = json(&project, &["env", "history", "status", "--json"]);
    assert_eq!(
        (status["state"].as_str(), status["retained"].as_u64()),
        (Some("on"), Some(0))
    );
    set(&project, "A=3");
    assert_eq!(entry_ids(&project).len(), 1);
}

#[test]
fn env_history_forget_removes_an_old_value_and_refuses_a_current_one() {
    let project = project();
    set(&project, "SECRET=leaked");
    set(&project, "SECRET=rotated");
    let ids = entry_ids(&project);
    let (success, response) = json(
        &project,
        &[
            "env", "history", "forget", &ids[0], "SECRET", "--before", "--yes", "--json",
        ],
    );
    assert!(success, "{response}");
    assert_eq!(response["places"][0]["removed"], true);
    let (_, revealed) = json(
        &project,
        &["env", "history", "show", &ids[0], "--reveal", "--json"],
    );
    let before = &revealed["entry"]["environments"][0]["keys"][0]["before"];
    assert_eq!(before["state"], "removed");
    assert!(before.get("value").is_none());
    assert_eq!(stored(&project, "SECRET"), "rotated");

    let (success, response) = json(
        &project,
        &[
            "env", "history", "forget", &ids[0], "SECRET", "--yes", "--json",
        ],
    );
    assert!(!success);
    assert_eq!(response["error_code"], "history.value_is_current");
}

#[test]
fn env_history_forget_only_env_with_all_keys_keeps_to_that_environment() {
    let project = project();
    for args in [
        ["env", "set", "A=same", "--env", "production", "--json"],
        ["env", "set", "B=same", "--env", "staging", "--json"],
        ["env", "set", "A=new", "--env", "production", "--json"],
        ["env", "set", "B=new", "--env", "staging", "--json"],
    ] {
        let (success, response) = json(&project, &args);
        assert!(success, "{response}");
    }
    let ids = entry_ids(&project);
    let (production_set, staging_set) = (&ids[3], &ids[2]);
    let (success, response) = json(
        &project,
        &[
            "env",
            "history",
            "forget",
            production_set,
            "A",
            "--env",
            "production",
            "--only-env",
            "--all-keys",
            "--yes",
            "--json",
        ],
    );
    assert!(success, "{response}");
    let (_, staging) = json(
        &project,
        &["env", "history", "show", staging_set, "--reveal", "--json"],
    );
    let after = &staging["entry"]["environments"][0]["keys"][0]["after"];
    assert_eq!(
        after["value"], "same",
        "staging's B holds the value too, but --only-env keeps to production: {staging}"
    );
}

#[test]
fn env_history_errors_use_the_shared_json_error_envelope() {
    let project = project();
    set(&project, "A=1");
    set(&project, "A=2");
    let (success, missing) = json(&project, &["env", "history", "show", "abcdef", "--json"]);
    assert!(!success);
    assert_eq!(missing["schema_version"], 1, "{missing}");
    assert_eq!(missing["error_code"], "history.entry_not_found");
    assert_eq!(missing["error"], "no entry in local history has that ID");

    let ids = entry_ids(&project);
    let first = ids[1].as_str();
    for (args, command) in [
        (
            vec!["env", "rollback", "--to", first, "--json"],
            "lpm env rollback",
        ),
        (
            vec!["env", "history", "forget", first, "A", "--json"],
            "lpm env history forget",
        ),
        (
            vec!["env", "history", "off", "--json"],
            "lpm env history off",
        ),
    ] {
        let (success, response) = json(&project, &args);
        assert!(!success, "{args:?}");
        assert_eq!(response["schema_version"], 1, "{response}");
        assert_eq!(response["error_code"], "confirmation_required");
        assert_eq!(response["error"]["code"], "CONFIRMATION_REQUIRED");
        assert_eq!(response["error"]["command"], command, "{response}");
        assert!(
            response["error"]["help"]
                .as_str()
                .is_some_and(|help| help.contains("--yes")),
            "{response}"
        );
        assert!(
            response.get("review").is_some(),
            "the review stays: {response}"
        );
    }
}

#[test]
fn a_values_write_that_history_cant_record_still_succeeds_and_says_why() {
    let project = project();
    set(&project, "A=1");
    let vaults = project.home().join(".lpm").join("vaults");
    let companion = std::fs::read_dir(&vaults)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".companion"))
        .expect("the project's companion folder")
        .path();
    std::fs::write(companion.join("record.history-head"), b"damaged").unwrap();

    let output = lpm(&project)
        .args(["env", "set", "A=2", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let response = parse_json_output(&output.stdout);
    assert_eq!(response["history"]["recorded"], false, "{response}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lpm: this change wasn't added to local history:"),
        "{stderr}"
    );
    assert_eq!(stored(&project, "A"), "2");
}

#[test]
fn env_repair_removes_damaged_history_which_restarts_at_the_next_change() {
    let project = project();
    set(&project, "A=1");
    let vaults = project.home().join(".lpm").join("vaults");
    let companion = std::fs::read_dir(&vaults)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".companion"))
        .expect("the project's companion folder")
        .path();
    std::fs::write(companion.join("record.history-head"), b"damaged").unwrap();

    let (success, review) = json(&project, &["env", "repair", "--json"]);
    assert!(!success, "the review alone fails: {review}");
    assert_eq!(
        review["problems"][0]["repair"]["feature"], "history",
        "{review}"
    );
    let (success, repaired) = json(&project, &["env", "repair", "--yes", "--json"]);
    assert!(success, "{repaired}");
    let (_, status) = json(&project, &["env", "history", "status", "--json"]);
    assert_eq!(
        (status["state"].as_str(), status["retained"].as_u64()),
        (Some("on"), Some(0))
    );
    set(&project, "A=2");
    assert_eq!(entry_ids(&project).len(), 1);
}

fn companion_folder(project: &TempProject) -> std::path::PathBuf {
    std::fs::read_dir(project.home().join(".lpm").join("vaults"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".companion"))
        .expect("the project's companion folder")
        .path()
}

#[test]
fn damaged_history_reads_as_paused_in_the_list_and_in_status() {
    let project = project();
    set(&project, "A=1");
    std::fs::write(
        companion_folder(&project).join("record.history.000"),
        b"damaged",
    )
    .unwrap();
    let (success, listing) = json(&project, &["env", "history", "--json"]);
    assert!(success, "{listing}");
    assert_eq!(
        (listing["state"].as_str(), listing["reason"].as_str()),
        (Some("paused"), Some("damaged")),
        "{listing}"
    );
    let (success, status) = json(&project, &["env", "history", "status", "--json"]);
    assert!(success, "{status}");
    assert_eq!(
        (status["state"].as_str(), status["reason"].as_str()),
        (Some("paused"), Some("damaged")),
        "{status}"
    );
}
