#![cfg(debug_assertions)]

//! Workflow tests for personal overrides: values one machine sets on top of
//! an env project's team values. No command writes them yet, so each test
//! seeds the file store the `lpm` process reads, the way a later client
//! would leave it.

mod support;

use support::{TempProject, lpm};

const OVERRIDES_MARKER: &str = r#"{"schemaVersion":1,"vaultId":"VAULT_ID","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;

fn project_with_team_value(scripts: &str) -> (TempProject, String) {
    let project = TempProject::empty(&format!(
        r#"{{"name":"personal-overrides","version":"1.0.0","scripts":{scripts}}}"#
    ));
    project.write_file("show.cjs", "console.log(`API_URL=${process.env.API_URL}`)");
    lpm(&project)
        .args(["env", "set", "API_URL=team"])
        .assert()
        .success();
    let vault_id =
        lpm_vault::vault_id::read_vault_id(project.path()).expect("env set creates a vault ID");
    (project, vault_id)
}

/// Add `fields` to the project's `lpm.json`, keeping the vault ID `env set` wrote.
fn extend_lpm_json(project: &TempProject, fields: serde_json::Value) {
    let mut config: serde_json::Value =
        serde_json::from_str(&project.read_file("lpm.json")).expect("lpm.json is JSON");
    for (key, value) in fields.as_object().expect("fields are an object") {
        config[key] = value.clone();
    }
    project.write_file("lpm.json", &config.to_string());
}

fn overrides_record(vault_id: &str, environment: &str, set: &str, unset: &str) -> String {
    format!(
        r#"{{"schemaVersion":1,"vaultId":"{vault_id}","environments":{{"{environment}":{{"set":{{{set}}},"unset":[{unset}]}}}}}}"#
    )
}

fn seed(project: &TempProject, vault_id: &str, marker: Option<&str>, overrides: Option<&str>) {
    let marker = marker.map(|marker| marker.replace("VAULT_ID", vault_id));
    lpm_vault::acceptance::store_file_companion_records(
        &project.home().join(".lpm"),
        vault_id,
        marker.as_deref(),
        overrides,
    )
    .expect("seed companion records");
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn run_applies_a_personal_override_and_reports_only_its_count() {
    let (project, vault_id) = project_with_team_value(r#"{"show":"node show.cjs"}"#);
    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(
            &vault_id,
            "default",
            r#""API_URL":"mine""#,
            "",
        )),
    );

    let output = lpm(&project)
        .args(["run", "show", "--no-cache"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("API_URL=mine"),
        "{}",
        stdout(&output)
    );
    let stderr = stderr(&output);
    assert!(
        stderr.contains("1 personal override on this Mac"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("API_URL"),
        "names stay out by default: {stderr}"
    );
}

#[test]
fn unset_removes_the_team_value_from_the_run() {
    let (project, vault_id) = project_with_team_value(r#"{"show":"node show.cjs"}"#);
    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(&vault_id, "default", "", r#""API_URL""#)),
    );

    let output = lpm(&project)
        .args(["run", "show", "--no-cache"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("API_URL=undefined"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn print_applies_overrides_but_ci_emission_excludes_them() {
    let (project, vault_id) = project_with_team_value("{}");
    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(
            &vault_id,
            "default",
            r#""API_URL":"mine""#,
            "",
        )),
    );

    let printed = lpm(&project)
        .args(["env", "print", "--format=json"])
        .output()
        .unwrap();
    assert!(printed.status.success(), "{}", stderr(&printed));
    let printed_json: serde_json::Value =
        serde_json::from_slice(&printed.stdout).expect("print emits one JSON document");
    assert_eq!(printed_json["API_URL"], "mine");
    assert!(stderr(&printed).contains("1 personal override on this Mac"));

    let ci = lpm(&project)
        .args(["env", "print", "--ci"])
        .output()
        .unwrap();
    assert!(ci.status.success(), "{}", stderr(&ci));
    assert!(stdout(&ci).contains("team"), "{}", stdout(&ci));
    assert!(!stdout(&ci).contains("mine"), "{}", stdout(&ci));
}

#[test]
fn overrides_without_a_marker_stop_runs_but_not_ci_emission() {
    let (project, vault_id) = project_with_team_value(r#"{"show":"node show.cjs"}"#);
    seed(
        &project,
        &vault_id,
        None,
        Some(&overrides_record(
            &vault_id,
            "default",
            r#""API_URL":"mine""#,
            "",
        )),
    );

    let run = lpm(&project)
        .args(["run", "show", "--no-cache"])
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(
        stderr(&run).contains("newer data is damaged"),
        "{}",
        stderr(&run)
    );

    let ci = lpm(&project)
        .args(["env", "print", "--ci"])
        .output()
        .unwrap();
    assert!(ci.status.success(), "{}", stderr(&ci));
    assert!(stdout(&ci).contains("team"));
}

#[test]
fn a_marker_listing_missing_overrides_stops_runs() {
    let (project, vault_id) = project_with_team_value(r#"{"show":"node show.cjs"}"#);
    seed(&project, &vault_id, Some(OVERRIDES_MARKER), None);

    let run = lpm(&project)
        .args(["run", "show", "--no-cache"])
        .output()
        .unwrap();

    assert!(!run.status.success());
    assert!(
        stderr(&run).contains(r#"missing record "overrides""#),
        "{}",
        stderr(&run)
    );
}

#[test]
fn an_unsupported_overrides_version_refuses_runs_and_writes() {
    let (project, vault_id) = project_with_team_value(r#"{"show":"node show.cjs"}"#);
    let newer = OVERRIDES_MARKER.replace(r#""version":1"#, r#""version":2"#);
    seed(&project, &vault_id, Some(&newer), None);

    let run = lpm(&project)
        .args(["run", "show", "--no-cache"])
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(
        stderr(&run).contains("personal overrides v2, which this LPM CLI doesn't support"),
        "{}",
        stderr(&run)
    );

    let set = lpm(&project)
        .args(["env", "set", "OTHER=value"])
        .output()
        .unwrap();
    assert!(!set.status.success());
    assert!(stderr(&set).contains("lpm self-update"), "{}", stderr(&set));
}

#[test]
fn a_changed_override_invalidates_the_task_cache() {
    let (project, vault_id) = project_with_team_value(r#"{"build":"node build.js"}"#);
    extend_lpm_json(
        &project,
        serde_json::json!({"tasks":{"build":{"cache":true,"inputs":["build.js"],"outputs":["dist/**"]}}}),
    );
    project.write_file(
        "build.js",
        r#"const fs = require('fs');
fs.mkdirSync('dist', {recursive: true});
fs.writeFileSync('dist/value.txt', String(process.env.API_URL));"#,
    );

    lpm(&project).args(["run", "build"]).assert().success();
    assert_eq!(project.read_file("dist/value.txt"), "team");

    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(
            &vault_id,
            "default",
            r#""API_URL":"mine""#,
            "",
        )),
    );
    std::fs::remove_dir_all(project.path().join("dist")).unwrap();
    lpm(&project).args(["run", "build"]).assert().success();

    assert_eq!(project.read_file("dist/value.txt"), "mine");
}

#[test]
fn env_ls_reports_effective_status_and_the_override_count() {
    let (project, vault_id) = project_with_team_value("{}");
    extend_lpm_json(
        &project,
        serde_json::json!({"envSchema":{"vars":{"API_URL":{"enum":["mine"]}}}}),
    );
    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(
            &vault_id,
            "default",
            r#""API_URL":"mine""#,
            "",
        )),
    );

    let output = lpm(&project)
        .args(["env", "ls", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    let listed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON document");
    let default = listed["environments"]
        .as_array()
        .and_then(|environments| {
            environments
                .iter()
                .find(|environment| environment["environment"] == "default")
        })
        .expect("default is listed");
    assert_eq!(default["personalOverrides"], 1);
    assert_eq!(default["schemaValid"], default["schemaTotal"]);
}

#[test]
fn check_attributes_a_failure_to_the_override_that_caused_it() {
    let (project, vault_id) = project_with_team_value("{}");
    extend_lpm_json(
        &project,
        serde_json::json!({"envSchema":{"vars":{"API_URL":{"format":"url"}}}}),
    );
    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(
            &vault_id,
            "default",
            r#""API_URL":"not a url""#,
            "",
        )),
    );

    let output = lpm(&project)
        .args(["env", "check", "--env=default", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let checked: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON document");
    let error = &checked["environments"][0]["errors"][0];
    assert_eq!(error["key"], "API_URL");
    assert_eq!(error["personalOverride"], true);
}
