#![cfg(debug_assertions)]

//! Workflow tests for personal overrides: values one machine sets on top of
//! an env project's team values. `lpm env override` writes them; tests of
//! states no command leaves, such as damage or a newer version, seed the
//! file store the `lpm` process reads, the way another client would.

mod support;

use lpm_runner::dotenv::{personal_override_notice, personal_overrides_here};
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
    // These tests plant the feature marker they need, so the project keeps no
    // local history whose records the planted marker wouldn't list.
    lpm(&project)
        .args(["env", "history", "off", "--yes"])
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
    assert!(stderr.contains(&personal_overrides_here(1)), "{stderr}");
    assert!(
        !stderr.contains("API_URL"),
        "names stay out by default: {stderr}"
    );
}

#[test]
fn an_override_of_the_marker_variable_is_neither_applied_nor_counted() {
    let (project, vault_id) = project_with_team_value(r#"{"marker":"node marker.cjs"}"#);
    project.write_file(
        "marker.cjs",
        "console.log(`marker=${process.env.LPM_PERSONAL_OVERRIDES_MARKER ?? 'none'}`)",
    );
    let refused = lpm(&project)
        .args([
            "env",
            "override",
            "set",
            "LPM_PERSONAL_OVERRIDES_MARKER=fixture-elsewhere",
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("LPM never passes a value for LPM_PERSONAL_OVERRIDES_MARKER"),
        "{}",
        stderr(&refused)
    );
    // As an earlier LPM CLI could have stored it.
    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(
            &vault_id,
            "default",
            r#""LPM_PERSONAL_OVERRIDES_MARKER":"fixture-elsewhere""#,
            "",
        )),
    );

    let output = lpm(&project)
        .env_remove("LPM_PERSONAL_OVERRIDES_MARKER")
        .args(["run", "marker", "--no-cache"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("marker=none"),
        "{}",
        stdout(&output)
    );
    assert!(
        !stderr(&output).contains(&personal_overrides_here(1)),
        "nothing it changed reached the script: {}",
        stderr(&output)
    );
}

#[test]
fn a_schema_rule_never_sees_the_marker_lpm_passes_a_task() {
    let (project, _) = project_with_team_value(r#"{"marker":"node marker.cjs"}"#);
    project.write_file(
        "marker.cjs",
        "console.log(`marker=${process.env.LPM_PERSONAL_OVERRIDES_MARKER ?? 'none'}`)",
    );
    extend_lpm_json(
        &project,
        serde_json::json!({"envSchema": {"vars": {
            "LPM_PERSONAL_OVERRIDES_MARKER": {"enum": ["fixture-only"]}
        }}}),
    );
    let inherited = project.path().join("outer-marker");
    std::fs::create_dir_all(&inherited).expect("an outer lpm's marker");

    let output = lpm(&project)
        .env("LPM_PERSONAL_OVERRIDES_MARKER", &inherited)
        .args(["run", "marker", "--no-cache"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains(&format!("marker={}", inherited.display())),
        "{}",
        stdout(&output)
    );
    assert!(
        !stderr(&output).contains("outer-marker"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn neither_a_project_value_nor_a_schema_default_names_the_marker_variable() {
    let (project, _) = project_with_team_value(r#"{"marker":"node marker.cjs"}"#);
    project.write_file(
        "marker.cjs",
        "console.log(`marker=${process.env.LPM_PERSONAL_OVERRIDES_MARKER ?? 'none'}`)",
    );
    let stored = lpm(&project)
        .args(["env", "set", "LPM_PERSONAL_OVERRIDES_MARKER=fixture-stored"])
        .output()
        .unwrap();
    assert!(
        stderr(&stored).contains(
            "LPM never passes a project's value for LPM_PERSONAL_OVERRIDES_MARKER to processes"
        ),
        "{}",
        stderr(&stored)
    );
    extend_lpm_json(
        &project,
        serde_json::json!({"envSchema": {"vars": {
            "LPM_PERSONAL_OVERRIDES_MARKER": {"default": "fixture-default"}
        }}}),
    );

    let output = lpm(&project)
        .env_remove("LPM_PERSONAL_OVERRIDES_MARKER")
        .args(["run", "marker", "--no-cache"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("marker=none"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn an_override_of_the_team_value_changes_nothing_and_goes_unannounced() {
    let (project, vault_id) = project_with_team_value(r#"{"show":"node show.cjs"}"#);
    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(
            &vault_id,
            "default",
            r#""API_URL":"team""#,
            "",
        )),
    );

    let output = lpm(&project)
        .args(["run", "show", "--no-cache"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("API_URL=team"),
        "{}",
        stdout(&output)
    );
    let stderr = stderr(&output);
    assert!(!stderr.contains("personal override"), "{stderr}");
}

#[test]
fn tasks_and_parallel_runs_say_once_that_overrides_apply() {
    let (project, vault_id) =
        project_with_team_value(r#"{"show":"node show.cjs","again":"node show.cjs"}"#);
    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(
            &vault_id,
            "default",
            r#""API_URL":"mine""#,
            r#""NOT_IN_THE_PROJECT""#,
        )),
    );
    extend_lpm_json(
        &project,
        serde_json::json!({"tasks": {"show": {"cache": true, "inputs": ["show.cjs"], "outputs": []}}}),
    );

    for args in [
        &["run", "show"][..],
        &["run", "show", "again", "--parallel", "--no-cache"][..],
    ] {
        let output = lpm(&project).args(args).output().unwrap();
        let stderr = stderr(&output);
        assert!(output.status.success(), "{args:?}: {stderr}");
        assert!(stdout(&output).contains("API_URL=mine"), "{args:?}");
        assert_eq!(
            stderr.matches("1 personal override on").count(),
            1,
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn a_file_run_directly_applies_a_personal_override_and_says_so_once() {
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

    let output = lpm(&project).args(["show.cjs"]).output().unwrap();

    let stderr = stderr(&output);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stdout(&output).contains("API_URL=mine"),
        "{}",
        stdout(&output)
    );
    assert_eq!(
        stderr.matches("1 personal override on").count(),
        1,
        "{stderr}"
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
    assert!(
        stderr(&printed).contains(&personal_overrides_here(1)),
        "{}",
        stderr(&printed)
    );

    for ci_args in [
        &["env", "print", "--ci"][..],
        &["env", "print", "--format=github-actions"],
    ] {
        let ci = lpm(&project).args(ci_args).output().unwrap();
        assert!(ci.status.success(), "{ci_args:?}: {}", stderr(&ci));
        assert!(stdout(&ci).contains("team"), "{ci_args:?}: {}", stdout(&ci));
        assert!(
            !stdout(&ci).contains("mine"),
            "{ci_args:?}: {}",
            stdout(&ci)
        );
        assert!(
            !stderr(&ci).contains(&personal_overrides_here(1)),
            "{ci_args:?}: {}",
            stderr(&ci)
        );
    }
}

#[test]
fn a_filtered_print_counts_only_the_overrides_of_the_names_it_prints() {
    let (project, _) = project_with_team_value("{}");
    lpm(&project)
        .args([
            "env",
            "set",
            "NEXT_PUBLIC_APP=team",
            "NEXT_PUBLIC_GONE=team",
        ])
        .assert()
        .success();
    extend_lpm_json(
        &project,
        serde_json::json!({"envSchema": {"vars": {
            "API_URL": {},
            "NEXT_PUBLIC_APP": {"client": true},
            "NEXT_PUBLIC_GONE": {"client": true},
        }}}),
    );
    lpm(&project)
        .args(["env", "override", "set", "API_URL=mine", "EXTRA=mine"])
        .assert()
        .success();
    lpm(&project)
        .args(["env", "override", "unset", "NEXT_PUBLIC_GONE"])
        .assert()
        .success();

    let notice = |args: &[&str]| {
        let output = lpm(&project).args(args).output().unwrap();
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        stderr(&output)
    };
    for (args, count) in [
        (&["env", "print"][..], 3),
        (&["env", "print", "--schema-only"], 2),
        (&["env", "print", "--client-only"], 1),
    ] {
        let shown = notice(args);
        let expected = personal_override_notice(count, "default").expect("a notice");
        assert!(
            shown.contains(&format!("lpm: {expected}")),
            "{args:?} prints the names of {count} overrides: {shown}"
        );
    }

    let printed = lpm(&project)
        .args(["env", "print", "--client-only"])
        .output()
        .unwrap();
    assert!(
        !stdout(&printed).contains("NEXT_PUBLIC_GONE"),
        "the unset leaves the key out of what's printed: {}",
        stdout(&printed)
    );

    let log = notice(&["--verbose", "env", "print", "--client-only"]);
    let named = log
        .lines()
        .find(|line| line.contains("personal overrides apply to:"))
        .unwrap_or_else(|| panic!("--verbose names the overrides: {log}"));
    assert!(
        named
            .trim_end()
            .ends_with("personal overrides apply to: NEXT_PUBLIC_GONE"),
        "the client output shows only NEXT_PUBLIC_GONE's change: {named}"
    );

    lpm(&project)
        .args(["env", "override", "remove", "NEXT_PUBLIC_GONE"])
        .assert()
        .success();
    let shown = notice(&["env", "print", "--client-only"]);
    assert!(
        !shown.contains("personal override"),
        "no override changes a client value: {shown}"
    );
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
    let message = stderr(&run);
    assert!(
        message.contains(r#"missing record "overrides""#),
        "{message}"
    );
    assert!(message.contains("lpm env repair"), "{message}");
    assert!(
        !message.contains("Environment validation failed"),
        "{message}"
    );
    assert!(!message.contains("--no-env-check"), "{message}");
}

#[test]
fn a_repair_that_can_t_report_its_change_to_overrides_changes_nothing() {
    let (project, vault_id) = project_with_team_value(r#"{"show":"node show.cjs"}"#);
    seed(&project, &vault_id, Some(OVERRIDES_MARKER), None);

    let refused = lpm(&project)
        .env("LPM_PERSONAL_OVERRIDES_MARKER", not_a_marker(&project))
        .args(["env", "repair", "--yes", "--json"])
        .output()
        .unwrap();

    assert!(!refused.status.success());
    let json: serde_json::Value = serde_json::from_slice(&refused.stdout).expect("JSON");
    assert_eq!(
        json["error_code"], "personal_overrides_unreported",
        "{json}"
    );
    let review = lpm(&project)
        .env_remove("LPM_PERSONAL_OVERRIDES_MARKER")
        .args(["env", "repair", "--json"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&review.stdout).expect("JSON");
    assert_eq!(
        json["problems"][0]["damage"], "missing record \"overrides\"",
        "the damage is still there: {json}"
    );
}

#[test]
fn env_repair_reviews_then_repairs_a_damaged_feature() {
    let (project, vault_id) = project_with_team_value(r#"{"show":"node show.cjs"}"#);
    seed(&project, &vault_id, Some(OVERRIDES_MARKER), None);

    let review = lpm(&project)
        .args(["env", "repair", "--json"])
        .output()
        .unwrap();
    assert!(!review.status.success());
    let json: serde_json::Value = serde_json::from_slice(&review.stdout).expect("JSON");
    assert_eq!(
        json["problems"],
        serde_json::json!([{
            "damage": "missing record \"overrides\"",
            "repair": {"action": "removeFeature", "feature": "overrides"},
        }])
    );
    assert_eq!(json["repaired"], serde_json::json!([]));

    let unattended = lpm(&project).args(["env", "repair"]).output().unwrap();
    assert!(!unattended.status.success());
    assert!(
        stderr(&unattended).contains("lpm env repair --yes"),
        "{}",
        stderr(&unattended)
    );

    let repair = lpm(&project)
        .args(["env", "repair", "--yes", "--json"])
        .output()
        .unwrap();
    assert!(repair.status.success(), "{}", stderr(&repair));
    let json: serde_json::Value = serde_json::from_slice(&repair.stdout).expect("JSON");
    assert_eq!(
        json["repaired"],
        serde_json::json!([{"action": "removeFeature", "feature": "overrides"}])
    );

    let run = lpm(&project)
        .args(["run", "show", "--no-cache"])
        .output()
        .unwrap();
    assert!(run.status.success(), "{}", stderr(&run));
    assert!(stdout(&run).contains("API_URL=team"), "{}", stdout(&run));

    let healthy = lpm(&project)
        .args(["env", "repair", "--json"])
        .output()
        .unwrap();
    assert!(healthy.status.success(), "{}", stderr(&healthy));
    let json: serde_json::Value = serde_json::from_slice(&healthy.stdout).expect("JSON");
    assert_eq!(json["problems"], serde_json::json!([]));
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

/// What `lpm run show` prints and reports after `lpm env debug-companion`
/// planted `state`.
fn run_after_planting(project: &TempProject, state: &[&str]) -> (String, String) {
    let planted = lpm(project)
        .args(["env", "debug-companion"])
        .args(state)
        .output()
        .unwrap();
    assert!(planted.status.success(), "{state:?}: {}", stderr(&planted));
    let run = lpm(project)
        .args(["run", "show", "--no-cache"])
        .output()
        .unwrap();
    (stdout(&run), stderr(&run))
}

#[test]
fn planted_companion_states_reach_the_cli_as_described() {
    let (project, _) = project_with_team_value(r#"{"show":"node show.cjs"}"#);

    let (out, err) = run_after_planting(&project, &["overrides", "--set", "API_URL=mine"]);
    assert!(out.contains("API_URL=mine"), "{out}");
    assert!(err.contains("1 personal override"), "{err}");

    let (_, err) = run_after_planting(&project, &["missing-record"]);
    assert!(err.contains("missing record \"overrides\""), "{err}");
    let repaired = lpm(&project)
        .args(["env", "repair", "--yes"])
        .output()
        .unwrap();
    assert!(repaired.status.success(), "{}", stderr(&repaired));

    let (_, err) = run_after_planting(&project, &["newer-version"]);
    assert!(err.contains("lpm self-update"), "{err}");

    let (out, err) = run_after_planting(&project, &["interrupted-deletion"]);
    assert!(out.contains("API_URL=team"), "{out}");
    assert!(err.contains("finished deleting"), "{err}");

    let (out, err) = run_after_planting(&project, &["clear"]);
    assert!(out.contains("API_URL=team"), "{out}");
    assert!(!err.contains("personal override"), "{err}");

    for keychain_only in [
        "contradictory-record",
        "weak-values",
        "orphans",
        "stuck-restore",
    ] {
        let refused = lpm(&project)
            .args(["env", "debug-companion", keychain_only])
            .output()
            .unwrap();
        assert!(!refused.status.success(), "{keychain_only}");
        assert!(
            stderr(&refused).contains("macOS Keychain"),
            "{}",
            stderr(&refused)
        );
    }
    let help = lpm(&project).args(["env", "--help"]).output().unwrap();
    assert!(
        !stdout(&help).contains("debug-companion") && !stderr(&help).contains("debug-companion"),
        "the command stays out of help"
    );
}

#[test]
fn check_reports_hidden_characters_in_a_personal_override_as_one() {
    let (project, vault_id) = project_with_team_value("{}");
    extend_lpm_json(
        &project,
        serde_json::json!({"envSchema":{"vars":{"API_URL":{}}}}),
    );
    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(
            &vault_id,
            "default",
            "\"API_URL\":\"mine\\u200b\"",
            "",
        )),
    );

    let json = lpm(&project)
        .args(["env", "check", "--env=default", "--json"])
        .output()
        .unwrap();
    assert!(json.status.success(), "{}", stdout(&json));
    let checked: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("one JSON document");
    let warning = &checked["environments"][0]["value_warnings"][0];
    assert_eq!(warning["key"], "API_URL");
    assert_eq!(warning["personal_override"], true);
    assert_eq!(warning["characters"][0]["name"], "ZERO WIDTH SPACE");
    assert_eq!(warning["characters"][0]["runs"][0]["position"], 5);

    let human = lpm(&project)
        .args(["env", "check", "--env=default"])
        .output()
        .unwrap();
    assert!(human.status.success());
    assert!(
        stdout(&human).contains(&format!(
            "API_URL (a personal override on {}) has characters that are hard to see",
            lpm_runner::dotenv::THIS_MACHINE
        )),
        "{}",
        stdout(&human)
    );
}

// ─── lpm env override ─────────────────────────────────────────────────

const ACTIVATION_NOTICE: &str = "LPM CLI releases 0.82.0 to 0.88.0 apply personal overrides but can share outputs built with them, through the remote task cache and `lpm env print --format=github-actions`; this build and later releases keep them on this computer, and an LPM CLI older than 0.82.0 runs this project with team values";

fn shown(project: &TempProject, script: &str) -> String {
    let output = lpm(project).args(["run", script]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    stdout(&output)
}

fn team_value(project: &TempProject, key: &str) -> String {
    let output = lpm(project)
        .args(["--json", "env", "get", key, "--reveal"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    value["value"].as_str().expect("a value").to_owned()
}

fn listed(project: &TempProject, args: &[&str]) -> serde_json::Value {
    let output = lpm(project)
        .args(["--json", "env", "override", "list"])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    serde_json::from_slice(&output.stdout).expect("one JSON document")
}

#[test]
fn override_commands_change_what_a_run_gets_and_never_the_team_value() {
    let (project, _) = project_with_team_value(r#"{"show":"node show.cjs"}"#);

    let set = lpm(&project)
        .args(["env", "override", "set", "API_URL", "--stdin"])
        .write_stdin("mine\n")
        .output()
        .unwrap();
    assert!(set.status.success(), "{}", stderr(&set));
    assert!(stderr(&set).contains(ACTIVATION_NOTICE), "{}", stderr(&set));
    assert!(shown(&project, "show").contains("API_URL=mine"));
    assert_eq!(team_value(&project, "API_URL"), "team");

    let again = lpm(&project)
        .args(["env", "override", "set", "API_URL=again"])
        .output()
        .unwrap();
    assert!(again.status.success(), "{}", stderr(&again));
    assert!(
        !stderr(&again).contains(ACTIVATION_NOTICE),
        "the notice comes with the project's first override only"
    );

    lpm(&project)
        .args(["env", "override", "unset", "API_URL"])
        .assert()
        .success();
    assert!(shown(&project, "show").contains("API_URL=undefined"));

    let removed = lpm(&project)
        .args(["--json", "env", "override", "remove", "API_URL"])
        .output()
        .unwrap();
    assert!(removed.status.success(), "{}", stderr(&removed));
    let envelope: serde_json::Value = serde_json::from_slice(&removed.stdout).unwrap();
    insta::assert_json_snapshot!(envelope, @r#"
    {
      "success": true,
      "env": "default",
      "changes": [
        {
          "key": "API_URL",
          "previous": "unset",
          "changed": true
        }
      ],
      "activated": false,
      "over_admission_target": false
    }
    "#);
    assert!(shown(&project, "show").contains("API_URL=team"));
    assert_eq!(listed(&project, &[])["environments"], serde_json::json!([]));
}

#[test]
fn override_set_reports_each_key_and_its_hidden_characters_as_json() {
    let (project, _) = project_with_team_value("{}");
    project.write_file("local-url.txt", "http://localhost:4000\n");
    let set = lpm(&project)
        .args([
            "--json",
            "env",
            "override",
            "set",
            "API_URL",
            "--stdin",
            "--from-file",
            "LOCAL_URL=local-url.txt",
        ])
        .write_stdin("fixture\u{200B}value")
        .output()
        .unwrap();
    assert!(set.status.success(), "{}", stderr(&set));
    let envelope: serde_json::Value = serde_json::from_slice(&set.stdout).unwrap();
    assert!(!envelope.to_string().contains("fixture"));
    assert!(!envelope.to_string().contains("localhost"));
    insta::assert_json_snapshot!(envelope, @r#"
    {
      "success": true,
      "env": "default",
      "changes": [
        {
          "key": "API_URL",
          "previous": "none",
          "changed": true
        },
        {
          "key": "LOCAL_URL",
          "previous": "none",
          "changed": true
        }
      ],
      "activated": true,
      "over_admission_target": false,
      "value_warnings": [
        {
          "key": "API_URL",
          "characters": [
            {
              "kind": "invisible",
              "code_point": "U+200B",
              "escape": "\\u{200b}",
              "name": "ZERO WIDTH SPACE",
              "group": null,
              "count": 1,
              "runs": [
                {
                  "position": 8,
                  "count": 1
                }
              ]
            }
          ],
          "more": 0
        }
      ]
    }
    "#);
}

#[test]
fn override_set_without_a_value_or_a_terminal_fails_at_once() {
    let (project, _) = project_with_team_value("{}");
    let output = lpm(&project)
        .args(["env", "override", "set", "API_URL"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("`lpm env override set API_URL --stdin`"),
        "{}",
        stderr(&output)
    );
    assert_eq!(listed(&project, &[])["environments"], serde_json::json!([]));
}

#[test]
fn names_lpm_never_passes_are_refused_when_written() {
    let (project, _) = project_with_team_value("{}");
    for args in [
        &["env", "override", "set", "NODE_OPTIONS=--inspect"][..],
        &[
            "env",
            "override",
            "set",
            "java_tool_options=-javaagent:x.jar",
        ],
        &["env", "override", "unset", "PATH"],
    ] {
        let output = lpm(&project).args(args).output().unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(
            stderr(&output).contains("so it can't be a personal override"),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            !stderr(&output).contains("javaagent"),
            "{}",
            stderr(&output)
        );
    }
    assert_eq!(listed(&project, &[])["environments"], serde_json::json!([]));
}

#[test]
fn override_list_shows_names_unless_values_are_revealed() {
    let (project, _) = project_with_team_value("{}");
    lpm(&project)
        .args(["env", "override", "set", "API_URL=fixture-mine"])
        .assert()
        .success();
    lpm(&project)
        .args(["env", "override", "unset", "--env", "staging", "SENTRY_DSN"])
        .assert()
        .success();

    let hidden = listed(&project, &[]);
    assert!(!hidden.to_string().contains("fixture-mine"));
    insta::assert_json_snapshot!(hidden, @r#"
    {
      "success": true,
      "environments": [
        {
          "env": "default",
          "set": [
            {
              "key": "API_URL",
              "value": "••••••••",
              "passed": true
            }
          ],
          "unset": []
        },
        {
          "env": "staging",
          "set": [],
          "unset": [
            {
              "key": "SENTRY_DSN",
              "passed": true
            }
          ]
        }
      ]
    }
    "#);
    let revealed = listed(&project, &["--reveal", "--env", "default"]);
    assert_eq!(
        revealed["environments"],
        serde_json::json!([{"env": "default", "set": [{"key": "API_URL", "value": "fixture-mine", "passed": true}], "unset": []}])
    );

    let human = lpm(&project)
        .args(["env", "override", "list"])
        .output()
        .unwrap();
    assert!(human.status.success(), "{}", stderr(&human));
    let text = stdout(&human) + &stderr(&human);
    assert!(text.contains("API_URL"), "{text}");
    assert!(text.contains("SENTRY_DSN"), "{text}");
    assert!(!text.contains("fixture-mine"), "{text}");
}

#[test]
fn override_clear_asks_first_and_needs_yes_without_a_terminal() {
    let (project, _) = project_with_team_value("{}");
    lpm(&project)
        .args(["env", "override", "set", "API_URL=mine", "OTHER=mine"])
        .assert()
        .success();
    lpm(&project)
        .args([
            "env",
            "override",
            "set",
            "--env",
            "staging",
            "API_URL=staged",
        ])
        .assert()
        .success();

    let machine = if cfg!(target_os = "macos") {
        "this Mac"
    } else {
        "this computer"
    };
    let asked = lpm(&project)
        .args(["env", "override", "clear", "--env", "staging"])
        .output()
        .unwrap();
    assert!(!asked.status.success());
    assert!(
        stderr(&asked).contains(&format!(
            "change remove the personal overrides on {machine} (staging)\n"
        )),
        "{}",
        stderr(&asked)
    );
    let asked = lpm(&project)
        .args(["--json", "env", "override", "clear", "--all"])
        .output()
        .unwrap();
    assert!(!asked.status.success());
    let refused: serde_json::Value = serde_json::from_slice(&asked.stdout).unwrap();
    assert_eq!(
        refused["error"]["message"],
        format!(
            "`lpm env override clear` needs `--yes` to remove the personal overrides on {machine} (every environment) without asking"
        )
    );
    let (empty, _) = project_with_team_value("{}");
    let nothing = lpm(&empty)
        .args(["env", "override", "clear", "--all"])
        .output()
        .unwrap();
    assert!(
        !nothing.status.success(),
        "it never decides without asking, whatever there is: {}",
        stdout(&nothing)
    );
    assert_eq!(
        listed(&project, &[])["environments"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let cleared = lpm(&project)
        .args([
            "--json", "env", "override", "clear", "--env", "staging", "--yes",
        ])
        .output()
        .unwrap();
    assert!(cleared.status.success(), "{}", stderr(&cleared));
    let envelope: serde_json::Value = serde_json::from_slice(&cleared.stdout).unwrap();
    assert_eq!(
        envelope,
        serde_json::json!({"success": true, "env": "staging", "removed": 1})
    );

    let all = lpm(&project)
        .args(["--json", "env", "override", "clear", "--all", "--yes"])
        .output()
        .unwrap();
    assert!(all.status.success(), "{}", stderr(&all));
    let envelope: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
    assert_eq!(
        envelope,
        serde_json::json!({"success": true, "env": null, "removed": 2})
    );
    assert_eq!(listed(&project, &[])["environments"], serde_json::json!([]));

    let neither = lpm(&project)
        .args(["env", "override", "clear"])
        .output()
        .unwrap();
    assert!(!neither.status.success(), "clear needs --env or --all");
}

#[test]
fn override_commands_resolve_environment_aliases_as_env_set_does() {
    let (project, _) = project_with_team_value("{}");
    extend_lpm_json(
        &project,
        serde_json::json!({"env": {"dev": ".env.development"}}),
    );
    lpm(&project)
        .args(["env", "set", "--env", "dev", "API_URL=team-dev"])
        .assert()
        .success();
    lpm(&project)
        .args(["env", "override", "set", "--env", "dev", "API_URL=mine"])
        .assert()
        .success();
    assert_eq!(
        listed(&project, &[])["environments"][0]["env"],
        "development"
    );
    let printed = lpm(&project)
        .args(["env", "print", "--env", "dev"])
        .output()
        .unwrap();
    assert!(printed.status.success(), "{}", stderr(&printed));
    assert!(
        stderr(&printed).contains(&format!(
            "lpm: {} applies to development",
            personal_overrides_here(1)
        )),
        "the notice names the environment as runs do: {}",
        stderr(&printed)
    );
}

#[test]
fn overrides_need_an_env_project_with_values() {
    let project = TempProject::empty(r#"{"name":"no-env-project","version":"1.0.0"}"#);
    let output = lpm(&project)
        .args(["env", "override", "set", "API_URL=mine"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("store a value first: lpm env set KEY"),
        "{}",
        stderr(&output)
    );
    assert!(!project.path().join("lpm.json").exists());
}

#[test]
fn the_verbose_notice_names_only_the_overrides_that_change_the_run() {
    let (project, _) = project_with_team_value(r#"{"show":"node show.cjs"}"#);
    lpm(&project)
        .args(["env", "set", "SAME=team-same"])
        .assert()
        .success();
    lpm(&project)
        .args(["env", "override", "set", "API_URL=mine", "SAME=team-same"])
        .assert()
        .success();

    let output = lpm(&project)
        .args(["--verbose", "run", "show"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let log = stderr(&output);
    let named = log
        .lines()
        .find(|line| line.contains("personal overrides apply to:"))
        .unwrap_or_else(|| panic!("--verbose names the overrides: {log}"));
    assert!(
        named
            .trim_end()
            .ends_with("personal overrides apply to: API_URL"),
        "an override of the value the project has changes nothing, so it isn't named: {named}"
    );
}

#[test]
fn a_cached_task_says_once_that_overrides_apply_and_a_removed_override_restores_the_team_hit() {
    let (project, _) = project_with_team_value(r#"{"build":"node build.js"}"#);
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

    lpm(&project)
        .args(["env", "override", "set", "API_URL=mine"])
        .assert()
        .success();
    let built = lpm(&project).args(["run", "build"]).output().unwrap();
    assert!(built.status.success(), "{}", stderr(&built));
    assert_eq!(project.read_file("dist/value.txt"), "mine");
    let notice = format!("{} applies to default", personal_overrides_here(1));
    assert_eq!(
        stderr(&built).matches(&notice).count() + stdout(&built).matches(&notice).count(),
        1,
        "the cache key and the run read the overrides; the notice shows once: {}",
        stderr(&built)
    );

    lpm(&project)
        .args(["env", "override", "set", "API_URL=yours"])
        .assert()
        .success();
    lpm(&project).args(["run", "build"]).assert().success();
    assert_eq!(project.read_file("dist/value.txt"), "yours");

    lpm(&project)
        .args(["env", "override", "remove", "API_URL"])
        .assert()
        .success();
    std::fs::remove_dir_all(project.path().join("dist")).unwrap();
    lpm(&project).args(["run", "build"]).assert().success();
    assert_eq!(
        project.read_file("dist/value.txt"),
        "team",
        "without the override the key is the team's again"
    );
}

#[test]
fn export_and_copy_take_team_values_only() {
    let (project, _) = project_with_team_value("{}");
    lpm(&project)
        .args([
            "env",
            "override",
            "set",
            "API_URL=mine",
            "ONLY_HERE=personal",
        ])
        .assert()
        .success();

    lpm(&project)
        .args(["env", "export", "exported.env"])
        .assert()
        .success();
    let exported = project.read_file("exported.env");
    assert!(exported.contains("API_URL=team"), "{exported}");
    assert!(
        !exported.contains("mine") && !exported.contains("ONLY_HERE"),
        "{exported}"
    );

    lpm(&project)
        .args(["env", "export", "--ci", "ci.env"])
        .assert()
        .success();
    let ci = project.read_file("ci.env");
    assert!(!ci.contains("mine") && !ci.contains("ONLY_HERE"), "{ci}");

    lpm(&project)
        .args(["env", "copy", "default", "staging"])
        .assert()
        .success();
    let staged = lpm(&project)
        .args([
            "--json", "env", "get", "API_URL", "--reveal", "--env", "staging",
        ])
        .output()
        .unwrap();
    let staged: serde_json::Value = serde_json::from_slice(&staged.stdout).unwrap();
    assert_eq!(staged["value"], "team");
    let environments = listed(&project, &[])["environments"].clone();
    assert_eq!(environments.as_array().unwrap().len(), 1, "{environments}");
    assert_eq!(environments[0]["env"], "default");
}

#[test]
fn removing_or_clearing_without_overrides_or_values_removes_nothing_and_says_so() {
    let project = TempProject::empty(r#"{"name":"no-env-project","version":"1.0.0"}"#);
    let removed = lpm(&project)
        .args(["env", "override", "remove", "API_URL"])
        .output()
        .unwrap();
    assert!(removed.status.success(), "{}", stderr(&removed));
    assert!(
        stderr(&removed).contains("had no override (default); nothing to remove"),
        "{}",
        stderr(&removed)
    );
    let cleared = lpm(&project)
        .args(["--json", "env", "override", "clear", "--all", "--yes"])
        .output()
        .unwrap();
    assert!(cleared.status.success(), "{}", stderr(&cleared));
    let envelope: serde_json::Value = serde_json::from_slice(&cleared.stdout).unwrap();
    assert_eq!(envelope["removed"], 0);
    let cleared = lpm(&project)
        .args(["env", "override", "clear", "--all", "--yes"])
        .output()
        .unwrap();
    assert!(
        stderr(&cleared).contains("no personal overrides to remove (every environment)"),
        "lower case, as its sibling lines are: {}",
        stderr(&cleared)
    );
    let asked = lpm(&project)
        .args(["env", "override", "clear", "--env", "default"])
        .output()
        .unwrap();
    assert!(
        !asked.status.success() && stderr(&asked).contains("Confirmation required"),
        "without a terminal it needs --yes before it reads anything: {}",
        stderr(&asked)
    );
    assert!(!project.path().join("lpm.json").exists());
}

#[test]
fn an_unusable_vault_field_is_named_by_every_override_command() {
    let project = TempProject::empty(r#"{"name":"bad-vault-field","version":"1.0.0"}"#);
    project.write_file("lpm.json", r#"{"vault":"../outside"}"#);
    for args in [
        &["env", "override", "set", "API_URL=fixture-mine"][..],
        &["env", "override", "unset", "API_URL"],
        &["env", "override", "remove", "API_URL"],
        &["env", "override", "list"],
        &["env", "override", "clear", "--all", "--yes"],
    ] {
        let output = lpm(&project).args(args).output().unwrap();
        assert!(!output.status.success(), "{args:?}: {}", stdout(&output));
        let said = stderr(&output);
        assert!(said.contains("path-traversal"), "{args:?}: {said}");
        assert!(!said.contains("no env project"), "{args:?}: {said}");
    }
}

#[test]
fn a_key_named_twice_in_unset_or_remove_is_one_change() {
    let (project, _) = project_with_team_value("{}");
    lpm(&project)
        .args(["env", "override", "set", "API_URL=mine"])
        .assert()
        .success();
    let removed = lpm(&project)
        .args(["env", "override", "remove", "API_URL", "API_URL"])
        .output()
        .unwrap();
    assert!(removed.status.success(), "{}", stderr(&removed));
    let text = stdout(&removed) + &stderr(&removed);
    assert_eq!(text.matches("API_URL").count(), 1, "{text}");
    assert!(!text.contains("nothing to remove"), "{text}");

    let unset = lpm(&project)
        .args([
            "--json",
            "env",
            "override",
            "unset",
            "SENTRY_DSN",
            "SENTRY_DSN",
        ])
        .output()
        .unwrap();
    assert!(unset.status.success(), "{}", stderr(&unset));
    let envelope: serde_json::Value = serde_json::from_slice(&unset.stdout).unwrap();
    assert_eq!(envelope["changes"].as_array().map(Vec::len), Some(1));
}

#[test]
fn the_human_list_says_when_lpm_never_passes_an_unset_name_too() {
    let (project, vault_id) = project_with_team_value("{}");
    seed(
        &project,
        &vault_id,
        Some(OVERRIDES_MARKER),
        Some(&overrides_record(
            &vault_id,
            "default",
            "",
            r#""CLASSPATH""#,
        )),
    );
    let listed = lpm(&project)
        .args(["env", "override", "list"])
        .output()
        .unwrap();
    assert!(listed.status.success(), "{}", stderr(&listed));
    let text = stdout(&listed);
    let line = text
        .lines()
        .find(|line| line.contains("CLASSPATH"))
        .expect("the unset name is listed");
    assert!(line.contains("LPM never passes it to processes"), "{text}");
}

#[test]
fn the_override_commands_say_what_env_and_their_keys_mean() {
    for (command, said) in [
        ("list", "every environment when left out"),
        ("clear", "The environment whose overrides to remove"),
        ("set", "default when left out"),
        ("set", "don't use the remote"),
        ("unset", "The keys to leave out"),
        ("remove", "The keys whose override to remove"),
    ] {
        let project = TempProject::empty(r#"{"name":"help","version":"1.0.0"}"#);
        let help = lpm(&project)
            .args(["env", "override", command, "--help"])
            .output()
            .unwrap();
        assert!(help.status.success(), "{}", stderr(&help));
        assert!(stdout(&help).contains(said), "{command}: {}", stdout(&help));
    }
}

#[test]
fn override_set_says_what_is_wrong_with_its_arguments_before_it_looks_at_the_project() {
    let project = TempProject::empty(r#"{"name":"no-env-project","version":"1.0.0"}"#);
    let refused = lpm(&project)
        .args(["env", "override", "set", "API_URL", "API_URL"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let said = stderr(&refused);
    assert!(said.contains("API_URL"), "{said}");
    assert!(!said.contains("no env project"), "{said}");
}

#[test]
fn removing_an_override_and_an_empty_list_say_what_happened_where() {
    let (project, _) = project_with_team_value("{}");
    lpm(&project)
        .args([
            "env",
            "override",
            "set",
            "--env",
            "staging",
            "LOCAL_ONLY=mine",
        ])
        .assert()
        .success();

    let removed = lpm(&project)
        .args([
            "env",
            "override",
            "remove",
            "--env",
            "staging",
            "LOCAL_ONLY",
        ])
        .output()
        .unwrap();
    assert!(removed.status.success(), "{}", stderr(&removed));
    let said = format!("{}{}", stdout(&removed), stderr(&removed));
    assert!(
        said.contains("LOCAL_ONLY no longer has an override on"),
        "{said}"
    );
    assert!(!said.contains("the project's value"), "{said}");

    let empty = lpm(&project)
        .args(["env", "override", "list", "--env", "staging"])
        .output()
        .unwrap();
    assert!(empty.status.success(), "{}", stderr(&empty));
    assert!(
        stdout(&empty).contains("lpm env override set KEY --env=staging"),
        "{}",
        stdout(&empty)
    );
}

#[test]
fn an_environment_with_overrides_and_no_values_is_checked_and_listed() {
    let (project, _) = project_with_team_value("{}");
    extend_lpm_json(
        &project,
        serde_json::json!({"envSchema":{"vars":{"API_URL":{"format":"url"}}}}),
    );
    lpm(&project)
        .args(["env", "set", "API_URL=https://team.example"])
        .assert()
        .success();
    lpm(&project)
        .args([
            "env",
            "override",
            "set",
            "--env",
            "staging",
            "API_URL=not-a-url",
        ])
        .assert()
        .success();

    let checked = lpm(&project)
        .args(["--json", "env", "check"])
        .output()
        .unwrap();
    assert!(!checked.status.success(), "staging fails with its override");
    let checked: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    let staging = checked["environments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|environment| environment["environment"] == "staging")
        .unwrap_or_else(|| panic!("staging is checked: {checked}"));
    assert_eq!(staging["errors"][0]["key"], "API_URL");
    assert_eq!(staging["errors"][0]["personalOverride"], true);

    let listed = lpm(&project)
        .args(["env", "ls", "--json"])
        .output()
        .unwrap();
    assert!(listed.status.success(), "{}", stderr(&listed));
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    let staging = listed["environments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|environment| environment["environment"] == "staging")
        .unwrap_or_else(|| panic!("staging is listed: {listed}"));
    assert_eq!(staging["personalOverrides"], 1);
}

#[test]
fn override_writes_from_several_commands_at_once_all_land() {
    let (project, _) = project_with_team_value("{}");
    std::thread::scope(|scope| {
        let runs: Vec<_> = (0..6)
            .map(|index| {
                let project = &project;
                scope.spawn(move || {
                    lpm(project)
                        .args([
                            "env",
                            "override",
                            "set",
                            &format!("KEY_{index}=fixture-{index}"),
                        ])
                        .output()
                        .unwrap()
                })
            })
            .collect();
        for run in runs {
            let output = run.join().expect("the command ran");
            assert!(output.status.success(), "{}", stderr(&output));
        }
    });
    let set = listed(&project, &[])["environments"][0]["set"].clone();
    let keys: Vec<&str> = set
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, ["KEY_0", "KEY_1", "KEY_2", "KEY_3", "KEY_4", "KEY_5"]);
}

#[test]
fn a_warning_after_a_run_with_overrides_still_shows() {
    let (project, _) = project_with_team_value(r#"{"build":"node build.cjs"}"#);
    lpm(&project)
        .args(["env", "override", "set", "API_URL=mine"])
        .assert()
        .success();
    extend_lpm_json(
        &project,
        serde_json::json!({"tasks":{"build":{"cache":true,"outputs":["src/generated/**"]}}}),
    );
    project.write_file("src/index.ts", "export const value = 1;\n");
    project.write_file(
        "build.cjs",
        "const fs = require('fs');\nfs.mkdirSync('src/generated', {recursive: true});\nfs.writeFileSync('src/generated/value.js', String(Date.now()));",
    );

    let run = lpm(&project).args(["run", "build"]).output().unwrap();
    assert!(run.status.success(), "{}", stderr(&run));
    let text = stdout(&run) + &stderr(&run);
    assert!(text.contains(&personal_overrides_here(1)), "{text}");
    assert!(
        text.contains("writes src/generated/value.js, which its cache inputs also match"),
        "{text}"
    );
}

#[test]
fn a_failure_an_override_caused_never_shows_its_value() {
    let (project, _) = project_with_team_value(r#"{"show":"node show.cjs"}"#);
    extend_lpm_json(
        &project,
        serde_json::json!({"envSchema":{"vars":{"API_URL":{"format":"url"}}}}),
    );
    lpm(&project)
        .args(["env", "set", "API_URL=https://team.example"])
        .assert()
        .success();
    lpm(&project)
        .args(["env", "override", "set", "API_URL=fixture-not-a-url"])
        .assert()
        .success();
    for args in [
        &["env", "check"][..],
        &["--json", "env", "check"],
        &["run", "show"],
    ] {
        let output = lpm(&project).args(args).output().unwrap();
        assert!(!output.status.success(), "{args:?}");
        let text = stdout(&output) + &stderr(&output);
        assert!(text.contains("API_URL"), "{args:?}: {text}");
        assert!(!text.contains("fixture-not-a-url"), "{args:?}: {text}");
    }
}

/// A regular file where a marker would be, which no entry can be added to.
fn not_a_marker(project: &TempProject) -> std::path::PathBuf {
    let path = project.path().join("not-a-marker");
    std::fs::write(&path, "").expect("a file where a marker would be");
    path
}
