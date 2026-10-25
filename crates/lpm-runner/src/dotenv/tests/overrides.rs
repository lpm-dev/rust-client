//! Personal overrides as layer 4 of a project's environment.

use super::*;

fn map(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn overrides(set: &[(&str, &str)], unset: &[&str]) -> PersonalOverrides {
    PersonalOverrides {
        set: map(set),
        unset: unset.iter().map(|name| (*name).to_owned()).collect(),
    }
}

fn layers(vars: &[(&str, &str)], overrides: PersonalOverrides) -> ProjectEnvLayers {
    ProjectEnvLayers {
        vars: map(vars),
        overrides,
        overrides_applied: false,
        vault_count: 0,
    }
}

#[test]
fn overrides_beat_team_and_service_values_and_lose_to_runtime_values() {
    let layers = layers(
        &[
            ("API_URL", "team"),
            ("PORT", "3000"),
            ("SERVICE_ONLY", "team"),
        ],
        overrides(
            &[
                ("API_URL", "mine"),
                ("SERVICE_ONLY", "mine"),
                ("PORT", "4000"),
            ],
            &[],
        ),
    );

    let mut env = layers
        .compose_service(&map(&[
            ("SERVICE_ONLY", "service"),
            ("FROM_SERVICE", "service"),
        ]))
        .expect("compose");
    insert_project_env(&mut env, "PORT".to_owned(), "5173".to_owned());

    assert_eq!(env["API_URL"], "mine");
    assert_eq!(env["SERVICE_ONLY"], "mine");
    assert_eq!(env["FROM_SERVICE"], "service");
    assert_eq!(env["PORT"], "5173", "runtime values beat overrides");
}

#[test]
fn unset_removes_the_project_value_and_an_empty_string_is_a_value() {
    let mut vars = map(&[("SENTRY_DSN", "team"), ("FEATURE", "on")]);
    apply_personal_overrides(&mut vars, &overrides(&[("FEATURE", "")], &["SENTRY_DSN"]));

    assert!(!vars.contains_key("SENTRY_DSN"));
    assert_eq!(vars["FEATURE"], "");
}

#[test]
fn overrides_match_names_without_case_where_the_host_ignores_case() {
    let mut vars = map(&[
        ("api_url", "team"),
        ("Sentry_Dsn", "team"),
        ("KEEP", "team"),
    ]);
    apply_overrides_with_case_policy(
        &mut vars,
        &overrides(&[("API_URL", "mine")], &["SENTRY_DSN"]),
        true,
    );

    assert_eq!(vars, map(&[("API_URL", "mine"), ("KEEP", "team")]));

    let mut exact = map(&[("api_url", "team")]);
    apply_overrides_with_case_policy(&mut exact, &overrides(&[("API_URL", "mine")], &[]), false);
    assert_eq!(exact, map(&[("api_url", "team"), ("API_URL", "mine")]));
}

#[test]
fn non_ascii_names_use_the_hosts_own_comparison() {
    let mut vars = map(&[("ÄPI", "team"), ("API", "team")]);
    apply_overrides_with_case_policy(&mut vars, &overrides(&[("API", "mine")], &[]), true);

    assert_eq!(vars["API"], "mine");
    assert_eq!(vars["ÄPI"], "team");
}

#[test]
fn composed_layers_refuse_service_values_after_the_overrides() {
    let composed = ProjectEnvLayers::already_composed(
        ComposedProjectEnv {
            vars: map(&[("A", "1")]),
            overrides: overrides(&[("A", "1")], &[]),
        },
        0,
    );

    assert!(composed.compose(None, Some("api")).is_err());
}

#[test]
fn validation_failures_name_an_override_only_while_it_is_the_final_origin() {
    let config = lpm_json::parse_lpm_json(
        r#"{"envSchema":{"vars":{"API_URL":{"format":"url"},"TOKEN":{"required":true}}}}"#,
    )
    .expect("schema");
    let validator = config.env_schema.as_ref().map(lpm_env::EnvValidator::new);
    let personal = overrides(&[("API_URL", "not a url")], &["TOKEN"]);

    let mut vars = map(&[("API_URL", "not a url")]);
    let error = validate_child_env(
        &mut vars,
        validator.as_ref(),
        lpm_env::EvalContext::default(),
        "/usr/bin",
        true,
        &personal,
    )
    .expect_err("both keys fail");
    let message = error.to_string();
    assert_eq!(
        message
            .matches("(from a personal override on this Mac)")
            .count(),
        2,
        "{message}"
    );

    let mut replaced = map(&[("API_URL", "still not a url"), ("TOKEN", "")]);
    let error = validate_child_env(
        &mut replaced,
        validator.as_ref(),
        lpm_env::EvalContext::default(),
        "/usr/bin",
        true,
        &personal,
    )
    .expect_err("a later layer's value still fails");
    assert!(!error.to_string().contains("personal override"), "{error}");
}

#[test]
fn the_notice_counts_overrides_without_naming_them() {
    assert_eq!(personal_override_notice(0, "development"), None);
    assert_eq!(
        personal_override_notice(1, "development").as_deref(),
        Some("1 personal override on this Mac applies to development")
    );
    assert_eq!(
        personal_override_notice(2, "dev\u{1b}[31m").as_deref(),
        Some("2 personal overrides on this Mac apply to dev"),
        "terminal controls never reach the notice"
    );
}
