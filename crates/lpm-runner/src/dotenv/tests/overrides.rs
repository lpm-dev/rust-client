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
        composed: None,
        vault_count: 0,
        vault_values: map(vars),
    }
}

fn error(key: &str, kind: lpm_env::ValidationErrorKind) -> lpm_env::ValidationError {
    lpm_env::ValidationError {
        key: key.to_owned(),
        kind,
        description: None,
        is_secret: false,
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
    env.insert_runtime("PORT".to_owned(), "5173".to_owned());

    assert_eq!(env.vars()["API_URL"], "mine");
    assert_eq!(env.vars()["SERVICE_ONLY"], "mine");
    assert_eq!(env.vars()["FROM_SERVICE"], "service");
    assert_eq!(env.vars()["PORT"], "5173", "runtime values beat overrides");
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
    let child = layers(&[("A", "0")], overrides(&[("A", "1")], &[]))
        .compose(None, None)
        .expect("compose");
    let composed = ProjectEnvLayers::already_composed(child, 0);

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
    let validate = |mut child: ChildEnv| {
        validate_child_env(
            &mut child,
            validator.as_ref(),
            lpm_env::EvalContext::default(),
            "/usr/bin",
            true,
        )
        .expect_err("both keys fail")
        .to_string()
    };
    let attributed = format!("(from a personal override on {THIS_MACHINE})");

    let child = layers(&[("TOKEN", "team")], personal.clone())
        .compose(None, None)
        .expect("compose");
    let message = validate(child);
    assert_eq!(message.matches(&attributed).count(), 2, "{message}");

    let mut replaced = layers(&[("TOKEN", "team")], personal)
        .compose(None, None)
        .expect("compose");
    replaced.insert_runtime("API_URL".to_owned(), "not a url".to_owned());
    replaced.insert_runtime("TOKEN".to_owned(), String::new());
    let message = validate(replaced);
    assert!(
        !message.contains("personal override"),
        "a later layer's value is its own, even when it equals the override's: {message}"
    );
}

#[test]
fn an_unset_is_blamed_only_for_the_value_it_left_missing() {
    let origins =
        OverrideOrigins::changing(&map(&[("PORT", "8080")]), &overrides(&[], &["PORT"]), false);
    let empty = HashMap::new();
    assert!(origins.caused(
        &error("PORT", lpm_env::ValidationErrorKind::Missing),
        &empty
    ));
    let invalid = error(
        "PORT",
        lpm_env::ValidationErrorKind::ConstraintViolation { constraint: "port" },
    );
    assert!(
        !origins.caused(&invalid, &empty),
        "an invalid value came from somewhere the unset didn't"
    );
}

#[test]
fn an_override_is_found_under_the_declared_spelling_where_the_host_ignores_case() {
    let origins = OverrideOrigins::changing(
        &HashMap::new(),
        &overrides(&[("api_url", "not a url")], &[]),
        true,
    );
    let invalid = error(
        "API_URL",
        lpm_env::ValidationErrorKind::ConstraintViolation { constraint: "url" },
    );
    assert!(origins.caused(&invalid, &map(&[("API_URL", "not a url")])));
    assert!(
        !OverrideOrigins::changing(
            &HashMap::new(),
            &overrides(&[("api_url", "not a url")], &[]),
            false
        )
        .caused(&invalid, &map(&[("API_URL", "not a url")]))
    );
}

#[test]
fn the_count_includes_only_overrides_that_change_the_environment() {
    let layers = layers(
        &[("SENTRY_DSN", "team"), ("REGION", "eu")],
        overrides(
            &[
                ("API_URL", "mine"),
                ("NODE_OPTIONS", "--inspect"),
                ("REGION", "eu"),
            ],
            &["SENTRY_DSN", "NOT_IN_THE_PROJECT", "CLASSPATH"],
        ),
    );
    assert_eq!(
        layers.override_count(),
        2,
        "a set of the value the project already has changes nothing"
    );
    let child = layers.compose(None, None).expect("compose");
    assert_eq!(child.override_count(), 2);
}

#[test]
fn an_override_of_the_value_the_project_has_is_never_blamed() {
    let layers = layers(
        &[("API_URL", "not a url")],
        overrides(&[("API_URL", "not a url")], &[]),
    );
    let child = layers.compose(None, None).expect("compose");
    let invalid = error(
        "API_URL",
        lpm_env::ValidationErrorKind::ConstraintViolation { constraint: "url" },
    );
    assert!(
        !child.caused_by_override(&invalid),
        "removing the override wouldn't change the value"
    );
}

#[test]
fn the_notice_counts_overrides_without_naming_them() {
    assert_eq!(personal_override_notice(0, "development"), None);
    assert_eq!(
        personal_override_notice(1, "development"),
        Some(format!(
            "1 personal override on {THIS_MACHINE} applies to development"
        ))
    );
    assert_eq!(
        personal_override_notice(2, "dev\u{1b}[31m"),
        Some(format!(
            "2 personal overrides on {THIS_MACHINE} apply to dev"
        )),
        "terminal controls never reach the notice"
    );
    assert_eq!(
        THIS_MACHINE,
        if cfg!(target_os = "macos") {
            "this Mac"
        } else {
            "this computer"
        }
    );
}

#[test]
fn stored_value_characters_lists_vault_values_then_personal_overrides_by_key() {
    let checked = layers(
        &[("B_KEY", "b\u{200B}"), ("A_KEY", " a"), ("CLEAN", "value")],
        overrides(&[("B_KEY", "mine\u{A0}"), ("CLEAN", "fine")], &["A_KEY"]),
    )
    .stored_value_characters();
    let listed: Vec<(&str, bool, &str)> = checked
        .iter()
        .map(|stored| {
            (
                stored.key.as_str(),
                stored.personal_override,
                stored.characters.characters[0].character.name(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("A_KEY", false, "SPACE"),
            ("B_KEY", false, "ZERO WIDTH SPACE"),
            ("B_KEY", true, "NO-BREAK SPACE"),
        ]
    );
}
