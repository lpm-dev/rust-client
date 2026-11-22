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
        overrides: std::sync::Arc::new(overrides),
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
    assert_eq!(
        child.attribute_overrides(&mut [invalid]),
        [false],
        "removing the override wouldn't change the value"
    );
}

#[test]
fn an_error_an_override_caused_forgets_its_value() {
    let layers = layers(
        &[("API_URL", "https://team.example")],
        overrides(&[("API_URL", "fixture-not-a-url")], &[]),
    );
    let child = layers.compose(None, None).expect("compose");
    let mut errors = [error(
        "API_URL",
        lpm_env::ValidationErrorKind::InvalidFormat {
            expected: lpm_env::VarFormat::Url,
            got: "fixture-not-a-url".to_owned(),
        },
    )];

    assert_eq!(child.attribute_overrides(&mut errors), [true]);
    let shown = format!("{} {:?}", errors[0], errors[0]);
    assert!(!shown.contains("fixture-not-a-url"), "{shown}");
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

#[test]
fn debug_output_of_the_layers_and_the_composed_child_names_keys_and_never_values() {
    let layers = layers(
        &[("API_URL", "fixture-team")],
        overrides(&[("API_URL", "fixture-mine")], &[]),
    );
    let printed = format!("{layers:?}");
    assert!(!printed.contains("fixture-"), "{printed}");
    assert!(printed.contains("API_URL"), "{printed}");
    let child = layers.compose(None, None).expect("compose");
    let printed = format!("{child:?}");
    assert!(!printed.contains("fixture-"), "{printed}");
    assert!(printed.contains("API_URL"), "{printed}");
}
