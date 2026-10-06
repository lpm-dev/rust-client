use crate::validate::validation_error;
use crate::{
    EnvSchema, EnvVarRule, RequiredWhen, ValidationError, ValidationErrorKind, VarFormat, VarGroup,
    VarGroupMode,
};
use std::collections::{HashMap, HashSet};

pub(crate) fn definition_errors(schema: &EnvSchema) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    for (key, rule) in &schema.vars {
        if let Some(message) = rule_definition_error(schema, rule) {
            errors.push(validation_error(
                key,
                rule,
                ValidationErrorKind::InvalidRule { message },
            ));
        }
    }
    if schema.groups.len() > 128
        || schema
            .groups
            .values()
            .try_fold(0usize, |total, group| total.checked_add(group.vars.len()))
            .is_none_or(|total| total > 4096)
    {
        errors.push(validation_error(
            "envSchema.groups",
            &EnvVarRule::default(),
            ValidationErrorKind::InvalidRule {
                message: "groups must contain at most 128 groups and 4096 total members",
            },
        ));
        errors.sort_by(|a, b| a.key.cmp(&b.key));
        return errors;
    }
    for (name, group) in &schema.groups {
        let mut members = HashSet::with_capacity(group.vars.len());
        let message = if name.len() > 256 || !crate::is_valid_env_var_name(name) {
            Some("group names must be portable environment variable names")
        } else if group.vars.is_empty() {
            Some("groups must contain at least one declared variable")
        } else if group
            .vars
            .iter()
            .any(|key| !schema.vars.contains_key(key) || !members.insert(key))
        {
            Some("group members must be unique declared variables")
        } else {
            None
        };
        if let Some(message) = message {
            errors.push(validation_error(
                &format!("envSchema.groups.{name}"),
                &EnvVarRule::default(),
                ValidationErrorKind::InvalidRule { message },
            ));
        }
    }
    errors.sort_by(|a, b| a.key.cmp(&b.key));
    errors
}

fn rule_definition_error(schema: &EnvSchema, rule: &EnvVarRule) -> Option<&'static str> {
    if rule.min.is_some() || rule.max.is_some() {
        if !matches!(rule.format, Some(VarFormat::Integer | VarFormat::Port)) {
            return Some("min and max require the integer or port format");
        }
        if matches!((rule.min, rule.max), (Some(min), Some(max)) if min > max) {
            return Some("min cannot exceed max");
        }
        if rule.format == Some(VarFormat::Port)
            && (rule.min.is_some_and(|min| min > 65535) || rule.max.is_some_and(|max| max < 1))
        {
            return Some("numeric bounds exclude every valid port");
        }
    }
    if matches!((rule.min_length, rule.max_length), (Some(min), Some(max)) if min > max) {
        return Some("minLength cannot exceed maxLength");
    }
    if let Some(protocols) = &rule.protocols {
        if rule.format != Some(VarFormat::Url) {
            return Some("protocols require the url format");
        }
        if protocols.is_empty() || protocols.len() > 32 {
            return Some("protocols must contain 1 to 32 unique lowercase URL schemes");
        }
        let mut unique = HashSet::with_capacity(protocols.len());
        if protocols
            .iter()
            .any(|protocol| !valid_protocol(protocol) || !unique.insert(protocol))
        {
            return Some("protocols must contain 1 to 32 unique lowercase URL schemes");
        }
    }
    if let Some(condition) = &rule.required_when {
        let Some(source) = schema.vars.get(condition.variable()) else {
            return Some("requiredWhen must reference a declared variable");
        };
        if let RequiredWhen::Equals(condition) = condition {
            if source.secret {
                return Some("requiredWhen cannot compare a secret source with a literal");
            }
            if !safe_text(&condition.equals) {
                return Some("schema text cannot contain unsafe control characters");
            }
        }
    }
    None
}

fn safe_text(value: &str) -> bool {
    !value
        .chars()
        .any(|character| matches!(character as u32, 0..=8 | 11..=12 | 14..=31 | 127..=159))
}

fn valid_protocol(value: &str) -> bool {
    value.len() <= 256
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')
        })
}

pub(crate) fn value_violation(value: &str, rule: &EnvVarRule) -> Option<&'static str> {
    if rule.min.is_some() || rule.max.is_some() {
        let integer: i64 = value.parse().ok()?;
        if rule.min.is_some_and(|min| integer < min) {
            return Some("min");
        }
        if rule.max.is_some_and(|max| integer > max) {
            return Some("max");
        }
    }
    if rule.min_length.is_some() || rule.max_length.is_some() {
        let limit = rule
            .max_length
            .or(rule.min_length)
            .map_or(usize::MAX, |limit| limit as usize);
        let count = value.chars().take(limit.saturating_add(1)).count();
        if rule.min_length.is_some_and(|min| count < min as usize) {
            return Some("minLength");
        }
        if rule.max_length.is_some_and(|max| count > max as usize) {
            return Some("maxLength");
        }
    }
    if let Some(protocols) = &rule.protocols {
        let scheme = value.split_once(':').map_or("", |(scheme, _)| scheme);
        if !protocols
            .iter()
            .any(|protocol| scheme.eq_ignore_ascii_case(protocol))
        {
            return Some("protocols");
        }
    }
    None
}

pub(crate) fn ordered_groups(schema: &EnvSchema) -> Vec<(&str, &VarGroup)> {
    if schema.groups.len() > 128
        || schema
            .groups
            .values()
            .try_fold(0usize, |total, group| total.checked_add(group.vars.len()))
            .is_none_or(|total| total > 4096)
    {
        return Vec::new();
    }
    let mut groups = Vec::with_capacity(schema.groups.len());
    groups.extend(
        schema
            .groups
            .iter()
            .map(|(name, group)| (name.as_str(), group)),
    );
    groups.sort_unstable_by_key(|(name, _)| *name);
    groups
}

pub(crate) fn validate_groups(
    schema: &EnvSchema,
    groups: &[(&str, &VarGroup)],
    values: &HashMap<String, String>,
    errors: &mut Vec<ValidationError>,
) {
    for &(name, group) in groups {
        let present = group
            .vars
            .iter()
            .filter(|key| values.get(*key).is_some_and(|value| !value.is_empty()))
            .count();
        let valid = match group.mode {
            VarGroupMode::AllOrNone => present == 0 || present == group.vars.len(),
            VarGroupMode::ExactlyOne => present == 1,
            VarGroupMode::AtLeastOne => present > 0,
        };
        if !valid {
            errors.extend(group.vars.iter().map(|key| ValidationError {
                key: key.clone(),
                kind: ValidationErrorKind::GroupViolation {
                    group: name.to_string(),
                    mode: group.mode,
                },
                description: None,
                is_secret: schema.is_secret(key),
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{EnvSchema, validate, validate_schema};
    use std::collections::HashMap;

    fn schema(input: &str) -> EnvSchema {
        serde_json::from_str(input).unwrap()
    }
    fn values(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn group_names_are_limited_to_256_bytes() {
        for length in [256, 257] {
            let name = "G".repeat(length);
            let schema = schema(&format!(
                r#"{{"vars":{{"A":{{}}}},"groups":{{"{name}":{{"mode":"atLeastOne","vars":["A"]}}}}}}"#
            ));
            assert_eq!(validate_schema(&schema).is_empty(), length == 256);
        }
    }

    #[test]
    fn group_diagnostics_explain_the_required_relationship() {
        let schema = schema(
            r#"{"vars":{"A":{},"B":{}},"groups":{"auth":{"mode":"exactlyOne","vars":["A","B"]}}}"#,
        );
        let errors = validate(&schema, &mut values(&[]));
        assert!(
            errors[0]
                .to_string()
                .contains("exactly one non-empty value")
        );
    }

    #[test]
    fn integer_bounds_preserve_exact_values_beyond_javascript_number_precision() {
        let definition = schema(
            r#"{"vars":{"COUNT":{"format":"integer","min":"9007199254740993","max":"9223372036854775807"}}}"#,
        );
        assert!(validate_schema(&definition).is_empty());
        assert!(!validate(&definition, &mut values(&[("COUNT", "9007199254740992")])).is_empty());
        assert!(validate(&definition, &mut values(&[("COUNT", "9007199254740993")])).is_empty());
        assert!(
            validate(
                &definition,
                &mut values(&[("COUNT", "9223372036854775807")])
            )
            .is_empty()
        );
        assert_eq!(
            serde_json::to_value(&definition).unwrap()["vars"]["COUNT"]["min"],
            "9007199254740993"
        );
    }

    #[test]
    fn length_constraints_count_unicode_scalars() {
        let definition = schema(r#"{"vars":{"TEXT":{"minLength":3,"maxLength":3}}}"#);
        assert!(validate(&definition, &mut values(&[("TEXT", "👩‍🚀")])).is_empty());
        for value in ["é", "e\u{0301}", "abcd"] {
            assert!(!validate(&definition, &mut values(&[("TEXT", value)])).is_empty());
        }
    }

    #[test]
    fn protocols_restrict_canonical_url_schemes() {
        let definition =
            schema(r#"{"vars":{"URL":{"format":"url","protocols":["https","postgres"]}}}"#);
        for value in ["HTTPS://example.test", "postgres://localhost/db"] {
            assert!(validate(&definition, &mut values(&[("URL", value)])).is_empty());
        }
        assert!(!validate(&definition, &mut values(&[("URL", "http://example.test")])).is_empty());
    }

    #[test]
    fn conditional_requirements_observe_every_injected_default() {
        let definition = schema(
            r#"{"vars":{"A_TOKEN":{"requiredWhen":{"variable":"Z_FEATURE","equals":"true"}},"Z_FEATURE":{"default":"true"}}}"#,
        );
        let errors = validate(&definition, &mut HashMap::new());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].key, "A_TOKEN");
    }

    #[test]
    fn presence_conditions_use_nonempty_values_and_equality_distinguishes_absence() {
        let definition = schema(
            r#"{"vars":{"A":{"requiredWhen":{"variable":"B","present":false}},"B":{"empty":"allow"},"C":{"requiredWhen":{"variable":"B","equals":""}}}}"#,
        );
        assert_eq!(validate(&definition, &mut values(&[("B", "")])).len(), 2);
        assert_eq!(validate(&definition, &mut HashMap::new()).len(), 1);
        assert!(validate(&definition, &mut values(&[("B", "x")])).is_empty());
    }

    #[test]
    fn groups_enforce_all_or_none_exactly_one_and_at_least_one() {
        for (mode, cases) in [
            (
                "allOrNone",
                [
                    (false, false, true),
                    (true, false, false),
                    (true, true, true),
                ],
            ),
            (
                "exactlyOne",
                [
                    (false, false, false),
                    (true, false, true),
                    (true, true, false),
                ],
            ),
            (
                "atLeastOne",
                [
                    (false, false, false),
                    (true, false, true),
                    (true, true, true),
                ],
            ),
        ] {
            let definition = schema(&format!(
                r#"{{"groups":{{"auth":{{"mode":"{mode}","vars":["A","B"]}}}},"vars":{{"A":{{}},"B":{{}}}}}}"#
            ));
            for (a, b, valid) in cases {
                let mut env = HashMap::new();
                if a {
                    env.insert("A".into(), "value".into());
                }
                if b {
                    env.insert("B".into(), "value".into());
                }
                assert_eq!(
                    validate(&definition, &mut env).is_empty(),
                    valid,
                    "{mode} {a} {b}"
                );
            }
        }
    }

    #[test]
    fn invalid_constraint_declarations_and_unused_defaults_fail_eagerly() {
        for input in [
            r#"{"vars":{"N":{"format":"integer","min":2,"max":1}}}"#,
            r#"{"vars":{"N":{"format":"integer","min":2,"default":"1"}}}"#,
            r#"{"vars":{"N":{"min":2}}}"#,
            r#"{"vars":{"N":{"minLength":2,"maxLength":1}}}"#,
            r#"{"vars":{"N":{"protocols":["https"]}}}"#,
            r#"{"vars":{"N":{"requiredWhen":{"variable":"UNKNOWN","present":true}}}}"#,
            r#"{"vars":{"TOKEN":{"secret":true},"N":{"requiredWhen":{"variable":"TOKEN","equals":"private-fixture"}}}}"#,
            r#"{"groups":{"auth":{"mode":"exactlyOne","vars":["A","A"]}},"vars":{"A":{}}}"#,
        ] {
            assert!(!validate_schema(&schema(input)).is_empty(), "{input}");
        }
    }
    #[test]
    fn relational_diagnostics_have_stable_order_and_do_not_duplicate_descriptions() {
        let rule = crate::EnvVarRule {
            description: Some("x".repeat(1024)),
            ..Default::default()
        };
        let mut first = EnvSchema {
            vars: HashMap::from([("A".into(), rule)]),
            ..Default::default()
        };
        for name in ["z", "a"] {
            first.groups.insert(
                name.into(),
                crate::VarGroup {
                    mode: crate::VarGroupMode::ExactlyOne,
                    vars: vec!["A".into()],
                },
            );
        }
        let errors = validate(&first, &mut HashMap::new());
        assert_eq!(errors.len(), 2);
        assert!(errors.iter().all(|error| error.description.is_none()));
        assert!(
            matches!(&errors[0].kind, crate::ValidationErrorKind::GroupViolation { group, .. } if group == "a")
        );
    }

    #[test]
    fn group_member_and_map_limits_reject_invalid_input_before_parsing_excess_values() {
        let members = std::iter::repeat_n("\"A\"", 4096)
            .collect::<Vec<_>>()
            .join(",");
        let input =
            format!(r#"{{"groups":{{"g":{{"mode":"allOrNone","vars":[{members},false]}}}}}}"#);
        let error = serde_json::from_str::<EnvSchema>(&input)
            .unwrap_err()
            .to_string();
        assert!(error.contains("4096"), "{error}");
        let input = r#"{"groups":{"g":{"mode":"allOrNone","vars":["A"]},"g":false}}"#;
        assert!(
            serde_json::from_str::<EnvSchema>(input)
                .unwrap_err()
                .to_string()
                .contains("duplicate variable group")
        );
    }

    #[test]
    fn exact_bounds_and_predicate_shape_reject_fractional_or_ambiguous_inputs() {
        for input in [
            r#"{"vars":{"N":{"min":1.0}}}"#,
            r#"{"vars":{"N":{"min":"9223372036854775808"}}}"#,
            r#"{"vars":{"N":{"requiredWhen":{"variable":"N"}}}}"#,
            r#"{"vars":{"N":{"requiredWhen":{"variable":"N","equals":"x","present":true}}}}"#,
        ] {
            assert!(serde_json::from_str::<EnvSchema>(input).is_err(), "{input}");
        }
        let definition = schema(
            r#"{"vars":{"N":{"format":"integer","min":"-9223372036854775808","max":"-9007199254740993"}}}"#,
        );
        assert!(validate(&definition, &mut values(&[("N", "-9223372036854775808")])).is_empty());
        assert!(!validate(&definition, &mut values(&[("N", "-9007199254740992")])).is_empty());
    }

    #[test]
    fn groups_and_conditions_observe_defaults_and_empty_values() {
        let definition = schema(
            r#"{"groups":{"g":{"mode":"exactlyOne","vars":["A","B"]}},"vars":{"A":{"default":"x"},"B":{"empty":"allow"}}}"#,
        );
        assert!(validate(&definition, &mut values(&[("B", "")])).is_empty());
        assert!(!validate(&definition, &mut values(&[("B", "x")])).is_empty());
    }

    #[test]
    fn malformed_protocol_definitions_and_unsafe_equality_literals_are_rejected() {
        for protocols in [
            r#"[]"#,
            r#"["https","https"]"#,
            r#"["HTTPS"]"#,
            r#"["1http"]"#,
        ] {
            assert!(
                !validate_schema(&schema(&format!(
                    r#"{{"vars":{{"URL":{{"format":"url","protocols":{protocols}}}}}}}"#
                )))
                .is_empty()
            );
        }
        assert!(!validate_schema(&schema(r#"{"vars":{"A":{},"B":{"requiredWhen":{"variable":"A","equals":"\u001bfixture"}}}}"#)).is_empty());
    }

    #[test]
    fn programmatic_declarations_enforce_group_and_protocol_budgets() {
        let mut definition = EnvSchema {
            vars: HashMap::from([("A".into(), crate::EnvVarRule::default())]),
            ..Default::default()
        };
        for index in 0..129 {
            definition.groups.insert(
                format!("G{index}"),
                crate::VarGroup {
                    mode: crate::VarGroupMode::AllOrNone,
                    vars: vec!["A".into()],
                },
            );
        }
        assert!(!validate_schema(&definition).is_empty());
        definition.groups.clear();
        definition.groups.insert(
            "G".into(),
            crate::VarGroup {
                mode: crate::VarGroupMode::AllOrNone,
                vars: vec!["A".into(); 4097],
            },
        );
        assert!(!validate_schema(&definition).is_empty());
        definition.groups.clear();
        let rule = definition.vars.get_mut("A").unwrap();
        rule.format = Some(crate::VarFormat::Url);
        rule.protocols = Some((0..33).map(|index| format!("scheme{index}")).collect());
        assert!(!validate_schema(&definition).is_empty());
    }

    #[test]
    fn length_bounds_serialize_exact_decimal_wire_values() {
        let definition = schema(r#"{"vars":{"TEXT":{"minLength":1,"maxLength":"4294967295"}}}"#);
        assert!(validate_schema(&definition).is_empty());
        let wire = serde_json::to_value(&definition).unwrap();
        assert_eq!(wire["vars"]["TEXT"]["minLength"], "1");
        assert_eq!(wire["vars"]["TEXT"]["maxLength"], "4294967295");
        for bound in [
            "1e0",
            "1.0000000000000001",
            "4294967295.0000001",
            "\"4294967296\"",
            "\"+1\"",
        ] {
            assert!(
                serde_json::from_str::<EnvSchema>(&format!(
                    r#"{{"vars":{{"TEXT":{{"maxLength":{bound}}}}}}}"#
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn zero_and_maximum_length_bounds_accept_their_boundary_values() {
        let definition = schema(r#"{"vars":{"A":{"empty":"allow","maxLength":0}}}"#);
        assert!(validate(&definition, &mut values(&[("A", "")])).is_empty());
        assert!(!validate(&definition, &mut values(&[("A", "a")])).is_empty());
        let definition = schema(r#"{"vars":{"A":{"maxLength":4294967295}}}"#);
        assert!(validate(&definition, &mut values(&[("A", "👩‍🚀")])).is_empty());
    }

    #[test]
    #[ignore = "manual peak-RSS harness"]
    fn overlapping_group_diagnostics_do_not_multiply_large_descriptions() {
        let mut definition = EnvSchema {
            vars: HashMap::from([(
                "A".into(),
                crate::EnvVarRule {
                    description: Some("x".repeat(8 * 1024 * 1024)),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        for index in 0..128 {
            definition.groups.insert(
                format!("GROUP_{index:03}"),
                crate::VarGroup {
                    mode: crate::VarGroupMode::ExactlyOne,
                    vars: vec!["A".into()],
                },
            );
        }
        let errors = validate(&definition, &mut HashMap::new());
        assert_eq!(errors.len(), 128);
        assert!(errors.iter().all(|error| error.description.is_none()));
    }
}
