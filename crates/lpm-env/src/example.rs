//! Generate `.env.example` from an env schema.
//!
//! Produces a dotenv file with comments showing descriptions, formats, and defaults.

use crate::schema::{EnvSchema, VarFormat};

/// Generate `.env.example` content from an env schema.
///
/// Output format:
/// ```text
/// # PostgreSQL connection string (required)
/// DATABASE_URL=
///
/// # (default: 3000)
/// PORT=3000
///
/// # One of: debug, info, warn, error (default: info)
/// LOG_LEVEL=info
/// ```
pub fn generate(schema: &EnvSchema) -> String {
    let capacity = schema
        .vars
        .iter()
        .map(|(name, rule)| {
            name.len()
                + 96
                + rule.description.as_ref().map_or(0, String::len)
                + rule.pattern.as_ref().map_or(0, String::len)
                + if rule.secret {
                    0
                } else {
                    rule.default.as_ref().map_or(0, |value| value.len() * 2)
                        + rule.enum_values.as_ref().map_or(0, |values| {
                            values.iter().map(|value| value.len() + 2).sum::<usize>()
                        })
                }
        })
        .sum();
    let mut output = String::with_capacity(capacity);
    let mut comment = String::with_capacity(128);
    let mut keys: Vec<&str> = schema.vars.keys().map(String::as_str).collect();
    keys.sort_unstable();

    for (index, key) in keys.iter().enumerate() {
        let rule = &schema.vars[*key];
        comment.clear();
        let mut has_parts = false;
        if let Some(description) = &rule.description {
            comment.push_str(description);
            has_parts = true;
        }
        for flag in [
            rule.required.then_some("required"),
            rule.secret.then_some("secret"),
        ]
        .into_iter()
        .flatten()
        {
            comment_separator(&mut comment, &mut has_parts);
            comment.push_str(flag);
        }
        if let Some(format) = &rule.format {
            comment_separator(&mut comment, &mut has_parts);
            comment.push_str("format: ");
            comment.push_str(format_name(format));
        }
        if !rule.secret
            && let Some(values) = &rule.enum_values
        {
            comment_separator(&mut comment, &mut has_parts);
            comment.push_str("one of: ");
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    comment.push_str(", ");
                }
                comment.push_str(value);
            }
        }
        if let Some(pattern) = &rule.pattern {
            comment_separator(&mut comment, &mut has_parts);
            comment.push_str("pattern: ");
            comment.push_str(pattern);
        }
        if !rule.secret
            && let Some(default) = &rule.default
        {
            comment_separator(&mut comment, &mut has_parts);
            comment.push_str("default: ");
            comment.push_str(default);
        }
        for line in comment.lines().flat_map(|line| line.split('\r')) {
            output.push_str("# ");
            output.push_str(line);
            output.push('\n');
        }
        let value = if rule.secret {
            ""
        } else {
            rule.default.as_deref().unwrap_or("")
        };
        crate::print::append_dotenv_entry(&mut output, key, value);
        output.push('\n');
        if index + 1 < keys.len() {
            output.push('\n');
        }
    }

    output
}

fn comment_separator(comment: &mut String, has_parts: &mut bool) {
    if *has_parts {
        comment.push_str(" · ");
    }
    *has_parts = true;
}

fn format_name(format: &VarFormat) -> &'static str {
    match format {
        VarFormat::Url => "url",
        VarFormat::Port => "port",
        VarFormat::Email => "email",
        VarFormat::Boolean => "boolean",
        VarFormat::Integer => "integer",
        VarFormat::Hostname => "hostname",
        VarFormat::Ip => "ip",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::EnvSchema;

    fn schema_from_json(json: &str) -> EnvSchema {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn empty_schema_produces_empty_output() {
        let schema = EnvSchema::default();
        assert_eq!(generate(&schema), "");
    }

    #[test]
    fn single_required_var() {
        let schema = schema_from_json(
            r#"{"vars": {"DATABASE_URL": {"required": true, "format": "url", "description": "PostgreSQL connection string"}}}"#,
        );
        let output = generate(&schema);
        assert!(output.contains("# PostgreSQL connection string"));
        assert!(output.contains("required"));
        assert!(output.contains("format: url"));
        assert!(output.contains("DATABASE_URL=\n"));
    }

    #[test]
    fn var_with_default() {
        let schema =
            schema_from_json(r#"{"vars": {"PORT": {"default": "3000", "format": "port"}}}"#);
        let output = generate(&schema);
        assert!(output.contains("PORT=3000\n"));
        assert!(output.contains("default: 3000"));
    }

    #[test]
    fn enum_var() {
        let schema = schema_from_json(
            r#"{"vars": {"LOG_LEVEL": {"enum": ["debug", "info", "warn", "error"], "default": "info"}}}"#,
        );
        let output = generate(&schema);
        assert!(output.contains("one of: debug, info, warn, error"));
        assert!(output.contains("LOG_LEVEL=info\n"));
    }

    #[test]
    fn secret_var() {
        let schema = schema_from_json(
            r#"{"vars": {"API_KEY": {"required": true, "secret": true, "pattern": "^sk_.*$"}}}"#,
        );
        let output = generate(&schema);
        assert!(output.contains("secret"));
        assert!(output.contains("pattern: ^sk_.*$"));
        assert!(output.contains("API_KEY=\n"));
    }

    #[test]
    fn sorted_output() {
        let schema = schema_from_json(
            r#"{"vars": {
                "ZEBRA": {"required": true},
                "ALPHA": {"required": true},
                "MIDDLE": {"default": "x"}
            }}"#,
        );
        let output = generate(&schema);
        let alpha_pos = output.find("ALPHA=").unwrap();
        let middle_pos = output.find("MIDDLE=").unwrap();
        let zebra_pos = output.find("ZEBRA=").unwrap();
        assert!(alpha_pos < middle_pos);
        assert!(middle_pos < zebra_pos);
    }

    #[test]
    fn blank_lines_between_entries() {
        let schema =
            schema_from_json(r#"{"vars": {"A": {"required": true}, "B": {"required": true}}}"#);
        let output = generate(&schema);
        assert!(output.contains("A=\n\n# "));
    }

    #[test]
    fn no_trailing_blank_line() {
        let schema = schema_from_json(r#"{"vars": {"ONLY": {"required": true}}}"#);
        let output = generate(&schema);
        assert!(!output.ends_with("\n\n"), "should not end with blank line");
        assert!(output.ends_with('\n'), "should end with single newline");
    }

    #[test]
    fn full_schema_example() {
        let schema = schema_from_json(
            r#"{"vars": {
                "DATABASE_URL": {"required": true, "format": "url", "secret": true, "description": "PostgreSQL connection string"},
                "PORT": {"default": "3000", "format": "port"},
                "STRIPE_SECRET_KEY": {"required": true, "secret": true, "pattern": "^sk_(test|live)_.*$"},
                "LOG_LEVEL": {"enum": ["debug", "info", "warn", "error"], "default": "info"}
            }}"#,
        );
        let output = generate(&schema);

        // Verify all 4 vars are present
        assert!(output.contains("DATABASE_URL="));
        assert!(output.contains("PORT=3000"));
        assert!(output.contains("STRIPE_SECRET_KEY="));
        assert!(output.contains("LOG_LEVEL=info"));
    }
    #[test]
    fn secret_defaults_and_allowlists_never_appear_in_examples() {
        let schema = schema_from_json(
            r#"{"vars":{"TOKEN":{"secret":true,"default":"private-default","enum":["private-allowed"]}}}"#,
        );
        let output = generate(&schema);
        assert!(!output.contains("private-default"));
        assert!(!output.contains("private-allowed"));
        assert!(output.contains("TOKEN=\n"));
    }
    #[test]
    fn examples_preserve_empty_descriptions_and_quote_multiline_defaults() {
        let schema = schema_from_json(
            r#"{"vars":{"A":{"description":"","required":true},"B":{"description":"first\nsecond","default":"line1\nline2"}}}"#,
        );
        assert_eq!(
            generate(&schema),
            "#  · required\nA=\n\n# first\n# second · default: line1\n# line2\nB=\"line1\\nline2\"\n"
        );
    }

    #[test]
    fn carriage_returns_cannot_turn_example_comments_into_assignments() {
        for field in ["description", "default", "pattern"] {
            let schema: EnvSchema = serde_json::from_value(serde_json::json!({
                "vars": {"TOKEN": {field: "safe\rINJECTED=value"}}
            }))
            .unwrap();
            let normalized = generate(&schema).replace('\r', "\n");
            assert!(
                normalized
                    .lines()
                    .all(|line| !line.starts_with("INJECTED=")),
                "uncommented assignment from {field}: {normalized}"
            );
        }
    }
}
