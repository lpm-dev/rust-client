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
    let mut output = String::new();
    let mut keys: Vec<&String> = schema.vars.keys().collect();
    keys.sort();

    for (i, key) in keys.iter().enumerate() {
        let rule = &schema.vars[*key];

        // Build comment line
        let mut parts = Vec::new();

        if let Some(desc) = &rule.description {
            parts.push(desc.clone());
        }

        if rule.required {
            parts.push("required".to_string());
        }

        if rule.secret {
            parts.push("secret".to_string());
        }

        if let Some(format) = &rule.format {
            parts.push(format!("format: {}", format_name(format)));
        }

        if let Some(enum_values) = &rule.enum_values {
            parts.push(format!("one of: {}", enum_values.join(", ")));
        }

        if let Some(pattern) = &rule.pattern {
            parts.push(format!("pattern: {pattern}"));
        }

        if let Some(default) = &rule.default {
            parts.push(format!("default: {default}"));
        }

        if !parts.is_empty() {
            output.push_str(&format!("# {}\n", parts.join(" · ")));
        }

        // Value line: KEY=default_or_empty
        let value = rule.default.as_deref().unwrap_or("");
        output.push_str(&format!("{key}={value}\n"));

        // Blank line between entries (except after last)
        if i < keys.len() - 1 {
            output.push('\n');
        }
    }

    output
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
            r#"{"vars": {"API_KEY": {"required": true, "secret": true, "pattern": "sk_*"}}}"#,
        );
        let output = generate(&schema);
        assert!(output.contains("secret"));
        assert!(output.contains("pattern: sk_*"));
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
                "STRIPE_SECRET_KEY": {"required": true, "secret": true, "pattern": "sk_(test|live)_*"},
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
}
