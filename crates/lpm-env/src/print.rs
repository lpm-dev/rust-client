//! Format resolved environment variables for export.
//!
//! Supports multiple output formats for piping into other tools and CI systems.

use std::collections::BTreeMap;

/// Output formats for resolved environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintFormat {
    /// `export KEY="value"` — for `eval $(lpm use vars print --format=shell)`
    Shell,
    /// `KEY=value` — standard dotenv format
    Dotenv,
    /// `{"KEY": "value"}` — JSON object
    Json,
    /// `KEY=value` — Docker `--env-file` format (no quotes, no export)
    Docker,
    /// `::add-mask::value\necho "KEY=value" >> $GITHUB_ENV` — GitHub Actions
    GithubActions,
}

impl PrintFormat {
    /// Parse a format string from CLI input.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "shell" | "sh" => Some(Self::Shell),
            "dotenv" | "env" => Some(Self::Dotenv),
            "json" => Some(Self::Json),
            "docker" => Some(Self::Docker),
            "github-actions" | "github" | "gh" | "gha" => Some(Self::GithubActions),
            _ => None,
        }
    }

    /// List all supported format names (for help text).
    pub fn all_names() -> &'static str {
        "shell, dotenv, json, docker, github-actions"
    }
}

/// Format environment variables in the specified format.
///
/// Variables are sorted alphabetically for deterministic output.
/// Secret keys (from the `secrets` set) are masked in GitHub Actions format.
pub fn format_env(
    vars: &std::collections::HashMap<String, String>,
    format: PrintFormat,
    secrets: &std::collections::HashSet<String>,
) -> String {
    // Sort for deterministic output
    let sorted: BTreeMap<&str, &str> = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    match format {
        PrintFormat::Shell => format_shell(&sorted),
        PrintFormat::Dotenv => format_dotenv(&sorted),
        PrintFormat::Json => format_json(&sorted),
        PrintFormat::Docker => format_docker(&sorted),
        PrintFormat::GithubActions => format_github_actions(&sorted, secrets),
    }
}

fn format_shell(vars: &BTreeMap<&str, &str>) -> String {
    vars.iter()
        .map(|(k, v)| format!("export {k}={}", shell_quote(v)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_dotenv(vars: &BTreeMap<&str, &str>) -> String {
    vars.iter()
        .map(|(k, v)| {
            if v.contains(' ') || v.contains('"') || v.contains('\'') || v.contains('#') {
                format!("{k}=\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_json(vars: &BTreeMap<&str, &str>) -> String {
    let map: serde_json::Map<String, serde_json::Value> = vars
        .iter()
        .map(|(k, v)| {
            (
                (*k).to_string(),
                serde_json::Value::String((*v).to_string()),
            )
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap_or_default()
}

fn format_docker(vars: &BTreeMap<&str, &str>) -> String {
    vars.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_github_actions(
    vars: &BTreeMap<&str, &str>,
    secrets: &std::collections::HashSet<String>,
) -> String {
    let mut lines = Vec::new();

    // First: mask all secrets
    for (k, v) in vars {
        if secrets.contains(*k) {
            lines.push(format!("::add-mask::{v}"));
        }
    }

    // Then: set all env vars
    for (k, v) in vars {
        lines.push(format!("echo \"{k}={v}\" >> \"$GITHUB_ENV\""));
    }

    lines.join("\n")
}

/// Shell-quote a value: wrap in single quotes, escape existing single quotes.
fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    // If the value contains no special characters, return as-is
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '@'))
    {
        return value.to_string();
    }
    // Wrap in single quotes, escape any existing single quotes
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn make_vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn parse_format_names() {
        assert_eq!(PrintFormat::parse("shell"), Some(PrintFormat::Shell));
        assert_eq!(PrintFormat::parse("sh"), Some(PrintFormat::Shell));
        assert_eq!(PrintFormat::parse("dotenv"), Some(PrintFormat::Dotenv));
        assert_eq!(PrintFormat::parse("env"), Some(PrintFormat::Dotenv));
        assert_eq!(PrintFormat::parse("json"), Some(PrintFormat::Json));
        assert_eq!(PrintFormat::parse("JSON"), Some(PrintFormat::Json));
        assert_eq!(PrintFormat::parse("docker"), Some(PrintFormat::Docker));
        assert_eq!(
            PrintFormat::parse("github-actions"),
            Some(PrintFormat::GithubActions)
        );
        assert_eq!(PrintFormat::parse("gha"), Some(PrintFormat::GithubActions));
        assert_eq!(PrintFormat::parse("gh"), Some(PrintFormat::GithubActions));
        assert_eq!(PrintFormat::parse("unknown"), None);
    }

    #[test]
    fn shell_format() {
        let vars = make_vars(&[("DB", "postgres://localhost"), ("PORT", "3000")]);
        let output = format_env(&vars, PrintFormat::Shell, &HashSet::new());
        assert!(output.contains("export DB="));
        assert!(output.contains("export PORT=3000"));
    }

    #[test]
    fn shell_quotes_values_with_spaces() {
        let vars = make_vars(&[("MSG", "hello world")]);
        let output = format_env(&vars, PrintFormat::Shell, &HashSet::new());
        assert!(output.contains("export MSG='hello world'"));
    }

    #[test]
    fn shell_quotes_empty_value() {
        let vars = make_vars(&[("EMPTY", "")]);
        let output = format_env(&vars, PrintFormat::Shell, &HashSet::new());
        assert!(output.contains("export EMPTY=''"));
    }

    #[test]
    fn dotenv_format() {
        let vars = make_vars(&[("KEY", "value"), ("SPACED", "hello world")]);
        let output = format_env(&vars, PrintFormat::Dotenv, &HashSet::new());
        assert!(output.contains("KEY=value"));
        assert!(output.contains("SPACED=\"hello world\""));
    }

    #[test]
    fn dotenv_escapes_quotes() {
        let vars = make_vars(&[("VAL", "say \"hello\"")]);
        let output = format_env(&vars, PrintFormat::Dotenv, &HashSet::new());
        assert!(output.contains(r#"VAL="say \"hello\"""#));
    }

    #[test]
    fn json_format() {
        let vars = make_vars(&[("A", "1"), ("B", "2")]);
        let output = format_env(&vars, PrintFormat::Json, &HashSet::new());
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["A"], "1");
        assert_eq!(parsed["B"], "2");
    }

    #[test]
    fn docker_format() {
        let vars = make_vars(&[("PORT", "3000"), ("HOST", "0.0.0.0")]);
        let output = format_env(&vars, PrintFormat::Docker, &HashSet::new());
        assert!(output.contains("PORT=3000"));
        assert!(output.contains("HOST=0.0.0.0"));
        assert!(!output.contains("export"));
        assert!(!output.contains('"'));
    }

    #[test]
    fn github_actions_masks_secrets() {
        let vars = make_vars(&[("PUBLIC", "hello"), ("SECRET_KEY", "sk_test_abc123")]);
        let secrets: HashSet<String> = ["SECRET_KEY".to_string()].into();
        let output = format_env(&vars, PrintFormat::GithubActions, &secrets);
        assert!(output.contains("::add-mask::sk_test_abc123"));
        assert!(output.contains("echo \"SECRET_KEY=sk_test_abc123\" >> \"$GITHUB_ENV\""));
        assert!(output.contains("echo \"PUBLIC=hello\" >> \"$GITHUB_ENV\""));
        // PUBLIC should NOT be masked
        assert!(!output.contains("::add-mask::hello"));
    }

    #[test]
    fn sorted_output() {
        let vars = make_vars(&[("ZEBRA", "z"), ("ALPHA", "a"), ("MIDDLE", "m")]);
        let output = format_env(&vars, PrintFormat::Shell, &HashSet::new());
        let alpha_pos = output.find("ALPHA").unwrap();
        let middle_pos = output.find("MIDDLE").unwrap();
        let zebra_pos = output.find("ZEBRA").unwrap();
        assert!(alpha_pos < middle_pos);
        assert!(middle_pos < zebra_pos);
    }

    #[test]
    fn shell_quote_special_chars() {
        assert_eq!(shell_quote("simple"), "simple");
        assert_eq!(shell_quote("has space"), "'has space'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a/b:c@d"), "a/b:c@d");
    }
}
