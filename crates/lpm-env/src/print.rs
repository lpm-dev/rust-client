//! Format resolved environment variables for export.
//!
//! Supports multiple output formats for piping into other tools and CI systems.

use std::collections::BTreeMap;

/// POSIX env var name validation: first char `[A-Za-z_]`, rest
/// `[A-Za-z0-9_]`, non-empty. The same shape NodeJS / dotenv parsers
/// honour, and the one required for `eval $(lpm env print --format=shell)`
/// to stay safe — a key like `A; touch /tmp/pwn #` would otherwise
/// turn the documented eval flow into command execution.
///
/// Exported so vault / CLI / dotenv-import callers all reject the same
/// shape and surface the same error message to operators.
pub fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Output formats for resolved environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintFormat {
    /// `export KEY="value"` — for `eval $(lpm env print --format=shell)`
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
///
/// Keys that don't satisfy [`is_valid_env_var_name`] are dropped from
/// every format. An emitted `eval`-able shell line for a key like
/// `A; touch /tmp/pwn #` would otherwise execute arbitrary shell on
/// `eval $(lpm env print --format=shell)`; the equivalent dotenv /
/// Docker / GitHub Actions formats have analogous injection shapes.
pub fn format_env(
    vars: &std::collections::HashMap<String, String>,
    format: PrintFormat,
    secrets: &std::collections::HashSet<String>,
) -> String {
    // Sort for deterministic output; invalid keys are filtered here so
    // every downstream `format_*` helper sees a sanitized map.
    let sorted: BTreeMap<&str, &str> = vars
        .iter()
        .filter(|(k, _)| {
            if is_valid_env_var_name(k) {
                true
            } else {
                tracing::warn!(
                    key = %k,
                    "lpm env print: skipping variable with invalid name (must match [A-Za-z_][A-Za-z0-9_]*)"
                );
                false
            }
        })
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

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
            // M39: newline injection — a vault value containing
            // `\n` would, pre-fix, emit multiple physical dotenv
            // lines, letting an attacker who controls one env var
            // value set additional keys. Quote-and-escape `\n` /
            // `\r` so the value stays a single dotenv assignment.
            let needs_quote = v.contains(' ')
                || v.contains('"')
                || v.contains('\'')
                || v.contains('#')
                || v.contains('\n')
                || v.contains('\r');
            if needs_quote {
                let escaped = v
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r");
                format!("{k}=\"{escaped}\"")
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
    // M39: Docker --env-file format does NOT support escaped newlines
    // or multiline values. Refuse to emit values that contain `\n`/`\r`
    // so an attacker who controls a vault value cannot smuggle extra
    // KEY=value assignments into a downstream `docker run --env-file`.
    // Refusing (with an empty assignment) is safer than silent
    // truncation — the consuming pipeline sees the value go missing
    // and fails loudly rather than silently honouring injected vars.
    vars.iter()
        .map(|(k, v)| {
            if v.contains('\n') || v.contains('\r') {
                format!(
                    "# {k}: value contains newline — refused (would inject extra env-file lines)"
                )
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_github_actions(
    vars: &BTreeMap<&str, &str>,
    secrets: &std::collections::HashSet<String>,
) -> String {
    let mut lines = Vec::new();

    // M39: multiline values must use the GHA `<<EOF` env-file form,
    // not `echo "KEY=value"` which would emit multiple physical lines
    // and let an attacker who controls a value set additional env
    // vars. `::add-mask::` similarly does NOT support newlines —
    // refuse to mask multiline secrets (the unmasked value would leak
    // in logs, which is worse than refusing the secret entirely).
    for (k, v) in vars {
        if secrets.contains(*k) {
            if v.contains('\n') || v.contains('\r') {
                lines.push(format!(
                    "# {k}: multiline secret — refused (::add-mask:: does not support newlines)"
                ));
            } else {
                lines.push(format!("::add-mask::{v}"));
            }
        }
    }

    for (k, v) in vars {
        if v.contains('\n') || v.contains('\r') {
            // GHA multiline assignment shape:
            //   {KEY}<<__LPM_EOF__
            //   value-with-newlines
            //   __LPM_EOF__
            // The delimiter must not appear in the value; we use a
            // long random-ish constant rather than user input so a
            // crafted value can't terminate the heredoc early.
            const DELIM: &str = "__LPM_GHA_EOF__";
            if v.contains(DELIM) {
                lines.push(format!(
                    "# {k}: value contains internal delimiter — refused (would close the heredoc early)"
                ));
            } else {
                lines.push(format!(
                    "{{ echo {key_delim}; echo {value}; echo '{DELIM}'; }} >> \"$GITHUB_ENV\"",
                    key_delim = shell_quote(&format!("{k}<<{DELIM}")),
                    value = shell_quote(v),
                ));
            }
        } else {
            lines.push(format!(
                "echo {} >> \"$GITHUB_ENV\"",
                shell_quote(&format!("{k}={v}"))
            ));
        }
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

    /// M44: env var names that don't match POSIX shape are dropped
    /// from every emitted format. A pre-fix shell line for
    /// `A; touch /tmp/pwn #` would `eval` into command execution.
    #[test]
    fn shell_format_drops_keys_with_shell_metacharacters() {
        let vars = make_vars(&[
            ("VALID_KEY", "ok"),
            ("A; touch /tmp/pwn #", "evil"),
            ("X=$(id)", "evil"),
            ("WITH SPACE", "evil"),
        ]);
        let output = format_env(&vars, PrintFormat::Shell, &HashSet::new());
        assert!(
            output.contains("export VALID_KEY="),
            "valid key must survive: {output}"
        );
        for bad in ["A; touch /tmp/pwn #", "X=$(id)", "WITH SPACE"] {
            assert!(
                !output.contains(bad),
                "invalid key {bad:?} leaked into output: {output}"
            );
        }
    }

    #[test]
    fn dotenv_format_drops_keys_with_newlines_or_specials() {
        let vars = make_vars(&[("OK", "v"), ("BAD\nINJECT", "v"), ("1LEADING_DIGIT", "v")]);
        let output = format_env(&vars, PrintFormat::Dotenv, &HashSet::new());
        assert!(output.contains("OK=v"));
        assert!(!output.contains("BAD"));
        assert!(!output.contains("1LEADING_DIGIT"));
    }

    #[test]
    fn json_format_drops_invalid_keys() {
        let vars = make_vars(&[("OK", "v"), ("BAD KEY", "v")]);
        let output = format_env(&vars, PrintFormat::Json, &HashSet::new());
        assert!(output.contains("\"OK\""));
        assert!(!output.contains("BAD KEY"));
    }

    #[test]
    fn is_valid_env_var_name_canonical_shapes() {
        assert!(is_valid_env_var_name("FOO"));
        assert!(is_valid_env_var_name("foo"));
        assert!(is_valid_env_var_name("_hidden"));
        assert!(is_valid_env_var_name("API_KEY_2024"));
        assert!(!is_valid_env_var_name(""));
        assert!(!is_valid_env_var_name("1leading"));
        assert!(!is_valid_env_var_name("with-dash"));
        assert!(!is_valid_env_var_name("with space"));
        assert!(!is_valid_env_var_name("A;evil"));
        assert!(!is_valid_env_var_name("A\nB"));
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
        assert!(output.contains("echo 'SECRET_KEY=sk_test_abc123' >> \"$GITHUB_ENV\""));
        assert!(output.contains("echo 'PUBLIC=hello' >> \"$GITHUB_ENV\""));
        // PUBLIC should NOT be masked
        assert!(!output.contains("::add-mask::hello"));
    }

    #[test]
    fn github_actions_quotes_shell_sensitive_values() {
        let vars = make_vars(&[("EVIL", "$(whoami) > /tmp/pwned")]);
        let output = format_env(&vars, PrintFormat::GithubActions, &HashSet::new());

        assert!(
            output.contains("echo 'EVIL=$(whoami) > /tmp/pwned' >> \"$GITHUB_ENV\""),
            "github-actions output must shell-quote env assignments: {output}"
        );
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

    /// M39: a vault value containing `\n` must not split into
    /// multiple dotenv assignments. Quoting + escape keeps it on
    /// one physical line.
    #[test]
    fn dotenv_escapes_newline_in_value() {
        let vars = make_vars(&[("KEY", "line1\nEVIL=injected")]);
        let output = format_env(&vars, PrintFormat::Dotenv, &HashSet::new());
        assert!(
            output.contains("KEY=\"line1\\nEVIL=injected\""),
            "newline must be escaped, got: {output}",
        );
        // And there must be exactly one assignment line — no
        // physical newline in the body.
        assert_eq!(output.lines().count(), 1);
    }

    /// Docker env-file format does NOT support escaped newlines.
    /// Refuse-with-comment is safer than letting the attacker
    /// inject extra env-file lines.
    #[test]
    fn docker_refuses_newline_value() {
        let vars = make_vars(&[("KEY", "line1\nEVIL=injected")]);
        let output = format_env(&vars, PrintFormat::Docker, &HashSet::new());
        assert!(output.contains("# KEY: value contains newline"));
        assert!(
            !output.contains("EVIL="),
            "must not emit the injected assignment, got: {output}",
        );
    }

    /// GitHub Actions newline values use the heredoc `<<EOF`
    /// envelope shape (not the unsafe `echo "KEY=value"` form),
    /// and `::add-mask::` for multiline secrets is refused entirely
    /// — masking newlines doesn't work and unmasked secrets would
    /// leak in logs.
    #[test]
    fn github_actions_uses_heredoc_for_multiline_value() {
        let vars = make_vars(&[("KEY", "line1\nline2")]);
        let output = format_env(&vars, PrintFormat::GithubActions, &HashSet::new());
        assert!(
            output.contains("KEY<<__LPM_GHA_EOF__") && output.contains("__LPM_GHA_EOF__"),
            "expected heredoc form, got: {output}",
        );
    }

    #[test]
    fn github_actions_refuses_multiline_secret_mask() {
        let vars = make_vars(&[("SECRET", "line1\nline2")]);
        let mut secrets = HashSet::new();
        secrets.insert("SECRET".to_string());
        let output = format_env(&vars, PrintFormat::GithubActions, &secrets);
        assert!(
            output.contains("# SECRET: multiline secret — refused"),
            "expected refusal comment for multiline secret, got: {output}",
        );
    }
}
