use jsonschema::Validator;
use lpm_common::LpmError;
use std::path::Path;
use std::sync::OnceLock;

const SCHEMA_TEXT: &str = include_str!("../schemas/lpm.config.schema.json");

fn validator() -> Result<&'static Validator, LpmError> {
    static VALIDATOR: OnceLock<Result<Validator, String>> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema = serde_json::from_str::<serde_json::Value>(SCHEMA_TEXT)
                .map_err(|error| format!("embedded lpm.config.json schema is invalid: {error}"))?;
            compile(&schema)
                .map_err(|error| format!("embedded lpm.config.json schema is invalid: {error}"))
        })
        .as_ref()
        .map_err(|error| LpmError::Registry(error.clone()))
}

/// A validator for `schema` that runs its patterns on the `regex` crate, which
/// matches in linear time: lpm.config.json comes with the packages and repos
/// people install, and jsonschema's default engine backtracks.
fn compile(schema: &serde_json::Value) -> Result<Validator, jsonschema::ValidationError<'static>> {
    jsonschema::options()
        .with_pattern_options(jsonschema::PatternOptions::regex())
        .build(schema)
}

pub(crate) fn parse_and_validate(
    path: &Path,
    content: &str,
) -> Result<serde_json::Value, LpmError> {
    let value = serde_json::from_str::<serde_json::Value>(content).map_err(|error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    })?;
    if let Err(errors) = validator()?.validate(&value) {
        return Err(LpmError::Registry(format!(
            "{} is not a valid lpm.config.json: {errors}",
            path.display()
        )));
    }
    Ok(value)
}

/// The prefix an `importAlias` value claims. Trailing slashes count as one.
/// A value that ends in a character a package name can continue with (an
/// ASCII letter or digit, `@`, `.`, `_` or `-`) gets a trailing `/`, so `@`
/// claims `@/lib/cn` but never the scoped package `@radix-ui/react-slot`. Any
/// other value, such as `#`, `~` or `/`, stays as written, since no package
/// name starts with it and `#lib/cn` is a valid subpath import. An empty value
/// is no alias, as it would claim every specifier.
pub(crate) fn import_alias_prefix(alias: &str) -> Option<String> {
    if alias.is_empty() {
        return None;
    }
    let stem = alias.trim_end_matches('/');
    let Some(last) = stem.chars().next_back() else {
        return Some("/".to_owned());
    };
    let had_slash = stem.len() < alias.len();
    if had_slash || last.is_ascii_alphanumeric() || matches!(last, '@' | '.' | '_' | '-') {
        Some(format!("{stem}/"))
    } else {
        Some(stem.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_alias_prefix_ends_at_a_package_name_boundary_and_drops_empty_values() {
        assert_eq!(import_alias_prefix("@").as_deref(), Some("@/"));
        assert_eq!(
            import_alias_prefix("@/components").as_deref(),
            Some("@/components/")
        );
        assert_eq!(import_alias_prefix("lib.v2").as_deref(), Some("lib.v2/"));
        assert_eq!(import_alias_prefix("ui-").as_deref(), Some("ui-/"));
        assert_eq!(import_alias_prefix("ui_").as_deref(), Some("ui_/"));
        assert_eq!(import_alias_prefix("@/").as_deref(), Some("@/"));
        assert_eq!(import_alias_prefix("@//").as_deref(), Some("@/"));
        assert_eq!(import_alias_prefix("lib//").as_deref(), Some("lib/"));
        assert_eq!(import_alias_prefix("#").as_deref(), Some("#"));
        assert_eq!(import_alias_prefix("#/").as_deref(), Some("#/"));
        assert_eq!(import_alias_prefix("~").as_deref(), Some("~"));
        assert_eq!(import_alias_prefix("/").as_deref(), Some("/"));
        assert_eq!(import_alias_prefix("//").as_deref(), Some("/"));
        assert_eq!(import_alias_prefix(""), None);
    }

    #[test]
    fn schema_patterns_run_on_the_linear_time_regex_engine() {
        // Lookaround needs a backtracking engine, so only the regex crate refuses it.
        let lookahead = serde_json::json!({"type": "string", "pattern": "^(?=a)a+$"});
        assert!(compile(&lookahead).is_err());
        let properties = serde_json::json!({"patternProperties": {"(?<=x)y": {}}});
        assert!(compile(&properties).is_err());
        let plain = serde_json::json!({"type": "string", "pattern": "^(a+)+$"});
        let nested_quantifiers = compile(&plain).expect("plain patterns compile");
        let long = format!("{}b", "a".repeat(100_000));
        assert!(!nested_quantifiers.is_valid(&serde_json::json!(long)));
        validator().expect("the embedded schema compiles");
    }

    #[test]
    fn select_fields_require_nonempty_options() {
        for field in [r#"{"type":"select"}"#, r#"{"type":"select","options":[]}"#] {
            assert!(
                parse_and_validate(
                    Path::new("lpm.config.json"),
                    &format!(r#"{{"configSchema":{{"theme":{field}}}}}"#)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn package_and_source_types_are_valid_and_type_may_be_omitted() {
        let path = Path::new("lpm.config.json");
        for document in [r#"{}"#, r#"{"type":"package"}"#, r#"{"type":"source"}"#] {
            parse_and_validate(path, document).unwrap();
        }
    }

    #[test]
    fn unsupported_package_types_are_rejected() {
        let path = Path::new("lpm.config.json");
        for package_type in [
            "mcp-server",
            "vscode-extension",
            "cursor-rules",
            "github-action",
            "xcframework",
            "arbitrary",
        ] {
            let error = parse_and_validate(path, &format!(r#"{{"type":"{package_type}"}}"#))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(package_type)
                    && error.contains("\"package\"")
                    && error.contains("\"source\""),
                "{error}"
            );
        }
    }

    #[test]
    fn unknown_fields_remain_rejected() {
        let error = parse_and_validate(
            Path::new("lpm.config.json"),
            r#"{"type":"package","futureField":true}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("futureField"), "{error}");
    }
}
