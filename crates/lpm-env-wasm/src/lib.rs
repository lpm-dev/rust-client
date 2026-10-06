//! Portable environment schema validation for server and browser boundaries.

use wasm_bindgen::prelude::*;

/// Validate declarations with the same bounded engine used by the CLI.
/// Parser diagnostics never include offending literal values.
#[wasm_bindgen]
pub fn schema_errors_json(input: &str) -> String {
    let errors = if input.len() > 2 * 1024 * 1024 {
        vec!["envSchema exceeds the 2 MiB input limit".to_string()]
    } else {
        match serde_json::from_str::<lpm_env::EnvSchema>(input) {
            Ok(schema) => lpm_env::validate_schema(&schema)
                .iter()
                .map(ToString::to_string)
                .collect(),
            Err(_) => vec!["invalid envSchema field names or value types".to_string()],
        }
    };
    serde_json::to_string(&errors)
        .unwrap_or_else(|_| "[\"could not serialize envSchema diagnostics\"]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_secret_literals_are_absent_from_portable_diagnostics() {
        let output =
            schema_errors_json(r#"{"vars":{"TOKEN":{"secret":true,"default":918273645}}}"#);
        assert!(!output.contains("918273645"));
        assert_ne!(output, "[]");
    }

    #[test]
    fn portable_schema_checks_use_rust_regex_syntax_and_default_validation() {
        assert_ne!(
            schema_errors_json(r#"{"vars":{"VALUE":{"pattern":"["}}}"#),
            "[]"
        );
        assert_ne!(
            schema_errors_json(r#"{"vars":{"VALUE":{"pattern":"^live$","default":"dev"}}}"#),
            "[]"
        );
        assert_eq!(
            schema_errors_json(
                r#"{"vars":{"VALUE":{"pattern":"(?i)^\\p{Letter}+$","default":"中文"}}}"#
            ),
            "[]"
        );
    }
}
