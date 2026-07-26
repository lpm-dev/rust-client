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
            Validator::new(&schema)
                .map_err(|error| format!("embedded lpm.config.json schema is invalid: {error}"))
        })
        .as_ref()
        .map_err(|error| LpmError::Registry(error.clone()))
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

#[cfg(test)]
mod tests {
    use super::*;

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
