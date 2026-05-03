//! `lpm schema <kind>` — emit a JSON Schema for an LPM config file.
//!
//! Two schemas ship today:
//!
//! - `lpm.json` — auto-derived from the [`lpm_runner::lpm_json::LpmJsonConfig`]
//!   typed struct via `schemars`. Lives in source as derive output;
//!   regenerated every build.
//! - `lpm.config.json` — hand-authored at
//!   [`crate::commands::schema::LPM_CONFIG_SCHEMA`] (`crates/lpm-cli/schemas/lpm.config.schema.json`).
//!   The consumer surface in [`crate::commands::add`] is dynamic
//!   (packages declare their own `configSchema`), so the schema is
//!   maintained alongside the consumer code with a corpus validation
//!   test guarding against drift.
//!
//! Both schemas are served at `https://lpm.dev/schemas/<name>.json`
//! for editor auto-discovery. The drift-guard test in
//! `tests/schema_drift.rs` diffs the emitted bytes against the
//! checked-in copy under `a-package-manager/public/schemas/` so the
//! two repos cannot silently diverge.
//!
//! Output format:
//! - `--out <path>` writes pretty-printed JSON to the file.
//! - Otherwise pretty-prints to stdout.

use lpm_common::LpmError;

/// Hand-authored `lpm.config.json` schema, baked into the binary at
/// compile time. Source of truth; the copy under
/// `a-package-manager/public/schemas/` is regenerated from this via
/// `lpm schema lpm.config.json --out <path>` + the drift-guard test.
pub const LPM_CONFIG_SCHEMA: &str = include_str!("../../schemas/lpm.config.schema.json");

/// Run the `lpm schema <kind>` subcommand.
pub fn run(kind: &str, out: Option<&str>) -> Result<(), LpmError> {
    let schema_text = render(kind)?;
    match out {
        Some(path) => {
            std::fs::write(path, &schema_text)
                .map_err(|e| LpmError::Script(format!("could not write {path}: {e}")))?;
        }
        None => {
            println!("{schema_text}");
        }
    }
    Ok(())
}

/// Render the requested schema as a pretty-printed JSON string.
///
/// Public so the drift-guard test (and any future external consumer)
/// can produce the canonical bytes without going through the CLI.
pub fn render(kind: &str) -> Result<String, LpmError> {
    let value = match kind {
        "lpm.json" => lpm_runner::lpm_json::generate_schema(),
        "lpm.config.json" => {
            serde_json::from_str::<serde_json::Value>(LPM_CONFIG_SCHEMA).map_err(|e| {
                LpmError::Script(format!("baked-in lpm.config.json schema is invalid: {e}"))
            })?
        }
        other => {
            return Err(LpmError::Script(format!(
                "unknown schema '{other}' — expected one of: lpm.json, lpm.config.json"
            )));
        }
    };
    serde_json::to_string_pretty(&value)
        .map_err(|e| LpmError::Script(format!("could not serialize schema: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baked_in_lpm_config_schema_parses_as_json() {
        let parsed: serde_json::Value =
            serde_json::from_str(LPM_CONFIG_SCHEMA).expect("baked-in schema must parse");
        assert_eq!(
            parsed.get("$id").and_then(|v| v.as_str()),
            Some("https://lpm.dev/schemas/lpm.config.json"),
            "$id must be the canonical URL so editors can auto-discover"
        );
    }

    #[test]
    fn render_lpm_json_returns_json_with_id() {
        let text = render("lpm.json").expect("lpm.json schema renders");
        let parsed: serde_json::Value =
            serde_json::from_str(&text).expect("rendered output is JSON");
        assert_eq!(
            parsed.get("$id").and_then(|v| v.as_str()),
            Some("https://lpm.dev/schemas/lpm.json"),
        );
    }

    #[test]
    fn render_lpm_config_json_returns_json_with_id() {
        let text = render("lpm.config.json").expect("lpm.config.json schema renders");
        let parsed: serde_json::Value =
            serde_json::from_str(&text).expect("rendered output is JSON");
        assert_eq!(
            parsed.get("$id").and_then(|v| v.as_str()),
            Some("https://lpm.dev/schemas/lpm.config.json"),
        );
    }

    #[test]
    fn render_unknown_kind_errors_with_friendly_message() {
        let err = render("package.json").expect_err("unknown kind must error");
        match err {
            LpmError::Script(msg) => {
                assert!(msg.contains("unknown schema"), "msg: {msg}");
                assert!(msg.contains("lpm.json"), "must list valid kinds: {msg}");
                assert!(
                    msg.contains("lpm.config.json"),
                    "must list valid kinds: {msg}"
                );
            }
            other => panic!("expected Script error, got {other:?}"),
        }
    }

    #[test]
    fn render_writes_pretty_printed_json() {
        let text = render("lpm.json").unwrap();
        // Pretty-printed JSON should have at least one indented line.
        assert!(text.contains("\n  "), "schema must be pretty-printed");
    }
}
