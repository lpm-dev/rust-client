//! **Tier placement: cli-binary** (per AGENTS.md `# Testing Tier
//! Discipline`). Justification class: **parser/schema corpus**. This
//! file iterates JSON fixtures under `tests/fixtures/lpm_config_corpus/`
//! and validates each against the hand-authored schema using the
//! `jsonschema::Validator` directly — no binary spawn, no
//! `TempProject`. Corpus tests belong in cli-binary tier because (a)
//! they need direct access to the schema source under
//! `crates/lpm-cli/`, (b) the fixture-relative paths are anchored on
//! `CARGO_MANIFEST_DIR` of the lpm-cli crate, and (c) the workflow
//! harness's subprocess-with-isolated-HOME pattern adds nothing to a
//! pure-deserialization test.
//!
//! Validates the hand-authored `lpm.config.json` schema against a
//! curated corpus of fixtures.
//!
//! The schema sits next to the consumer code in `commands/add/` and
//! must agree with what the runtime actually accepts. Without a corpus
//! it would silently drift the moment someone added a new field.
//!
//! Fixtures live in `tests/fixtures/lpm_config_corpus/`. Naming
//! convention:
//!
//! - `NN-<descriptor>.json` — must validate.
//! - `NN-invalid-<descriptor>.json` — must NOT validate.
//!
//! The numeric prefix orders fixtures so test failures point at a
//! stable filename. Add new ones whenever the consumer surface in
//! `commands/add/` grows or shifts.
//!
//! When this test fails the cause is one of:
//!  - The schema is wrong → fix `crates/lpm-cli/schemas/lpm.config.schema.json`.
//!  - The fixture is wrong → adjust the fixture to match the new contract.
//!  - The consumer code in `commands/add/` shifted → update both the schema
//!    and the fixture together.

use jsonschema::Validator;
use std::fs;
use std::path::PathBuf;

const SCHEMA_TEXT: &str = include_str!("../schemas/lpm.config.schema.json");

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("lpm_config_corpus")
}

fn load_validator() -> Validator {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA_TEXT)
        .expect("hand-authored lpm.config.schema.json must parse as JSON");
    Validator::new(&schema)
        .expect("hand-authored lpm.config.schema.json must be a valid JSON Schema")
}

fn load_corpus() -> Vec<(String, serde_json::Value, bool)> {
    let dir = corpus_dir();
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("could not read corpus dir {}: {e}", dir.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".json") {
                return None;
            }
            let must_validate = !name.contains("invalid");
            let body = fs::read_to_string(entry.path()).ok()?;
            let parsed: serde_json::Value = serde_json::from_str(&body)
                .unwrap_or_else(|e| panic!("fixture {name} is not valid JSON: {e}"));
            Some((name, parsed, must_validate))
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!files.is_empty(), "corpus dir is empty: {}", dir.display());
    files
}

#[test]
fn schema_itself_is_valid_json_and_a_valid_schema() {
    // Surfaces a malformed schema separately from a fixture failure
    // so the failure message points at the right file.
    let _ = load_validator();
}

#[test]
fn every_positive_fixture_validates() {
    let validator = load_validator();
    let corpus = load_corpus();
    let mut failures = Vec::new();
    for (name, value, must_validate) in &corpus {
        if !*must_validate {
            continue;
        }
        if let Err(errors) = validator.validate(value) {
            failures.push(format!(
                "{name} should validate but failed:\n  - {}",
                format!("{errors}").replace('\n', "\n    ")
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} positive fixture(s) failed:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn every_negative_fixture_is_rejected() {
    let validator = load_validator();
    let corpus = load_corpus();
    let mut surprises = Vec::new();
    for (name, value, must_validate) in &corpus {
        if *must_validate {
            continue;
        }
        if validator.validate(value).is_ok() {
            surprises.push(format!(
                "{name} is named *-invalid-* but validated successfully — \
                 either tighten the schema or rename the fixture"
            ));
        }
    }
    assert!(
        surprises.is_empty(),
        "{} negative fixture(s) unexpectedly validated:\n\n{}",
        surprises.len(),
        surprises.join("\n")
    );
}

#[test]
fn corpus_covers_the_documented_field_surface() {
    // Pin the de-facto Rust-consumer field surface so adding a new
    // top-level key to commands/add/ without a fixture trips this test.
    // Update this list AND add a fixture whenever the consumer
    // surface grows.
    const REQUIRED_KEYS: &[&str] = &[
        "ecosystem",
        "configSchema",
        "defaultConfig",
        "files",
        "dependencies",
        "importAlias",
    ];
    let corpus = load_corpus();
    let positive: Vec<&serde_json::Value> = corpus
        .iter()
        .filter(|(_, _, must_validate)| *must_validate)
        .map(|(_, v, _)| v)
        .collect();

    for key in REQUIRED_KEYS {
        let covered = positive.iter().any(|v| v.get(*key).is_some());
        assert!(
            covered,
            "no positive fixture exercises top-level key '{key}' — add one in \
             tests/fixtures/lpm_config_corpus/ so the schema gets coverage"
        );
    }
}
