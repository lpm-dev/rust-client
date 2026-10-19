//! The CLI's publish-time skill rules for the registry, which checks the
//! skills in an uploaded tarball with them.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Input {
    prefix: String,
    entries: Vec<InputEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InputEntry {
    path: String,
    size: u64,
    #[serde(default)]
    content_base64: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    skills: Vec<OutputSkill>,
    errors: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputSkill {
    path: String,
    name: String,
    description: String,
    version: Option<String>,
    globs: Vec<String>,
    content: String,
    raw_content: String,
    size_bytes: usize,
}

/// Checks the entries a host found under a tarball's skills directory, as
/// `{"prefix": "lpm-skills/", "entries": [{"path", "size", "contentBase64"}]}`,
/// with the CLI's rules. Returns `{"skills": [...], "errors": [...]}`;
/// skills are listed only when there are no errors.
#[wasm_bindgen]
pub fn validate_skills_json(input: &str) -> String {
    serde_json::to_string(&validate(input)).unwrap_or_else(|_| {
        "{\"skills\":[],\"errors\":[\"could not serialize skill diagnostics\"]}".to_string()
    })
}

/// How a host treats an entry under the skills directory: `0` skips it,
/// `1` lists it for [`validate_skills_json`] without its bytes, and `2`
/// lists it with them. `size` is in bytes.
#[wasm_bindgen]
pub fn skill_entry_role(path: &str, size: f64) -> u8 {
    let size = if size.is_finite() && size >= 0.0 {
        size as u64
    } else {
        u64::MAX
    };
    if lpm_skill::reads_content(path, size) {
        2
    } else if lpm_skill::is_skill_file(path) || lpm_skill::is_nested_markdown(path) {
        1
    } else {
        0
    }
}

/// The publish limits, as `{"maxSkillSize", "maxTotalSize", "maxSkillCount",
/// "minBodyLength"}`. A host reads the bytes of at most `maxSkillCount + 1`
/// skill files.
#[wasm_bindgen]
pub fn skill_limits_json() -> String {
    serde_json::json!({
        "maxSkillSize": lpm_skill::MAX_SKILL_SIZE,
        "maxTotalSize": lpm_skill::MAX_TOTAL_SIZE,
        "maxSkillCount": lpm_skill::MAX_SKILL_COUNT,
        "minBodyLength": lpm_skill::MIN_BODY_LENGTH,
    })
    .to_string()
}

fn validate(input: &str) -> Output {
    let failed = |error: &str| Output {
        skills: Vec::new(),
        errors: vec![error.to_string()],
    };
    if input.len() > MAX_INPUT_BYTES {
        return failed("skill validation input exceeds the 4 MiB limit");
    }
    let Ok(input) = serde_json::from_str::<Input>(input) else {
        return failed("skill validation input is not valid");
    };
    let mut entries = Vec::with_capacity(input.entries.len());
    for entry in input.entries {
        let content = match entry.content_base64 {
            Some(encoded) => {
                let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
                    return failed("skill validation input is not valid");
                };
                Some(bytes)
            }
            None => None,
        };
        entries.push(lpm_skill::SkillEntry {
            path: entry.path,
            size: entry.size,
            content,
        });
    }
    let report = lpm_skill::validate(&input.prefix, &entries);
    let errors = report.messages();
    Output {
        skills: report
            .skills
            .into_iter()
            .map(|skill| OutputSkill {
                size_bytes: skill.raw.len(),
                path: skill.path,
                name: skill.name,
                description: skill.description,
                version: skill.version,
                globs: skill.globs,
                content: skill.body,
                raw_content: skill.raw,
            })
            .collect(),
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skill() -> String {
        format!(
            "---\nname: usage\ndescription: How to use the package well\n---\n\n{}\n",
            "Call the client once and reuse it for every request you make. ".repeat(3)
        )
    }

    fn input(content: &str) -> String {
        serde_json::json!({
            "prefix": "lpm-skills/",
            "entries": [{
                "path": "usage.md",
                "size": content.len(),
                "contentBase64": base64::engine::general_purpose::STANDARD.encode(content),
            }],
        })
        .to_string()
    }

    #[test]
    fn returns_the_validated_skill_as_the_registry_stores_it() {
        let output: serde_json::Value =
            serde_json::from_str(&validate_skills_json(&input(&skill()))).unwrap();

        assert_eq!(output["errors"], serde_json::json!([]));
        assert_eq!(output["skills"][0]["name"], "usage");
        assert_eq!(output["skills"][0]["rawContent"], skill());
        assert_eq!(output["skills"][0]["sizeBytes"], skill().len());
        assert!(
            output["skills"][0]["content"]
                .as_str()
                .unwrap()
                .starts_with("Call the client")
        );
    }

    #[test]
    fn returns_the_cli_s_messages_for_a_rejected_skill() {
        let content = skill().replace("Call the client once", "eval(payload) then call once");

        let output: serde_json::Value =
            serde_json::from_str(&validate_skills_json(&input(&content))).unwrap();

        assert_eq!(output["skills"], serde_json::json!([]));
        assert_eq!(
            output["errors"],
            serde_json::json!([
                "lpm-skills/usage.md:6: blocked shell-injection pattern `dynamic-code-execution`"
            ])
        );
    }

    #[test]
    fn says_which_entries_a_host_reads() {
        assert_eq!(skill_entry_role("usage.md", 10.0), 2);
        assert_eq!(skill_entry_role("usage.md", 15.0 * 1024.0 + 1.0), 1);
        assert_eq!(skill_entry_role("guides/usage.md", 10.0), 1);
        assert_eq!(skill_entry_role("notes.txt", 10.0), 0);
        assert_eq!(skill_entry_role("usage.md", f64::NAN), 1);
    }

    #[test]
    fn reports_the_publish_limits() {
        let limits: serde_json::Value = serde_json::from_str(&skill_limits_json()).unwrap();

        assert_eq!(limits["maxSkillCount"], 10);
        assert_eq!(limits["maxSkillSize"], 15 * 1024);
    }

    #[test]
    fn refuses_malformed_or_oversized_input() {
        assert!(validate_skills_json("{").contains("not valid"));
        assert!(validate_skills_json(&" ".repeat(MAX_INPUT_BYTES + 1)).contains("4 MiB"));
    }
}
