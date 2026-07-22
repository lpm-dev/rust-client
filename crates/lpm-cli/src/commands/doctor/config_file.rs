use std::path::Path;

use crate::doctor_catalog;

use super::check::Check;

/// Validate lpm.json structure and known fields.
///
/// Checks:
/// - Valid JSON syntax
/// - Known top-level fields (runtime, env, tasks, tools, services, tunnel, publish, https)
/// - runtime.node is a valid version spec
/// - tasks have valid structure (command, dependsOn, cache, outputs, inputs, env)
/// - tools reference known managed tools
/// - services have required command field
/// - Falls back to serde deserialization for type-level validation
pub(super) fn validate_lpm_json(project_dir: &Path) -> Option<Check> {
    let lpm_json_path = project_dir.join("lpm.json");
    let content = match lpm_common::read_text_file_capped(
        &lpm_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(c) => c,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => return None,
        Err(e) => {
            return Some(Check::fail(
                &doctor_catalog::LPM_JSON_UNREADABLE,
                &format!("cannot read: {e}"),
            ));
        }
    };

    // 1. Valid JSON?
    let doc: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return Some(Check::fail(
                &doctor_catalog::LPM_JSON_INVALID_SYNTAX,
                &format!("invalid JSON at line {} — {}", e.line(), e),
            ));
        }
    };

    let obj = match doc.as_object() {
        Some(o) => o,
        None => {
            return Some(Check::fail(
                &doctor_catalog::LPM_JSON_NOT_OBJECT,
                "must be a JSON object, not an array or primitive",
            ));
        }
    };

    let mut warnings: Vec<String> = Vec::new();

    // 2. Check for unknown top-level fields
    let known_fields = [
        "runtime", "env", "tasks", "tools", "services", "tunnel", "publish", "https",
    ];
    for key in obj.keys() {
        if !known_fields.contains(&key.as_str()) {
            warnings.push(format!("unknown field \"{key}\""));
        }
    }

    // 3. Validate runtime section
    if let Some(runtime) = obj.get("runtime") {
        if let Some(runtime_obj) = runtime.as_object() {
            for (rt_name, rt_value) in runtime_obj {
                if rt_name != "node" && rt_name != "bun" {
                    warnings.push(format!(
                        "runtime \"{rt_name}\" not yet supported (supported: \"node\", \"bun\")"
                    ));
                }
                if !rt_value.is_string() {
                    warnings.push(format!("runtime.{rt_name} must be a string version spec"));
                }
            }
        } else {
            warnings.push("\"runtime\" must be an object".into());
        }
    }

    // 4. Validate tasks section
    if let Some(tasks) = obj.get("tasks") {
        if let Some(tasks_obj) = tasks.as_object() {
            let known_task_fields = ["command", "dependsOn", "cache", "outputs", "inputs", "env"];
            for (task_name, task_value) in tasks_obj {
                if let Some(task_obj) = task_value.as_object() {
                    for key in task_obj.keys() {
                        if !known_task_fields.contains(&key.as_str()) {
                            warnings.push(format!("tasks.{task_name}: unknown field \"{key}\""));
                        }
                    }
                    // cache must be bool
                    if let Some(cache) = task_obj.get("cache")
                        && !cache.is_boolean()
                    {
                        warnings.push(format!("tasks.{task_name}.cache must be a boolean"));
                    }
                    // outputs and inputs must be arrays of strings
                    for field in ["outputs", "inputs"] {
                        if let Some(arr) = task_obj.get(field)
                            && !arr.is_array()
                        {
                            warnings.push(format!("tasks.{task_name}.{field} must be an array"));
                        }
                    }
                    // dependsOn must be array of strings
                    if let Some(deps) = task_obj.get("dependsOn")
                        && !deps.is_array()
                    {
                        warnings.push(format!("tasks.{task_name}.dependsOn must be an array"));
                    }
                } else {
                    warnings.push(format!("tasks.{task_name} must be an object"));
                }
            }
        } else {
            warnings.push("\"tasks\" must be an object".into());
        }
    }

    // 5. Validate tools section
    if let Some(tools) = obj.get("tools") {
        if let Some(tools_obj) = tools.as_object() {
            let mut known_tools: Vec<&str> = lpm_plugin::registry::list_plugins()
                .iter()
                .map(|p| p.name)
                .collect();
            known_tools.extend(lpm_plugin::user_facing_engine_tool_names());
            known_tools.sort_unstable();
            for (tool_name, tool_value) in tools_obj {
                if !known_tools.contains(&tool_name.as_str()) {
                    warnings.push(format!(
                        "tools.{tool_name}: unknown managed tool (available: {})",
                        known_tools.join(", ")
                    ));
                }
                if !tool_value.is_string() {
                    warnings.push(format!("tools.{tool_name} must be a version string"));
                }
            }
        } else {
            warnings.push("\"tools\" must be an object".into());
        }
    }

    // 6. Validate services section
    if let Some(services) = obj.get("services") {
        if let Some(services_obj) = services.as_object() {
            for (svc_name, svc_value) in services_obj {
                if let Some(svc_obj) = svc_value.as_object() {
                    if !svc_obj.contains_key("command") {
                        warnings.push(format!(
                            "services.{svc_name}: missing required \"command\" field"
                        ));
                    }
                } else {
                    warnings.push(format!("services.{svc_name} must be an object"));
                }
            }
        } else {
            warnings.push("\"services\" must be an object".into());
        }
    }

    // Also try parsing with the actual struct to catch serde errors
    if let Err(e) = serde_json::from_str::<lpm_runner::lpm_json::LpmJsonConfig>(&content) {
        warnings.push(format!("schema error: {e}"));
    }

    if warnings.is_empty() {
        Some(Check::pass(&doctor_catalog::LPM_JSON_VALID, "valid"))
    } else if warnings.len() == 1 {
        Some(Check::warn(
            &doctor_catalog::LPM_JSON_SCHEMA_WARNINGS,
            &warnings[0],
        ))
    } else {
        Some(Check::warn(
            &doctor_catalog::LPM_JSON_SCHEMA_WARNINGS,
            &format!("{} issues: {}", warnings.len(), warnings.join("; ")),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog::Severity;

    // ── validate_lpm_json tests ────────────────────────────────────────

    #[test]
    fn validate_lpm_json_no_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_lpm_json(dir.path()).is_none());
    }

    #[test]
    fn validate_lpm_json_empty_object_passes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "{}").unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "empty object should pass: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_invalid_json_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "{ not json").unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Fail));
        assert!(result.detail.contains("invalid JSON"));
    }

    #[test]
    fn validate_lpm_json_array_root_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "[1, 2, 3]").unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Fail));
        assert!(result.detail.contains("must be a JSON object"));
    }

    #[test]
    fn validate_lpm_json_unknown_field_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "bogus_field": true }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("unknown field \"bogus_field\""));
    }

    #[test]
    fn validate_lpm_json_publish_field_accepted() {
        // Regression test for publish is a valid LpmJsonConfig field
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "publish": { "registries": ["lpm"] } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "publish should be accepted: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_https_field_accepted() {
        // Regression test for https is a valid LpmJsonConfig field
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "https": true }"#).unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "https should be accepted: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_vault_field_rejected() {
        // vault is NOT in LpmJsonConfig — should be flagged as unknown
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "vault": {} }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(
            matches!(result.severity, Severity::Warn),
            "vault should be unknown: {}",
            result.detail
        );
        assert!(result.detail.contains("unknown field \"vault\""));
    }

    #[test]
    fn validate_lpm_json_all_known_fields_pass() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "runtime": { "node": ">=22" },
                "env": { "dev": ".env.development" },
                "tasks": { "build": { "command": "tsc" } },
                "tools": {},
                "services": { "web": { "command": "next dev" } },
                "tunnel": { "domain": "acme.lpm.fyi" },
                "publish": { "registries": ["lpm", "npm"] },
                "https": true
            }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "all known fields should pass: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_runtime_non_object_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "runtime": "node" }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_runtime_unsupported_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "runtime": { "deno": ">=2.0.0" } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("not yet supported"));
    }

    #[test]
    fn validate_lpm_json_tasks_string_value_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": "tsc" } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_task_unknown_field_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": { "command": "tsc", "bogus": true } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("unknown field \"bogus\""));
    }

    #[test]
    fn validate_lpm_json_task_cache_non_bool_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": { "command": "tsc", "cache": "yes" } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("cache must be a boolean"));
    }

    #[test]
    fn validate_lpm_json_task_outputs_non_array_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": { "command": "tsc", "outputs": "dist" } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("outputs must be an array"));
    }

    #[test]
    fn validate_lpm_json_task_depends_on_non_array_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "test": { "command": "vitest", "dependsOn": "build" } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("dependsOn must be an array"));
    }

    #[test]
    fn validate_lpm_json_tools_non_object_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "tools": "biome" }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_accepts_rolldown_tool_pin() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tools": { "rolldown": "1.0.2" } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(
            matches!(result.severity, Severity::Pass),
            "rolldown should be a known managed tool: {}",
            result.detail
        );
    }

    #[test]
    fn validate_lpm_json_services_missing_command_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "services": { "api": { "port": 3000 } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("missing required \"command\""));
    }

    #[test]
    fn validate_lpm_json_services_non_object_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "services": "web" }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_multiple_issues_counted() {
        let dir = tempfile::tempdir().unwrap();
        // 2 unknown fields + runtime non-object + serde schema error = 4 issues
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "bogus1": 1, "bogus2": 2, "runtime": "bad" }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(
            result.detail.contains("issues"),
            "should report multiple issues: {}",
            result.detail
        );
        // Verify it's more than 1 issue (the exact count depends on serde fallback too)
        assert!(
            result.detail.starts_with("4 issues") || result.detail.starts_with("3 issues"),
            "should have 3-4 issues: {}",
            result.detail
        );
    }
}
