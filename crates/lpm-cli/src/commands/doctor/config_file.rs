use std::collections::BinaryHeap;
use std::path::Path;

use crate::doctor_catalog;

use super::check::Check;

const ISSUE_PREVIEW_LIMIT: usize = 5;

#[derive(Default)]
struct IssuePreview {
    total: usize,
    smallest: BinaryHeap<String>,
}

impl IssuePreview {
    fn push(&mut self, issue: String) {
        self.total += 1;
        if self.smallest.len() < ISSUE_PREVIEW_LIMIT {
            self.smallest.push(issue);
        } else if self.smallest.peek().is_some_and(|largest| issue < *largest) {
            self.smallest.pop();
            self.smallest.push(issue);
        }
    }

    fn is_empty(&self) -> bool {
        self.total == 0
    }

    fn len(&self) -> usize {
        self.total
    }

    fn rendered(&self) -> String {
        let mut preview: Vec<_> = self.smallest.iter().map(String::as_str).collect();
        preview.sort_unstable();
        let mut rendered = preview.join("; ");
        if self.total > preview.len() {
            rendered.push_str(&format!("; +{} more", self.total - preview.len()));
        }
        rendered
    }
}

pub(super) struct DiagnosticLpmJson {
    pub(super) check: Option<Check>,
    pub(super) config: Option<lpm_runner::lpm_json::LpmJsonConfig>,
    node_spec: Option<String>,
    bun_spec: Option<String>,
}

impl DiagnosticLpmJson {
    pub(super) fn node_spec(&self) -> Option<&str> {
        self.node_spec.as_deref()
    }

    pub(super) fn bun_spec(&self) -> Option<&str> {
        self.bun_spec.as_deref()
    }
}

/// Validate lpm.json structure and known fields.
///
/// Checks:
/// - Valid JSON syntax
/// - Known top-level fields from the canonical generated schema
/// - runtime.node is a valid version spec
/// - tasks have valid structure (command, dependsOn, cache, outputs, inputs, env)
/// - tools reference known managed tools
/// - services have required command field
/// - Falls back to serde deserialization for type-level validation
pub(super) fn load_lpm_json(project_dir: &Path) -> DiagnosticLpmJson {
    let lpm_json_path = project_dir.join("lpm.json");
    let content = match lpm_common::read_text_file_capped_nofollow(
        &lpm_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(c) => c,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return DiagnosticLpmJson {
                check: None,
                config: None,
                node_spec: None,
                bun_spec: None,
            };
        }
        Err(e) => {
            return DiagnosticLpmJson {
                check: Some(Check::fail(
                    &doctor_catalog::LPM_JSON_UNREADABLE,
                    &format!("cannot read: {e}"),
                )),
                config: None,
                node_spec: None,
                bun_spec: None,
            };
        }
    };

    // 1. Valid JSON?
    let doc: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return DiagnosticLpmJson {
                check: Some(Check::fail(
                    &doctor_catalog::LPM_JSON_INVALID_SYNTAX,
                    &format!("invalid JSON at line {} — {}", e.line(), e),
                )),
                config: None,
                node_spec: None,
                bun_spec: None,
            };
        }
    };

    let obj = match doc.as_object() {
        Some(o) => o,
        None => {
            return DiagnosticLpmJson {
                check: Some(Check::fail(
                    &doctor_catalog::LPM_JSON_NOT_OBJECT,
                    "must be a JSON object, not an array or primitive",
                )),
                config: None,
                node_spec: None,
                bun_spec: None,
            };
        }
    };

    let mut warnings = IssuePreview::default();
    let mut node_spec = None;
    let mut bun_spec = None;

    // 2. Check for unknown fields against the canonical generated contract.
    for path in lpm_runner::lpm_json::unknown_field_paths(&doc) {
        warnings.push(format!("unknown field \"{path}\""));
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
                match rt_value.as_str() {
                    None => {
                        warnings.push(format!("runtime.{rt_name} must be a string version spec"))
                    }
                    Some(spec) if rt_name == "node" => {
                        if let Err(error) = lpm_runtime::node::validate_version_spec(spec) {
                            warnings.push(format!("runtime.node is invalid: {error}"));
                        } else {
                            node_spec = Some(spec.to_owned());
                        }
                    }
                    Some(spec) if rt_name == "bun" => {
                        if let Err(error) = lpm_runtime::bun::validate_version_spec(spec) {
                            warnings.push(format!("runtime.bun is invalid: {error}"));
                        } else {
                            bun_spec = Some(spec.to_owned());
                        }
                    }
                    Some(_) => {}
                }
            }
        } else {
            warnings.push("\"runtime\" must be an object".into());
        }
    }

    // 4. Validate tasks section
    if let Some(tasks) = obj.get("tasks") {
        if let Some(tasks_obj) = tasks.as_object() {
            for (task_name, task_value) in tasks_obj {
                if let Some(task_obj) = task_value.as_object() {
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

    // Use the actual semantic parser so Doctor agrees with command execution.
    let config = match lpm_runner::lpm_json::parse_lpm_json(&content) {
        Ok(config) => Some(config),
        Err(error) => {
            warnings.push(format!("schema error: {error}"));
            None
        }
    };

    let check = if warnings.is_empty() {
        Check::pass(&doctor_catalog::LPM_JSON_VALID, "valid")
    } else if warnings.len() == 1 {
        Check::warn(
            &doctor_catalog::LPM_JSON_SCHEMA_WARNINGS,
            &warnings.rendered(),
        )
    } else {
        Check::warn(
            &doctor_catalog::LPM_JSON_SCHEMA_WARNINGS,
            &format!("{} issues: {}", warnings.len(), warnings.rendered()),
        )
    };
    DiagnosticLpmJson {
        check: Some(check),
        config,
        node_spec,
        bun_spec,
    }
}

#[cfg(test)]
fn validate_lpm_json(project_dir: &Path) -> Option<Check> {
    load_lpm_json(project_dir).check
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
    fn validate_lpm_json_accepts_documented_schema_and_env_metadata_fields() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "$schema": "https://cli.lpm.dev/schemas/lpm.json",
                "vault": "vault-123",
                "vaultSync": {
                    "personalVersion": 7,
                    "personalSyncedAt": "2026-08-13T09:00:00Z",
                    "orgVersions": {"acme": 4},
                    "orgSyncedAt": {"acme": "2026-08-13T09:01:00Z"}
                }
            }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(
            matches!(result.severity, Severity::Pass),
            "documented fields should be accepted: {}",
            result.detail
        );
    }

    #[test]
    fn validate_lpm_json_warns_for_unknown_nested_fields_with_full_paths() {
        let cases = [
            (
                r#"{"remoteCache":{"readonly":true}}"#,
                "remoteCache.readonly",
            ),
            (
                r#"{"services":{"web":{"command":"vite","restar":true}}}"#,
                "services.web.restar",
            ),
            (r#"{"proxy":{"httpRediect":true}}"#, "proxy.httpRediect"),
            (
                r#"{"publish":{"npm":{"otpRequred":true}}}"#,
                "publish.npm.otpRequred",
            ),
            (
                r#"{"envSchema":{"vars":{"TOKEN":{"secert":true}}}}"#,
                "envSchema.vars.TOKEN.secert",
            ),
            (
                r#"{"environments":{"prod":{"extnds":"base"}}}"#,
                "environments.prod.extnds",
            ),
            (r#"{"cert":{"allowPublicDNS":true}}"#, "cert.allowPublicDNS"),
        ];

        for (input, path) in cases {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("lpm.json"), input).unwrap();
            let result = validate_lpm_json(dir.path()).unwrap();
            assert!(
                matches!(result.severity, Severity::Warn),
                "{path}: {}",
                result.detail
            );
            assert!(result.detail.contains(path), "{path}: {}", result.detail);
        }
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
    fn validate_lpm_json_rejects_invalid_node_and_bun_selectors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime":{"node":"$(whoami)","bun":"../../outside"}}"#,
        )
        .unwrap();

        let check = validate_lpm_json(dir.path()).expect("lpm.json check");
        assert!(matches!(check.severity, Severity::Warn));
        assert!(
            check.detail.contains("runtime.node is invalid"),
            "{}",
            check.detail
        );
        assert!(
            check.detail.contains("runtime.bun is invalid"),
            "{}",
            check.detail
        );

        let diagnostic = load_lpm_json(dir.path());
        assert!(
            diagnostic.node_spec().is_none(),
            "an invalid Node selector must not become a runtime remediation target"
        );
        assert!(
            diagnostic.bun_spec().is_none(),
            "an invalid Bun selector must not become a runtime remediation target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linked_lpm_json_is_reported_as_unreadable_without_following_the_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("outside.json");
        std::fs::write(&target, "{}").unwrap();
        symlink(&target, dir.path().join("lpm.json")).unwrap();

        let diagnostic = load_lpm_json(dir.path());
        let check = diagnostic.check.expect("linked lpm.json diagnostic");
        assert_eq!(check.code(), "lpm_json_unreadable");
        assert!(matches!(check.severity, Severity::Fail));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_lpm_json_is_rejected_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.json");
        let encoded = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `encoded` is a NUL-terminated path owned by this test.
        assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();

        let diagnostic = load_lpm_json(dir.path());

        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert_eq!(diagnostic.check.unwrap().code(), "lpm_json_unreadable");
    }

    #[test]
    fn validate_lpm_json_accepts_compound_node_selectors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"runtime":{"node":">=20.0.0 <23.0.0"}}"#,
        )
        .unwrap();

        let check = validate_lpm_json(dir.path()).expect("lpm.json check");
        assert!(matches!(check.severity, Severity::Pass), "{}", check.detail);
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
        assert!(
            result
                .detail
                .contains("unknown field \"tasks.build.bogus\"")
        );
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

    #[test]
    fn lpm_json_issue_output_retains_only_a_bounded_preview() {
        let dir = tempfile::tempdir().unwrap();
        let fields: serde_json::Map<String, serde_json::Value> = (0..100)
            .map(|index| (format!("unknown_{index:03}"), serde_json::Value::Null))
            .collect();
        std::fs::write(
            dir.path().join("lpm.json"),
            serde_json::Value::Object(fields).to_string(),
        )
        .unwrap();

        let check = validate_lpm_json(dir.path()).unwrap();

        assert!(check.detail.starts_with("100 issues:"), "{}", check.detail);
        assert!(check.detail.contains("+95 more"), "{}", check.detail);
        assert!(check.detail.len() < 512, "{}", check.detail.len());
    }
}
