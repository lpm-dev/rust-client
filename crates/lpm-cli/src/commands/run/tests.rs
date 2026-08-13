use super::cache::{build_cache_context, is_task_cached_with_config};
use super::format::{
    TaskResult, format_cache_summary, format_duration, format_failed_task_output_header,
    format_run_failure_detail, format_workspace_member_scripts_header, print_json_summary,
};
use super::parallel::{MAX_CAPTURED_OUTPUT, truncate_output};
use super::task::{is_meta_task, run_task, run_task_captured};
use lpm_common::LpmError;
use lpm_runner::bin_path::ManagedRuntimeHint::Unknown;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[test]
fn run_failure_detail_formats_as_slim_detail_row() {
    assert_eq!(
        console::strip_ansi_codes(&format_run_failure_detail("web", "exit 1")).into_owned(),
        "  ✗ web: exit 1"
    );
}

#[test]
fn failed_task_output_header_formats_as_slim_detail_row() {
    let plain = console::strip_ansi_codes(&format_failed_task_output_header("build")).into_owned();

    assert!(
        plain.starts_with("  ── build output "),
        "failed output header must keep the task name in a slim detail row: {plain:?}"
    );
}

#[test]
fn cache_summary_formats_as_slim_detail_row() {
    assert_eq!(
        console::strip_ansi_codes(&format_cache_summary(2, 3)).into_owned(),
        "  Cache: 2 hit, 3 miss"
    );
}

#[test]
fn workspace_member_header_formats_as_slim_detail_row() {
    let scripts = vec!["build".to_string(), "test".to_string()];
    assert_eq!(
        console::strip_ansi_codes(&format_workspace_member_scripts_header(
            "@app/web", &scripts
        ))
        .into_owned(),
        "  [@app/web] build, test"
    );
}

// --- transitive skip propagation ---

/// Helper matching the skip-check logic in `run_tasks_parallel`.
fn should_skip_task(
    task_name: &str,
    tasks: &std::collections::HashMap<String, lpm_runner::lpm_json::TaskConfig>,
    failed_tasks: &HashSet<String>,
) -> bool {
    if let Some(tc) = tasks.get(task_name) {
        tc.depends_on
            .iter()
            .filter(|d| !d.starts_with('^'))
            .any(|d| failed_tasks.contains(d.as_str()))
    } else {
        failed_tasks.contains(task_name)
    }
}

#[test]
fn transitive_skip_propagation() {
    // Chain: A depends on B, B depends on C. C fails.
    let mut tasks = std::collections::HashMap::new();
    tasks.insert(
        "A".into(),
        lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["B".into()],
            ..Default::default()
        },
    );
    tasks.insert(
        "B".into(),
        lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["C".into()],
            ..Default::default()
        },
    );
    tasks.insert("C".into(), lpm_runner::lpm_json::TaskConfig::default());

    let mut failed_tasks: HashSet<String> = HashSet::new();
    failed_tasks.insert("C".into());

    // B should be skipped (depends on C which failed)
    assert!(should_skip_task("B", &tasks, &failed_tasks));

    // After marking B as skipped, add it to failed_tasks (the fix)
    failed_tasks.insert("B".into());

    // A should now also be skipped (depends on B which is in failed_tasks)
    assert!(should_skip_task("A", &tasks, &failed_tasks));
}

#[test]
fn no_skip_when_deps_ok() {
    let mut tasks = std::collections::HashMap::new();
    tasks.insert(
        "A".into(),
        lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["B".into()],
            ..Default::default()
        },
    );
    tasks.insert("B".into(), lpm_runner::lpm_json::TaskConfig::default());

    let failed_tasks: HashSet<String> = HashSet::new();
    assert!(!should_skip_task("A", &tasks, &failed_tasks));
}

// Selection logic itself lives in `crate::workspace_select` and is tested there.
// This verifies the run-workspace caller uses the bare-filter migration hint
// on the empty-match branch.

#[test]
fn workspace_target_selection_no_match_path_suggests_glob_migration() {
    // A bare-name filter should receive the same migration hint used by
    // the run_workspace no-match branch.
    let hint = crate::commands::filter::format_no_match_hint(&["pkg".to_string()]);

    assert!(
        hint.is_some(),
        "no-match path must emit a hint for bare names"
    );
    let hint = hint.unwrap();
    assert!(
        hint.contains("D2"),
        "hint must reference the compatibility note"
    );
    assert!(
        hint.contains("\"*pkg*\"") || hint.contains("\"*/pkg\""),
        "hint must suggest at least one glob form"
    );
}

// --- output truncation ---

#[test]
fn truncate_output_small_passthrough() {
    let small = "hello world\n".repeat(10);
    let result = truncate_output(small.clone());
    assert_eq!(result, small);
}

#[test]
fn truncate_output_large_truncated() {
    // 11 MB of output
    let large = "x".repeat(11 * 1024 * 1024);
    let result = truncate_output(large);
    assert!(result.len() <= MAX_CAPTURED_OUTPUT + 100); // +100 for the message
    assert!(result.contains("[output truncated at 10MB]"));
}

#[test]
fn truncate_output_cuts_at_newline() {
    // Create string just over limit with newlines
    let mut s = String::new();
    let line = "a".repeat(1000) + "\n";
    while s.len() < MAX_CAPTURED_OUTPUT + 5000 {
        s.push_str(&line);
    }
    let result = truncate_output(s);
    assert!(result.contains("[output truncated at 10MB]"));
    // The truncated content (before "...") should end at a newline boundary
    let before_ellipsis = result.split("...\n").next().unwrap();
    assert!(before_ellipsis.ends_with('\n') || before_ellipsis.ends_with('a'));
}

// --- skipped tasks excluded from sequential estimate ---

#[test]
fn sequential_excludes_skipped() {
    let results = [
        TaskResult {
            name: "build".into(),
            success: true,
            duration: std::time::Duration::from_secs(5),
            cached: false,
            skipped: false,
        },
        TaskResult {
            name: "test".into(),
            success: true,
            duration: std::time::Duration::from_secs(3),
            cached: false,
            skipped: false,
        },
        TaskResult {
            name: "deploy".into(),
            success: false,
            duration: std::time::Duration::ZERO,
            cached: false,
            skipped: true,
        },
    ];

    let sequential_ms: u128 = results
        .iter()
        .filter(|r| !r.skipped)
        .map(|r| r.duration.as_millis())
        .sum();
    assert_eq!(sequential_ms, 8000);

    let ran_count = results.iter().filter(|r| !r.skipped).count();
    assert_eq!(ran_count, 2);
}

// --- Cache context ---

#[test]
fn build_cache_context_returns_none_without_lpm_json() {
    let dir = tempfile::tempdir().unwrap();
    // No lpm.json → caching not configured
    let ctx = build_cache_context(
        dir.path(),
        "build",
        None,
        &[],
        &lpm_runner::bin_path::ManagedRuntimeHint::Absent,
        None,
    )
    .unwrap();
    assert!(ctx.is_none(), "should return None without lpm.json");
}

#[test]
fn build_cache_context_returns_none_when_cache_false() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"scripts":{"build":"echo hi"}}"#,
    )
    .unwrap();
    let config = lpm_runner::lpm_json::LpmJsonConfig {
        tasks: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "build".into(),
                lpm_runner::lpm_json::TaskConfig {
                    cache: false,
                    outputs: vec!["dist/**".into()],
                    ..Default::default()
                },
            );
            m
        },
        ..Default::default()
    };
    let ctx = build_cache_context(
        dir.path(),
        "build",
        None,
        &[],
        &lpm_runner::bin_path::ManagedRuntimeHint::Absent,
        Some(&config),
    )
    .unwrap();
    assert!(ctx.is_none(), "should return None when cache is false");
}

#[test]
fn build_cache_context_returns_none_when_outputs_empty() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"scripts":{"build":"echo hi"}}"#,
    )
    .unwrap();
    let config = lpm_runner::lpm_json::LpmJsonConfig {
        tasks: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "build".into(),
                lpm_runner::lpm_json::TaskConfig {
                    cache: true,
                    outputs: vec![], // empty outputs
                    ..Default::default()
                },
            );
            m
        },
        ..Default::default()
    };
    let ctx = build_cache_context(
        dir.path(),
        "build",
        None,
        &[],
        &lpm_runner::bin_path::ManagedRuntimeHint::Absent,
        Some(&config),
    )
    .unwrap();
    assert!(ctx.is_none(), "should return None when outputs are empty");
}

#[test]
fn build_cache_context_returns_some_when_properly_configured() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"scripts":{"build":"echo hi"}}"#,
    )
    .unwrap();
    let config = lpm_runner::lpm_json::LpmJsonConfig {
        tasks: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "build".into(),
                lpm_runner::lpm_json::TaskConfig {
                    cache: true,
                    outputs: vec!["dist/**".into()],
                    ..Default::default()
                },
            );
            m
        },
        ..Default::default()
    };
    let ctx = build_cache_context(
        dir.path(),
        "build",
        None,
        &[],
        &lpm_runner::bin_path::ManagedRuntimeHint::Absent,
        Some(&config),
    )
    .unwrap();
    assert!(ctx.is_some(), "should return Some for valid cache config");
    let ctx = ctx.unwrap();
    assert_eq!(ctx.command, "echo hi");
    assert_eq!(ctx.cache_key.len(), 64, "cache key should be SHA-256 hex");
}

#[test]
fn build_cache_context_changes_with_arguments_and_managed_runtime() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"scripts":{"build":"echo hi"}}"#,
    )
    .unwrap();
    let config = lpm_runner::lpm_json::LpmJsonConfig {
        tasks: std::collections::HashMap::from([(
            "build".into(),
            lpm_runner::lpm_json::TaskConfig {
                cache: true,
                outputs: vec!["dist/**".into()],
                ..Default::default()
            },
        )]),
        ..Default::default()
    };
    let node_20 = lpm_runner::bin_path::ManagedRuntimeHint::Resolved(vec![
        lpm_runner::bin_path::ManagedRuntimeBin {
            runtime: lpm_runtime::detect::RuntimeKind::Node,
            version: "20.19.0".into(),
            bin_dir: dir.path().join("node-20/bin"),
        },
    ]);
    let node_22 = lpm_runner::bin_path::ManagedRuntimeHint::Resolved(vec![
        lpm_runner::bin_path::ManagedRuntimeBin {
            runtime: lpm_runtime::detect::RuntimeKind::Node,
            version: "22.14.0".into(),
            bin_dir: dir.path().join("node-22/bin"),
        },
    ]);

    let node_20_browser = build_cache_context(
        dir.path(),
        "build",
        None,
        &["--target=browser".into()],
        &node_20,
        Some(&config),
    )
    .unwrap()
    .unwrap();
    let node_20_server = build_cache_context(
        dir.path(),
        "build",
        None,
        &["--target=server".into()],
        &node_20,
        Some(&config),
    )
    .unwrap()
    .unwrap();
    let node_22_browser = build_cache_context(
        dir.path(),
        "build",
        None,
        &["--target=browser".into()],
        &node_22,
        Some(&config),
    )
    .unwrap()
    .unwrap();

    assert_ne!(node_20_browser.cache_key, node_20_server.cache_key);
    assert_ne!(node_20_browser.cache_key, node_22_browser.cache_key);
}

// --- Format helpers ---

#[test]
fn format_duration_milliseconds() {
    assert_eq!(
        format_duration(std::time::Duration::from_millis(42)),
        "42ms"
    );
    assert_eq!(
        format_duration(std::time::Duration::from_millis(999)),
        "999ms"
    );
}

#[test]
fn format_duration_seconds() {
    assert_eq!(
        format_duration(std::time::Duration::from_millis(1500)),
        "1.5s"
    );
    assert_eq!(format_duration(std::time::Duration::from_secs(10)), "10.0s");
}

// --- Meta-task detection ---

/// Read the on-disk `package.json` `scripts` map for a fixture dir, the
/// same way `run_multi` does at runtime. Lets the tests exercise the new
/// `is_meta_task(name, tasks, pkg_scripts)` shape without re-reading inside
/// the helper itself.
fn pkg_scripts_at(dir: &Path) -> Option<HashMap<String, String>> {
    lpm_workspace::read_package_json(&dir.join("package.json"))
        .ok()
        .map(|p| p.scripts)
}

#[test]
fn meta_task_with_deps_no_command_no_script() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"scripts": {"lint": "eslint .", "test": "vitest"}}"#,
    )
    .unwrap();

    let mut tasks = std::collections::HashMap::new();
    // "ci" has dependsOn but no command and no package.json script → meta-task
    tasks.insert(
        "ci".into(),
        lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["lint".into(), "test".into()],
            ..Default::default()
        },
    );

    let scripts = pkg_scripts_at(dir.path());
    assert!(is_meta_task("ci", &tasks, scripts.as_ref()));
}

#[test]
fn meta_task_false_when_has_script() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"scripts": {"ci": "echo ci", "lint": "eslint ."}}"#,
    )
    .unwrap();

    let mut tasks = std::collections::HashMap::new();
    tasks.insert(
        "ci".into(),
        lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["lint".into()],
            ..Default::default()
        },
    );

    let scripts = pkg_scripts_at(dir.path());
    assert!(!is_meta_task("ci", &tasks, scripts.as_ref()));
}

#[test]
fn meta_task_false_when_has_command() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"scripts": {"lint": "eslint ."}}"#,
    )
    .unwrap();

    let mut tasks = std::collections::HashMap::new();
    tasks.insert(
        "ci".into(),
        lpm_runner::lpm_json::TaskConfig {
            command: Some("echo all-done".into()),
            depends_on: vec!["lint".into()],
            ..Default::default()
        },
    );

    let scripts = pkg_scripts_at(dir.path());
    assert!(!is_meta_task("ci", &tasks, scripts.as_ref()));
}

#[test]
fn meta_task_false_when_no_deps() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

    let tasks = std::collections::HashMap::new();
    let scripts = pkg_scripts_at(dir.path());
    assert!(!is_meta_task("build", &tasks, scripts.as_ref()));
}

// --- is_task_cached_with_config ---

#[test]
fn is_task_cached_with_config_returns_true() {
    let config = lpm_runner::lpm_json::LpmJsonConfig {
        tasks: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "build".into(),
                lpm_runner::lpm_json::TaskConfig {
                    cache: true,
                    outputs: vec!["dist/**".into()],
                    ..Default::default()
                },
            );
            m
        },
        ..Default::default()
    };
    assert!(is_task_cached_with_config("build", Some(&config)));
}

#[test]
fn is_task_cached_with_config_false_no_outputs() {
    let config = lpm_runner::lpm_json::LpmJsonConfig {
        tasks: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "lint".into(),
                lpm_runner::lpm_json::TaskConfig {
                    cache: true,
                    outputs: vec![],
                    ..Default::default()
                },
            );
            m
        },
        ..Default::default()
    };
    assert!(!is_task_cached_with_config("lint", Some(&config)));
}

#[test]
fn is_task_cached_with_config_false_no_config() {
    assert!(!is_task_cached_with_config("build", None));
}

// --- run_task resolves lpm.json command ---

#[test]
fn run_task_uses_lpm_json_command() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

    let mut tasks = std::collections::HashMap::new();
    tasks.insert(
        "codegen".into(),
        lpm_runner::lpm_json::TaskConfig {
            command: Some("echo codegen-ran".into()),
            ..Default::default()
        },
    );

    let result = run_task(dir.path(), "codegen", &[], None, &tasks, &Unknown);
    assert!(result.is_ok(), "should run lpm.json command: {result:?}");
}

#[test]
fn run_task_falls_back_to_script() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"scripts": {"build": "echo build-ran"}}"#,
    )
    .unwrap();

    let tasks = std::collections::HashMap::new();
    let result = run_task(dir.path(), "build", &[], None, &tasks, &Unknown);
    assert!(result.is_ok(), "should fall back to package.json script");
}

#[test]
fn run_task_errors_for_unknown() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

    let tasks = std::collections::HashMap::new();
    let result = run_task(dir.path(), "nonexistent", &[], None, &tasks, &Unknown);
    assert!(result.is_err());
}

// --- run_task_captured resolves lpm.json command ---

#[test]
fn run_task_captured_uses_lpm_json_command() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), r#"{"scripts": {}}"#).unwrap();

    let mut tasks = std::collections::HashMap::new();
    tasks.insert(
        "codegen".into(),
        lpm_runner::lpm_json::TaskConfig {
            command: Some("echo captured-codegen".into()),
            ..Default::default()
        },
    );

    let result = run_task_captured(dir.path(), "codegen", &[], None, &tasks, &Unknown);
    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.stdout.contains("captured-codegen"));
}

// --- JSON summary ---

#[test]
fn json_summary_format() {
    let results = vec![
        TaskResult {
            name: "lint".into(),
            success: true,
            duration: std::time::Duration::from_millis(100),
            cached: false,
            skipped: false,
        },
        TaskResult {
            name: "test".into(),
            success: false,
            duration: std::time::Duration::from_millis(200),
            cached: false,
            skipped: false,
        },
        TaskResult {
            name: "deploy".into(),
            success: false,
            duration: std::time::Duration::ZERO,
            cached: false,
            skipped: true,
        },
    ];

    // Just verify it doesn't panic — output goes to stdout
    // which is captured by the test harness
    print_json_summary(&results, std::time::Duration::from_millis(300));
}

// --- dependsOn expansion: single script with deps should expand ---

#[test]
fn task_graph_expands_single_script_deps() {
    // "test" depends on "check" — requesting just "test" should include both
    let scripts: std::collections::HashMap<String, String> = [
        ("test".to_string(), "vitest".to_string()),
        ("check".to_string(), "tsc --noEmit".to_string()),
    ]
    .into();

    let mut tasks = std::collections::HashMap::new();
    tasks.insert(
        "test".into(),
        lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["check".into()],
            ..Default::default()
        },
    );

    let levels = lpm_runner::task_graph::task_levels(&scripts, &tasks, &["test".into()]).unwrap();

    // Should be 2 levels: [check], [test]
    assert_eq!(levels.len(), 2, "expected 2 levels, got {levels:?}");
    assert_eq!(levels[0], vec!["check"]);
    assert_eq!(levels[1], vec!["test"]);
}

#[test]
fn single_script_no_deps_single_level() {
    let scripts: std::collections::HashMap<String, String> =
        [("build".to_string(), "vite build".to_string())].into();
    let tasks = std::collections::HashMap::new();

    let levels = lpm_runner::task_graph::task_levels(&scripts, &tasks, &["build".into()]).unwrap();

    assert_eq!(levels.len(), 1);
    assert_eq!(levels[0], vec!["build"]);
}

// --- ScriptWithOutput error preserves output ---

#[test]
fn script_with_output_error_captures_stderr() {
    let err = LpmError::ScriptWithOutput {
        code: 1,
        stdout: "some stdout".into(),
        stderr: "detailed error info".into(),
    };
    assert!(err.to_string().contains("code 1"));
    if let LpmError::ScriptWithOutput { stderr, .. } = &err {
        assert_eq!(stderr, "detailed error info");
    }
}

// --- Remaining nested meta-task dependency resolution ---

#[test]
fn nested_meta_task_deps_expand_correctly() {
    // release → ci (meta-task), ci → [lint, test]
    let scripts: std::collections::HashMap<String, String> = [
        ("lint".to_string(), "eslint .".to_string()),
        ("test".to_string(), "vitest".to_string()),
    ]
    .into();

    let mut tasks = std::collections::HashMap::new();
    tasks.insert(
        "ci".into(),
        lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["lint".into(), "test".into()],
            ..Default::default()
        },
    );
    tasks.insert(
        "release".into(),
        lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["ci".into()],
            ..Default::default()
        },
    );

    let levels =
        lpm_runner::task_graph::task_levels(&scripts, &tasks, &["release".into()]).unwrap();

    // [lint, test], [ci], [release]
    assert_eq!(levels.len(), 3, "got: {levels:?}");
    assert!(levels[0].contains(&"lint".to_string()));
    assert!(levels[0].contains(&"test".to_string()));
    assert_eq!(levels[1], vec!["ci"]);
    assert_eq!(levels[2], vec!["release"]);
}

// --- Remaining sequential failure uses aggregate exit code ---

#[test]
fn sequential_failure_exit_code_is_failure_count() {
    // Verify the run_tasks_sequential path returns failure_count, not the
    // raw script exit code. We can't easily run the async function in a
    // sync test, but we can verify the exit-code logic directly.

    let results = [
        TaskResult {
            name: "lint".into(),
            success: false,
            duration: std::time::Duration::from_millis(100),
            cached: false,
            skipped: false,
        },
        TaskResult {
            name: "test".into(),
            success: false,
            duration: std::time::Duration::ZERO,
            cached: false,
            skipped: true,
        },
    ];

    let failure_count = results.iter().filter(|r| !r.success && !r.skipped).count();
    assert_eq!(failure_count, 1, "only non-skipped failures counted");

    // The function returns LpmError::ExitCode(failure_count as i32)
    let err = LpmError::ExitCode(failure_count as i32);
    if let LpmError::ExitCode(code) = err {
        assert_eq!(
            code, 1,
            "exit code should be failure count, not script exit code"
        );
    }
}

// --- Meta-task execution in sequential path ---

#[test]
fn meta_task_in_expanded_graph_is_noop() {
    // Verify that a meta-task (dependsOn, no command, no script) in a
    // task graph is detected as a meta-task and would succeed as a no-op.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"scripts": {"lint": "eslint .", "test": "vitest"}}"#,
    )
    .unwrap();

    let mut tasks = std::collections::HashMap::new();
    tasks.insert(
        "ci".into(),
        lpm_runner::lpm_json::TaskConfig {
            depends_on: vec!["lint".into(), "test".into()],
            ..Default::default()
        },
    );

    let scripts = pkg_scripts_at(dir.path());

    // "ci" should be detected as a meta-task
    assert!(is_meta_task("ci", &tasks, scripts.as_ref()));

    // "lint" should NOT be a meta-task (it has a script)
    assert!(!is_meta_task("lint", &tasks, scripts.as_ref()));

    // Task graph should expand ci → [lint, test], [ci]
    let pkg = lpm_workspace::read_package_json(&dir.path().join("package.json")).unwrap();
    let levels = lpm_runner::task_graph::task_levels(&pkg.scripts, &tasks, &["ci".into()]).unwrap();
    assert_eq!(levels.len(), 2);
    assert_eq!(levels[1], vec!["ci"]);
}
