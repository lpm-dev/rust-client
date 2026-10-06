use super::*;
use std::cell::Cell;
use std::fs;

struct ProbeAllocator;
thread_local! {
    static PROBE_ENABLED: Cell<bool> = const { Cell::new(false) };
    static LARGE_ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
    static MAX_ALLOCATION: Cell<usize> = const { Cell::new(0) };
}
fn record_allocation(size: usize) {
    if PROBE_ENABLED.try_with(Cell::get).unwrap_or(false) {
        ALLOCATED_BYTES.with(|value| value.set(value.get() + size));
        MAX_ALLOCATION.with(|value| value.set(value.get().max(size)));
        if size >= 10 * 1024 * 1024 {
            LARGE_ALLOCATIONS.with(|value| value.set(value.get() + 1));
        }
    }
}
#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;
unsafe impl std::alloc::GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: Forward the caller's unchanged allocator contract to System.
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: The pointer and layout came from the same System allocator.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        record_allocation(size);
        // SAFETY: Forward the caller's unchanged allocator contract to System.
        unsafe { std::alloc::System.realloc(ptr, layout, size) }
    }
}

pub(super) fn allocation_probe<T>(operation: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOCATED_BYTES.with(|value| value.set(0));
    MAX_ALLOCATION.with(|value| value.set(0));
    PROBE_ENABLED.with(|value| value.set(true));
    let result = operation();
    PROBE_ENABLED.with(|value| value.set(false));
    (
        result,
        ALLOCATED_BYTES.with(Cell::get),
        MAX_ALLOCATION.with(Cell::get),
    )
}

fn resolve(
    dir: &tempfile::TempDir,
    source: serde_json::Value,
) -> Result<ResolvedSchema, SourceError> {
    let bytes = serde_json::to_vec(&source).unwrap();
    resolve_schema(dir.path(), &bytes, serde_json::from_slice(&bytes).unwrap())
}

#[test]
fn fragment_type_errors_preserve_the_field_pointer_without_value_literals() {
    for (fragment, pointer) in [
        (
            serde_json::json!({"vars":{"KEY":{"required":"private-fixture-value"}}}),
            "/vars/KEY/required",
        ),
        (serde_json::json!({"vars":{"KEY":12}}), "/vars/KEY"),
        (
            serde_json::json!({"clientPrefixes":[12]}),
            "/clientPrefixes/0",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("base.json"), fragment.to_string()).unwrap();
        let error = resolve(&dir, serde_json::json!({"extends":["base.json"]})).unwrap_err();
        assert_eq!(error.diagnostic.code, "env.invalid_definition");
        assert_eq!(error.diagnostic.source, "base.json");
        assert_eq!(error.diagnostic.pointer, pointer);
        assert!(error.diagnostic.message.unwrap().contains("value type"));
        assert!(
            !serde_json::to_string(&error.diagnostic)
                .unwrap()
                .contains("private-fixture-value")
        );
    }
}

#[test]
fn diamond_imports_share_one_declaration_origin_and_read_each_file_once() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("leaf.json"),
        r#"{"vars":{"VALUE":{"default":"one"}}}"#,
    )
    .unwrap();
    for name in ["left", "right"] {
        fs::write(
            dir.path().join(format!("{name}.json")),
            r#"{"extends":["leaf.json"]}"#,
        )
        .unwrap();
    }
    let result = resolve(
        &dir,
        serde_json::json!({"extends":["left.json","right.json"]}),
    )
    .unwrap();
    assert_eq!(result.stats.nodes, 4);
    assert_eq!(result.stats.edges, 4);
    assert_eq!(result.dependencies.len(), 3);
    assert_eq!(result.origins["VALUE"].source, "leaf.json");
    assert_eq!(result.schema.vars["VALUE"].default.as_deref(), Some("one"));
}

#[test]
fn complete_overrides_resolve_conflicts_without_retaining_inherited_security_policy() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("one.json"),
        r#"{"vars":{"VALUE":{"secret":true,"required":true}}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("two.json"),
        r#"{"vars":{"VALUE":{"default":"public"}}}"#,
    )
    .unwrap();
    let input = serde_json::json!({"extends":["one.json","two.json"]});
    assert_eq!(
        resolve(&dir, input.clone()).unwrap_err().diagnostic.code,
        "env.declaration_conflict"
    );
    let mut input = input;
    input["overrides"] = serde_json::json!({"VALUE":{"format":"integer","default":"1"}});
    let result = resolve(&dir, input).unwrap();
    assert!(!result.schema.vars["VALUE"].secret);
    assert!(!result.schema.vars["VALUE"].required);
    assert_eq!(
        result.origins["VALUE"].pointer,
        "/envSchema/overrides/VALUE"
    );
}

#[test]
fn overrides_require_an_inherited_declaration_and_cannot_duplicate_local_rules() {
    let dir = tempfile::tempdir().unwrap();
    for input in [
        serde_json::json!({"overrides":{"A":{}}}),
        serde_json::json!({"vars":{"A":{}},"overrides":{"A":{}}}),
    ] {
        assert_eq!(
            resolve(&dir, input).unwrap_err().diagnostic.code,
            "env.override_missing"
        );
    }
    fs::write(dir.path().join("base.json"), r#"{"vars":{"A":{}}}"#).unwrap();
    assert_eq!(
        resolve(
            &dir,
            serde_json::json!({"extends":["base.json"],"vars":{"A":{}},"overrides":{"A":{}}})
        )
        .unwrap_err()
        .diagnostic
        .code,
        "env.declaration_conflict"
    );
}

#[test]
fn relationships_validate_after_cross_fragment_merge() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("refs.json"), r#"{"vars":{"TOKEN":{"requiredWhen":{"variable":"MODE","equals":"live"}}},"groups":{"pair":{"mode":"allOrNone","vars":["MODE","TOKEN"]}}}"#).unwrap();
    let result = resolve(
        &dir,
        serde_json::json!({"extends":["refs.json"],"vars":{"MODE":{}}}),
    )
    .unwrap();
    assert_eq!(result.schema.vars.len(), 2);
    assert_eq!(result.schema.groups.len(), 1);
    let error = resolve(&dir, serde_json::json!({"extends":["refs.json"]})).unwrap_err();
    assert_eq!(error.diagnostic.source, "refs.json");
}

#[test]
fn nested_relative_imports_stay_inside_the_project_boundary() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("schemas")).unwrap();
    fs::write(dir.path().join("base.json"), r#"{"vars":{"A":{}}}"#).unwrap();
    fs::write(
        dir.path().join("schemas/nested.json"),
        r#"{"extends":["../base.json"]}"#,
    )
    .unwrap();
    assert!(resolve(&dir, serde_json::json!({"extends":["schemas/nested.json"]})).is_ok());
    for path in [
        "../outside.json",
        "/tmp/outside.json",
        "C:/outside.json",
        "a\\b",
        "NUL",
        "trailing.",
    ] {
        assert!(
            resolve(&dir, serde_json::json!({"extends":[path]})).is_err(),
            "{path}"
        );
    }
}

#[test]
fn cycles_and_graph_depth_fail_with_stable_codes() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("cycle.json"),
        r#"{"extends":["cycle.json"]}"#,
    )
    .unwrap();
    assert_eq!(
        resolve(&dir, serde_json::json!({"extends":["cycle.json"]}))
            .unwrap_err()
            .diagnostic
            .code,
        "env.import_cycle"
    );
    for n in 0..=MAX_DEPTH {
        fs::write(
            dir.path().join(format!("{n}.json")),
            serde_json::json!({"extends":[format!("{}.json",n+1)]}).to_string(),
        )
        .unwrap();
    }
    assert_eq!(
        resolve(&dir, serde_json::json!({"extends":["0.json"]}))
            .unwrap_err()
            .diagnostic
            .code,
        "env.graph_depth"
    );
}

#[test]
fn missing_import_errors_retain_literal_repair_paths_without_values() {
    let dir = tempfile::tempdir().unwrap();
    let error = resolve(&dir, serde_json::json!({"extends":["schema[base].json"]})).unwrap_err();
    assert_eq!(error.requested_paths, ["schema[base].json"]);
    assert_eq!(error.diagnostic.code, "env.import_unreadable");
}

#[test]
fn unchanged_and_overridden_dependencies_still_affect_fingerprint_and_freshness() {
    let dir = tempfile::tempdir().unwrap();
    let leaf = dir.path().join("leaf.json");
    fs::write(&leaf, r#"{"vars":{"A":{"default":"one"}}}"#).unwrap();
    let input = serde_json::json!({"extends":["leaf.json"],"overrides":{"A":{}}});
    let before = resolve(&dir, input.clone()).unwrap();
    before.verify_dependencies().unwrap();
    fs::write(
        dir.path().join("replacement.json"),
        r#"{"vars":{"A":{"default":"two"}}}"#,
    )
    .unwrap();
    fs::rename(dir.path().join("replacement.json"), &leaf).unwrap();
    assert_eq!(
        before.verify_dependencies().unwrap_err().diagnostic.code,
        "env.source_changed"
    );
    let after = resolve(&dir, input).unwrap();
    assert_ne!(before.fingerprint, after.fingerprint);
    assert_eq!(
        serde_json::to_value(before.schema).unwrap(),
        serde_json::to_value(after.schema).unwrap()
    );
}

#[test]
fn declaration_diagnostics_do_not_echo_default_or_pattern_literals() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("bad.json"),
        r#"{"vars":{"A":{"pattern":"[PRIVATE_PATTERN"}}}"#,
    )
    .unwrap();
    let error = resolve(&dir, serde_json::json!({"extends":["bad.json"]})).unwrap_err();
    let rendered = serde_json::to_string(&error.diagnostic).unwrap();
    assert!(!rendered.contains("PRIVATE_PATTERN"));
    assert_eq!(error.diagnostic.code, "env.invalid_pattern");
    assert_eq!(error.diagnostic.pointer, "/vars/A");
}

#[test]
fn built_in_presets_share_the_node_origin_without_network_or_behavioral_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let result = resolve(
        &dir,
        serde_json::json!({"extends":["preset:node","preset:nextjs","preset:vite"]}),
    )
    .unwrap();
    assert_eq!(result.origins["NODE_ENV"].source, "preset:node");
    assert!(result.dependencies.is_empty());
    assert!(
        result
            .schema
            .vars
            .values()
            .all(|r| r.default.is_none() && !r.required && !r.secret)
    );
}

#[test]
fn output_budget_counts_json_escaping_before_allocating_past_the_limit() {
    let value = "\n".repeat(4096);
    assert!(bounded_json(&value, 4096).is_err());
    assert_eq!(bounded_json(&value, 8194).unwrap().len(), 8194);
}

#[cfg(unix)]
#[test]
fn imports_reject_parent_and_leaf_symlinks_and_non_regular_files() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("leaf.json"), "{}").unwrap();
    symlink(external.path(), dir.path().join("parent")).unwrap();
    symlink(
        external.path().join("leaf.json"),
        dir.path().join("leaf.json"),
    )
    .unwrap();
    fs::create_dir(dir.path().join("directory.json")).unwrap();
    for path in ["parent/leaf.json", "leaf.json", "directory.json"] {
        assert_eq!(
            resolve(&dir, serde_json::json!({"extends":[path]}))
                .unwrap_err()
                .diagnostic
                .code,
            "env.import_unreadable"
        );
    }
}

#[test]
fn override_diagnostics_have_stable_lexical_precedence() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("base.json"), r#"{"vars":{"A":{}}}"#).unwrap();
    for _ in 0..128 {
        let error = resolve(&dir, serde_json::json!({"extends":["base.json"], "vars":{"A":{}}, "overrides":{"A":{},"Z":{}}})).unwrap_err();
        assert_eq!(error.diagnostic.code, "env.declaration_conflict");
        assert_eq!(error.diagnostic.pointer, "/envSchema/overrides/A");
    }
}

#[test]
fn imported_group_definition_errors_point_to_the_group_origin() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("leaf.json"),
        r#"{"groups":{"pair":{"mode":"allOrNone","vars":["UNDECLARED"]}}}"#,
    )
    .unwrap();
    let error = resolve(&dir, serde_json::json!({"extends":["leaf.json"]})).unwrap_err();
    assert_eq!(error.diagnostic.source, "leaf.json");
    assert_eq!(error.diagnostic.pointer, "/groups/pair");
    let error = resolve(&dir, serde_json::json!({"extends":["../escape.json"]})).unwrap_err();
    assert_eq!(error.diagnostic.pointer, "/envSchema/extends");
}

#[test]
fn memoized_subtrees_enforce_depth_independent_of_import_order() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("sub.json"), r#"{"extends":["child.json"]}"#).unwrap();
    fs::write(dir.path().join("child.json"), "{}").unwrap();
    for n in 0..15 {
        let next = if n == 14 {
            "sub.json".into()
        } else {
            format!("{}.json", n + 1)
        };
        fs::write(
            dir.path().join(format!("{n}.json")),
            serde_json::json!({"extends":[next]}).to_string(),
        )
        .unwrap();
    }
    for imports in [["sub.json", "0.json"], ["0.json", "sub.json"]] {
        let result = resolve(&dir, serde_json::json!({"extends":imports}));
        assert_eq!(result.unwrap_err().diagnostic.code, "env.graph_depth");
    }
}

#[test]
fn group_overrides_apply_before_effective_member_budget_independent_of_import_order() {
    let dir = tempfile::tempdir().unwrap();
    let names: Vec<_> = (0..4096).map(|n| format!("A{n}")).collect();
    let vars: serde_json::Map<_, _> = names
        .iter()
        .map(|n| (n.clone(), serde_json::json!({})))
        .collect();
    fs::write(
        dir.path().join("left.json"),
        serde_json::json!({"vars":vars,"groups":{"g":{"mode":"allOrNone","vars":names}}})
            .to_string(),
    )
    .unwrap();
    fs::write(dir.path().join("right.json"), r#"{"groups":{"g":{"mode":"allOrNone","vars":["A0"]},"h":{"mode":"allOrNone","vars":["A0"]}}}"#).unwrap();
    for imports in [["left.json", "right.json"], ["right.json", "left.json"]] {
        let result = resolve(&dir, serde_json::json!({"extends":imports,"groupOverrides":{"g":{"mode":"allOrNone","vars":["A0"]}}})).unwrap();
        assert_eq!(
            result
                .schema
                .groups
                .values()
                .map(|g| g.vars.len())
                .sum::<usize>(),
            2
        );
    }
}

#[test]
fn duplicate_local_prefixes_reject_before_cross_document_union() {
    let dir = tempfile::tempdir().unwrap();
    let result = resolve(&dir, serde_json::json!({"clientPrefixes":["APP_","APP_"]}));
    assert_eq!(result.unwrap_err().diagnostic.code, "env.invalid_prefixes");
    fs::write(
        dir.path().join("fragment.json"),
        r#"{"clientPrefixes":["APP_","APP_"]}"#,
    )
    .unwrap();
    let result = resolve(&dir, serde_json::json!({"extends":["fragment.json"]}));
    assert_eq!(result.unwrap_err().diagnostic.code, "env.invalid_prefixes");
}

#[test]
fn oversized_effective_enums_reject_before_copying_declarations() {
    let dir = tempfile::tempdir().unwrap();
    let text = "\"\",".repeat(500_000);
    for n in 0..4 {
        fs::write(
            dir.path().join(format!("{n}.json")),
            format!(r#"{{"vars":{{"A{n}":{{"enum":[{text}""]}}}}}}"#),
        )
        .unwrap();
    }
    LARGE_ALLOCATIONS.with(|value| value.set(0));
    ALLOCATED_BYTES.with(|value| value.set(0));
    PROBE_ENABLED.with(|value| value.set(true));
    let result = resolve(
        &dir,
        serde_json::json!({"extends":["0.json","1.json","2.json","3.json"]}),
    );
    PROBE_ENABLED.with(|value| value.set(false));
    eprintln!(
        "allocation probe: bytes={}, large={}",
        ALLOCATED_BYTES.with(Cell::get),
        LARGE_ALLOCATIONS.with(Cell::get)
    );
    assert!(
        LARGE_ALLOCATIONS.with(Cell::get) <= 4,
        "oversized schemas must reject before cloning enum storage"
    );
    assert_eq!(result.unwrap_err().diagnostic.code, "env.output_budget");
}

#[test]
fn bounded_json_capacity_never_exceeds_its_output_budget() {
    let value = "x".repeat(1_300_000);
    let bytes = bounded_json(&value, MAX_SCHEMA_BYTES).unwrap();
    assert!(
        bytes.capacity() <= MAX_SCHEMA_BYTES,
        "capacity={}",
        bytes.capacity()
    );
}

#[test]
fn human_diagnostics_escape_bidi_controls_without_changing_repair_paths() {
    let dir = tempfile::tempdir().unwrap();
    for control in ['\u{061c}', '\u{200e}', '\u{200f}', '\u{202e}', '\u{2066}'] {
        let path = format!("safe{control}json");
        let error = resolve(&dir, serde_json::json!({"extends":[path]})).unwrap_err();
        assert!(!error.to_string().contains(control), "{control:?}");
        assert_eq!(error.requested_paths, [path]);
    }
    let error = resolve(
        &dir,
        serde_json::json!({"extends":["preset:safe\u{2066}name"]}),
    )
    .unwrap_err();
    assert!(!error.to_string().contains('\u{2066}'));
    let error = resolve(&dir, serde_json::json!({"extends":["中文.json"]})).unwrap_err();
    assert!(error.to_string().contains("中文.json"));
}

#[test]
fn effective_schema_at_the_exact_output_limit_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let mut schema = lpm_env::EnvSchema::default();
    schema.vars.insert(
        "VALUE".into(),
        lpm_env::EnvVarRule {
            description: Some(String::new()),
            ..Default::default()
        },
    );
    let overhead = serde_json::to_vec(&schema).unwrap().len();
    let text = "x".repeat(MAX_SCHEMA_BYTES - overhead);
    schema.vars.get_mut("VALUE").unwrap().description = Some(text.clone());
    assert_eq!(serde_json::to_vec(&schema).unwrap().len(), MAX_SCHEMA_BYTES);
    assert!(
        resolve(
            &dir,
            serde_json::json!({"vars":{"VALUE":{"description":text}}})
        )
        .is_ok()
    );
}

#[cfg(unix)]
#[test]
fn retargeting_the_selected_project_symlink_invalidates_its_snapshot() {
    use std::os::unix::fs::symlink;
    let parent = tempfile::tempdir().unwrap();
    for name in ["one", "two"] {
        fs::create_dir(parent.path().join(name)).unwrap();
        fs::write(
            parent.path().join(name).join("base.json"),
            r#"{"vars":{"A":{}}}"#,
        )
        .unwrap();
    }
    let selected = parent.path().join("selected");
    symlink(parent.path().join("one"), &selected).unwrap();
    let input = br#"{"extends":["base.json"]}"#;
    let snapshot =
        resolve_schema(&selected, input, serde_json::from_slice(input).unwrap()).unwrap();
    snapshot.verify_dependencies().unwrap();
    fs::remove_file(&selected).unwrap();
    symlink(parent.path().join("two"), &selected).unwrap();
    assert_eq!(
        snapshot.verify_dependencies().unwrap_err().diagnostic.code,
        "env.source_changed"
    );
}

#[test]
fn dependency_verification_streams_large_fragments_without_content_allocations() {
    let dir = tempfile::tempdir().unwrap();
    let text = "x".repeat(1_500_000);
    for index in 0..4 {
        fs::write(
            dir.path().join(format!("{index}.json")),
            serde_json::json!({"vars":{format!("A{index}"):{"description":text}}}).to_string(),
        )
        .unwrap();
    }
    let resolved = resolve(&dir, serde_json::json!({"extends":["0.json","1.json","2.json","3.json"],"overrides":{"A0":{},"A1":{},"A2":{},"A3":{}}})).unwrap();
    resolved.verify_dependencies().unwrap();
    ALLOCATED_BYTES.with(|value| value.set(0));
    MAX_ALLOCATION.with(|value| value.set(0));
    PROBE_ENABLED.with(|value| value.set(true));
    for _ in 0..32 {
        resolved.verify_dependencies().unwrap();
    }
    PROBE_ENABLED.with(|value| value.set(false));
    eprintln!(
        "verification allocation bytes={}, max={}",
        ALLOCATED_BYTES.with(Cell::get),
        MAX_ALLOCATION.with(Cell::get)
    );
    assert!(MAX_ALLOCATION.with(Cell::get) < 256 * 1024);
}

#[test]
fn borrowed_oversized_definitions_reject_before_allocating_a_deep_copy() {
    let directory = tempfile::tempdir().unwrap();
    let mut definition = lpm_env::EnvSchemaDefinition::default();
    definition.vars.insert(
        "VALUE".into(),
        lpm_env::EnvVarRule {
            enum_values: Some(vec![String::new(); 700_000]),
            ..Default::default()
        },
    );
    let (result, allocated, _) =
        allocation_probe(|| super::resolve_schema_borrowed(directory.path(), b"{}", &definition));
    assert_eq!(result.unwrap_err().diagnostic.code, "env.output_budget");
    assert!(
        allocated < 100_000,
        "rejected borrowed definition allocated {allocated} bytes"
    );
}

#[test]
fn effective_rules_reuse_owned_declaration_storage_after_graph_preflight() {
    let directory = tempfile::tempdir().unwrap();
    let mut definition = lpm_env::EnvSchemaDefinition::default();
    let values = vec!["alpha".into(), "beta".into()];
    let original = values.as_ptr();
    definition.vars.insert(
        "VALUE".into(),
        lpm_env::EnvVarRule {
            enum_values: Some(values),
            ..Default::default()
        },
    );
    let result = super::resolve_schema(directory.path(), b"{}", definition).unwrap();
    assert_eq!(
        result.schema.vars["VALUE"]
            .enum_values
            .as_ref()
            .unwrap()
            .as_ptr(),
        original
    );
}

#[test]
fn conflicting_declarations_report_both_authored_origins_and_the_key() {
    for field in ["vars", "groups"] {
        let dir = tempfile::tempdir().unwrap();
        let value = if field == "vars" {
            serde_json::json!({})
        } else {
            serde_json::json!({"mode":"allOrNone","vars":["A"]})
        };
        for source in ["a.json", "b.json"] {
            fs::write(
                dir.path().join(source),
                if field == "vars" {
                    serde_json::json!({"vars":{"DUP":value}})
                } else {
                    serde_json::json!({"groups":{"DUP":value},"vars":{"A":{}}})
                }
                .to_string(),
            )
            .unwrap();
        }
        let root = if field == "vars" {
            serde_json::json!({"extends":["a.json","b.json"]})
        } else {
            serde_json::json!({"extends":["a.json","b.json"],"overrides":{"A":{}}})
        };
        let error = resolve(&dir, root).unwrap_err();
        let diagnostic = serde_json::to_value(&error.diagnostic).unwrap();
        assert_eq!(diagnostic["key"], "DUP");
        assert_eq!(diagnostic["source"], "b.json");
        assert_eq!(diagnostic["pointer"], format!("/{field}/DUP"));
        assert_eq!(diagnostic["relatedSources"][0]["source"], "a.json");
        assert_eq!(diagnostic["relatedSources"][1]["source"], "b.json");
    }
}

#[test]
fn root_selection_freshness_errors_point_to_the_manifest_root() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("selected");
    fs::create_dir(&path).unwrap();
    let root = b"{}";
    let schema = resolve_schema(&path, root, Default::default()).unwrap();
    fs::rename(&path, dir.path().join("old")).unwrap();
    fs::create_dir(&path).unwrap();
    let error = schema.verify_dependencies().unwrap_err();
    assert_eq!(error.diagnostic.source, "lpm.json");
    assert_eq!(error.diagnostic.pointer, "");
}

#[test]
fn local_conflicts_report_authored_root_and_import_pointers() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("base.json"), r#"{"vars":{"A":{}}}"#).unwrap();
    for overrides in [false, true] {
        let root = if overrides {
            serde_json::json!({"extends":["base.json"],"vars":{"A":{}},"overrides":{"A":{}}})
        } else {
            serde_json::json!({"extends":["base.json"],"vars":{"A":{}}})
        };
        let error = resolve(&dir, root).unwrap_err();
        assert_eq!(error.diagnostic.key.as_deref(), Some("A"));
        let origins = &error.diagnostic.related_sources;
        assert_eq!(origins.len(), 2);
        assert_eq!(
            origins[0].source,
            if overrides { "lpm.json" } else { "base.json" }
        );
        assert_eq!(
            origins[1].pointer,
            if overrides {
                "/envSchema/overrides/A"
            } else {
                "/envSchema/vars/A"
            }
        );
        assert!(error.to_string().contains(if overrides {
            "/envSchema/vars/A"
        } else {
            "base.json/vars/A"
        }));
    }
}

#[test]
fn missing_variable_and_group_overrides_identify_the_requested_key() {
    let dir = tempfile::tempdir().unwrap();
    for field in ["overrides", "groupOverrides"] {
        let input = if field == "overrides" {
            serde_json::json!({"overrides":{"MISSING":{}}})
        } else {
            serde_json::json!({"groupOverrides":{"MISSING":{"mode":"allOrNone","vars":["A","B"]}}})
        };
        let error = resolve(&dir, input).unwrap_err();
        assert_eq!(error.diagnostic.code, "env.override_missing");
        assert_eq!(error.diagnostic.key.as_deref(), Some("MISSING"));
    }
}

#[test]
fn composed_public_prefix_errors_explain_client_visibility() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("base.json"),
        r#"{"vars":{"VITE_API_URL":{}}}"#,
    )
    .unwrap();
    let error = resolve(&dir, serde_json::json!({"extends":["base.json"]})).unwrap_err();
    assert!(error.to_string().contains("client: true"), "{error}");
}
