//! Bounded C ABI for the bundled native schema engine. No process environment access.

use lpm_env_source::SchemaSnapshot;
use serde::Serialize;
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

const ABI_VERSION: u32 = 1;
const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

/// C callers own this result until one matching lpm_env_release call.
#[repr(C)]
pub struct LPMEnvResult {
    pub status: u32,
    pub data: *mut u8,
    pub length: usize,
    pub snapshot: *mut c_void,
}

fn result(status: u32, bytes: Vec<u8>, snapshot: Option<Arc<SchemaSnapshot>>) -> LPMEnvResult {
    let bytes = bytes.into_boxed_slice();
    let length = bytes.len();
    LPMEnvResult {
        status,
        data: Box::into_raw(bytes).cast::<u8>(),
        length,
        snapshot: snapshot.map_or(std::ptr::null_mut(), |snapshot| {
            Box::into_raw(Box::new(snapshot)).cast()
        }),
    }
}

fn failure(status: u32, code: &'static str) -> LPMEnvResult {
    result(
        status,
        format!("{{\"abiVersion\":1,\"code\":\"{code}\"}}").into_bytes(),
        None,
    )
}

fn diagnostic(error: &lpm_env_source::SourceError) -> LPMEnvResult {
    match lpm_env_source::bounded_json(&error.diagnostic, 4096) {
        Ok(bytes) => result(1, bytes, None),
        Err(_) => failure(4, "env.output_budget"),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lpm_env_abi_version() -> u32 {
    ABI_VERSION
}

/// Validate a flat schema without access to files or the process environment.
/// # Safety
/// The pointer must reference readable bytes for its length during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_validate(input: *const u8, length: usize) -> LPMEnvResult {
    if input.is_null() || length == 0 || length > lpm_env_source::MAX_SCHEMA_BYTES {
        return failure(2, "env.invalid_input");
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller supplies a live readable range; its length was bounded above.
        let bytes = unsafe { std::slice::from_raw_parts(input, length) };
        if std::str::from_utf8(bytes).is_err() {
            return failure(2, "env.invalid_utf8");
        }
        let schema = match serde_json::from_slice::<lpm_env::EnvSchema>(bytes) {
            Ok(schema) => schema,
            Err(_) => return failure(1, "env.invalid_definition"),
        };
        if let Some(error) = lpm_env::validate_schema(&schema).first() {
            return failure(1, lpm_env_source::declaration_code(&error.kind));
        }
        match lpm_env_source::schema_json(&schema) {
            Ok(bytes) => result(0, bytes, None),
            Err(_) => failure(4, "env.output_budget"),
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// # Safety
/// Non-null pointers must reference readable ranges for their lengths during this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_resolve(
    input: *const u8,
    input_length: usize,
    folder: *const u8,
    folder_length: usize,
) -> LPMEnvResult {
    if input.is_null()
        || folder.is_null()
        || input_length == 0
        || input_length > lpm_env_source::MAX_SCHEMA_BYTES
        || folder_length == 0
        || folder_length > 32 * 1024
    {
        return failure(2, "env.invalid_input");
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The C caller supplies valid ranges; lengths were bounded above.
        let input = unsafe { std::slice::from_raw_parts(input, input_length) };
        // SAFETY: The C caller supplies valid ranges; lengths were bounded above.
        let folder = unsafe { std::slice::from_raw_parts(folder, folder_length) };
        let (Ok(_), Ok(folder)) = (std::str::from_utf8(input), std::str::from_utf8(folder)) else {
            return failure(2, "env.invalid_utf8");
        };
        if folder.contains('\0') {
            return failure(2, "env.invalid_input");
        }
        let definition = match lpm_env_source::decode_definition(input, "lpm.json") {
            Ok(definition) => definition,
            Err(error) => return diagnostic(&error),
        };
        match lpm_env_source::resolve_schema(std::path::Path::new(folder), input, definition) {
            Ok(mut resolved) => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct Output<'a, E: Serialize> {
                    abi_version: u32,
                    effective: E,
                    origins: &'a std::collections::BTreeMap<String, lpm_env_source::SourceLocation>,
                    group_origins:
                        &'a std::collections::BTreeMap<String, lpm_env_source::SourceLocation>,
                    declaring_origins:
                        &'a std::collections::BTreeMap<String, lpm_env_source::SourceLocation>,
                    dependencies: &'a [lpm_env_source::SchemaDependency],
                    fingerprint: String,
                }
                let effective = lpm_env_source::ordered_schema(&resolved.schema);
                let output = Output {
                    abi_version: ABI_VERSION,
                    effective,
                    origins: &resolved.origins,
                    group_origins: &resolved.group_origins,
                    declaring_origins: &resolved.declaring_origins,
                    dependencies: &resolved.dependencies,
                    fingerprint: hex::encode(resolved.fingerprint),
                };
                match lpm_env_source::bounded_json(&output, OUTPUT_LIMIT) {
                    Ok(bytes) => {
                        let Some(snapshot) = Arc::get_mut(&mut resolved.snapshot) else {
                            return failure(3, "env.engine_internal");
                        };
                        snapshot.origins.clear();
                        snapshot.group_origins.clear();
                        snapshot.declaring_origins.clear();
                        result(0, bytes, Some(resolved.snapshot))
                    }
                    Err(_) => failure(4, "env.output_budget"),
                }
            }
            Err(error) => diagnostic(&error),
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// # Safety
/// The snapshot must come from a live successful result and cannot race its release.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_verify(snapshot: *const c_void) -> u32 {
    if snapshot.is_null() {
        return 2;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller retains the successful result for this entire call.
        let snapshot = unsafe { &*snapshot.cast::<Arc<SchemaSnapshot>>() };
        if snapshot.verify_dependencies().is_ok() {
            0
        } else {
            1
        }
    }))
    .unwrap_or(3)
}

/// # Safety
/// The result must be exclusively borrowed and retain its original allocation metadata.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_clear_output(result: *mut LPMEnvResult) {
    if result.is_null() {
        return;
    }
    // SAFETY: The caller exclusively borrows a live result during this call.
    let result = unsafe { &mut *result };
    if !result.data.is_null() {
        // SAFETY: The pointer and length are the unchanged boxed slice returned by this ABI.
        drop(unsafe {
            Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                result.data,
                result.length,
            ))
        });
        result.data = std::ptr::null_mut();
        result.length = 0;
    }
}

/// # Safety
/// Release each returned result exactly once, after all snapshot users complete.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_release(result: LPMEnvResult) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !result.data.is_null() {
            // SAFETY: The pointer and length are the unchanged boxed slice returned by this ABI.
            drop(unsafe {
                Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                    result.data,
                    result.length,
                ))
            });
        }
        if !result.snapshot.is_null() {
            // SAFETY: This ownership was transferred by one successful resolve call.
            drop(unsafe { Box::from_raw(result.snapshot.cast::<Arc<SchemaSnapshot>>()) });
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    fn resolve(input: &[u8], folder: &str) -> LPMEnvResult {
        // SAFETY: Both slices remain live throughout the synchronous call.
        unsafe { lpm_env_resolve(input.as_ptr(), input.len(), folder.as_ptr(), folder.len()) }
    }
    fn output(result: &LPMEnvResult) -> serde_json::Value {
        // SAFETY: The result remains owned and unreleased for the complete read.
        serde_json::from_slice(unsafe { std::slice::from_raw_parts(result.data, result.length) })
            .unwrap()
    }
    #[test]
    fn flat_validation_rejects_semantics_and_preserves_exact_bounds() {
        for input in [
            br#"{"vars":{"A":{"pattern":"["}}}"#.as_slice(),
            br#"{"vars":{"A":{"default":"0","format":"port"}}}"#,
        ] {
            // SAFETY: The input slice remains live throughout this synchronous call.
            let result = unsafe { lpm_env_validate(input.as_ptr(), input.len()) };
            assert_eq!(result.status, 1);
            // SAFETY: This is the sole release of the returned result.
            unsafe {
                lpm_env_release(result);
            }
        }
        let input = br#"{"vars":{"A":{"format":"integer","min":"-9223372036854775808","max":"9223372036854775807"}}}"#;
        // SAFETY: The input slice remains live throughout this synchronous call.
        let result = unsafe { lpm_env_validate(input.as_ptr(), input.len()) };
        assert_eq!(result.status, 0);
        assert_eq!(output(&result)["vars"]["A"]["max"], "9223372036854775807");
        // SAFETY: This is the sole release of the returned result.
        unsafe {
            lpm_env_release(result);
        }
    }
    #[test]
    fn resolving_serializes_the_same_ordered_schema_and_can_release_only_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = br#"{"vars":{"Z":{"default":"quote\" and \u4e2d\u6587"},"A":{"client":true}},"clientPrefixes":["A_"],"groups":{"pair":{"mode":"allOrNone","vars":["A","Z"]}}}"#;
        // A public declaration must use its configured prefix.
        let input = std::str::from_utf8(input)
            .unwrap()
            .replace("\"A\"", "\"A_VALUE\"");
        let resolved = lpm_env_source::resolve_schema(
            dir.path(),
            input.as_bytes(),
            serde_json::from_str(&input).unwrap(),
        )
        .unwrap();
        let expected: serde_json::Value =
            serde_json::from_slice(&lpm_env_source::schema_json(&resolved.schema).unwrap())
                .unwrap();
        let mut result = resolve(input.as_bytes(), dir.path().to_str().unwrap());
        assert_eq!(result.status, 0);
        assert_eq!(output(&result)["effective"], expected);
        // SAFETY: The result is exclusively borrowed, verified while live, and released once.
        unsafe {
            lpm_env_clear_output(&mut result);
            assert!(result.data.is_null());
            assert_eq!(result.length, 0);
            assert_eq!(lpm_env_verify(result.snapshot), 0);
            let retained = &*result.snapshot.cast::<Arc<SchemaSnapshot>>();
            assert!(retained.origins.is_empty());
            assert!(retained.group_origins.is_empty());
            assert!(retained.declaring_origins.is_empty());
            lpm_env_clear_output(&mut result);
            lpm_env_release(result);
        }
    }
    #[test]
    fn overrides_preserve_declaring_origins_across_resolved_import_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        for (file, rule) in [("base.json", "{}"), ("other.json", r#"{"required":true}"#)] {
            std::fs::write(
                dir.path().join(file),
                format!(r#"{{"vars":{{"INHERITED":{rule}}}}}"#),
            )
            .unwrap();
        }
        let input = br#"{"extends":["base.json","other.json"],"vars":{"LOCAL":{}},"overrides":{"INHERITED":{}}}"#;
        let result = resolve(input, dir.path().to_str().unwrap());
        assert_eq!(result.status, 0);
        let actual = output(&result);
        // SAFETY: This is the sole release of the returned result.
        unsafe {
            lpm_env_release(result);
        }
        assert_eq!(actual["origins"]["INHERITED"]["source"], "lpm.json");
        assert_eq!(
            actual["declaringOrigins"]["INHERITED"]["source"],
            "base.json"
        );
        assert_eq!(
            actual["declaringOrigins"]["INHERITED"]["pointer"],
            "/vars/INHERITED"
        );
        assert!(actual["declaringOrigins"].get("LOCAL").is_none());
    }

    #[test]
    fn native_abi_rejects_invalid_semantics_and_never_echoes_literals() {
        let dir = tempfile::tempdir().unwrap();
        for input in [
            r#"{"vars":{"VALUE":{"pattern":"[PRIVATE"}}}"#,
            r#"{"vars":{"VALUE":{"pattern":"^live$","default":"PRIVATE"}}}"#,
            r#"{"vars":{"VALUE":{"format":"port","default":"0"}}}"#,
        ] {
            let result = resolve(input.as_bytes(), dir.path().to_str().unwrap());
            assert_eq!(result.status, 1);
            assert!(!output(&result).to_string().contains("PRIVATE"));
            // SAFETY: This is the sole release of the returned result.
            unsafe {
                lpm_env_release(result);
            }
        }
    }
    #[test]
    fn root_definition_errors_name_the_declaration_and_never_echo_literals() {
        let dir = tempfile::tempdir().unwrap();
        for (input, pointer, message) in [
            (
                r#"{"vars":{"PORT":{"rnage":"PRIVATE"}}}"#,
                "/envSchema/vars/PORT/rnage",
                "Invalid schema definition. Check the field name and value type at this location.",
            ),
            (
                r#"{"vars":{"PORT":{"required":"PRIVATE"}}}"#,
                "/envSchema/vars/PORT/required",
                "Invalid schema definition. Check the field name and value type at this location.",
            ),
            (
                r#"{"varz":{}}"#,
                "/envSchema/varz",
                "Invalid schema definition. Check the field name and value type at this location.",
            ),
        ] {
            let result = resolve(input.as_bytes(), dir.path().to_str().unwrap());
            assert_eq!(result.status, 1, "{input}");
            let diagnostic = output(&result);
            // SAFETY: This is the sole release of the returned result.
            unsafe {
                lpm_env_release(result);
            }
            assert_eq!(diagnostic["code"], "env.invalid_definition", "{input}");
            assert_eq!(diagnostic["source"], "lpm.json", "{input}");
            assert_eq!(diagnostic["pointer"], pointer, "{input}");
            assert_eq!(diagnostic["message"], message, "{input}");
            assert!(!diagnostic.to_string().contains("PRIVATE"), "{input}");
        }
    }

    #[test]
    fn diagnostic_pointers_escape_control_and_direction_characters() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("base.json"),
            "{\"vars\":{\"A\":{\"x\u{202e}\\n\":1}}}",
        )
        .unwrap();
        for (input, pointer) in [
            (
                "{\"vars\":{\"PORT\":{\"fmt\u{202e}\\u0007\":\"PRIVATE\"}}}",
                "/envSchema/vars/PORT/fmt\\u{202e}\\u{7}",
            ),
            (r#"{"extends":["base.json"]}"#, "/vars/A/x\\u{202e}\\u{a}"),
        ] {
            let result = resolve(input.as_bytes(), dir.path().to_str().unwrap());
            assert_eq!(result.status, 1, "{input}");
            let diagnostic = output(&result);
            // SAFETY: This is the sole release of the returned result.
            unsafe {
                lpm_env_release(result);
            }
            let rendered = diagnostic.to_string();
            assert!(
                !rendered.contains('\u{202e}') && !rendered.contains('\u{7}'),
                "{rendered}"
            );
            assert_eq!(diagnostic["pointer"], pointer, "{input}");
            assert!(diagnostic["key"].is_null(), "{input}");
        }
    }

    #[test]
    fn native_abi_bounds_input_before_dereference_and_checks_utf8() {
        // SAFETY: Invalid pointers are only used with rejected lengths, before dereference.
        let result =
            unsafe { lpm_env_resolve(std::ptr::dangling(), usize::MAX, std::ptr::dangling(), 1) };
        assert_eq!(result.status, 2);
        // SAFETY: This is the sole release of the returned result.
        unsafe {
            lpm_env_release(result);
        }
        let result = resolve(&[0xff], "/tmp");
        assert_eq!(result.status, 2);
        // SAFETY: This is the sole release of the returned result.
        unsafe {
            lpm_env_release(result);
        }
    }
    #[test]
    fn native_snapshot_detects_overridden_fragment_changes_and_folder_replacement() {
        let parent = tempfile::tempdir().unwrap();
        let folder = parent.path().join("project");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("base.json"), r#"{"vars":{"A":{}}}"#).unwrap();
        let result = resolve(
            br#"{"extends":["base.json"],"overrides":{"A":{}}}"#,
            folder.to_str().unwrap(),
        );
        assert_eq!(result.status, 0);
        assert!(output(&result)["effective"]["extends"].is_null());
        // SAFETY: The result remains live until the sole release below.
        unsafe {
            assert_eq!(lpm_env_verify(result.snapshot), 0);
            std::fs::write(
                folder.join("base.json"),
                r#"{"vars":{"A":{"required":true}}}"#,
            )
            .unwrap();
            assert_eq!(lpm_env_verify(result.snapshot), 1);
            std::fs::write(folder.join("base.json"), r#"{"vars":{"A":{}}}"#).unwrap();
            std::fs::rename(&folder, parent.path().join("old")).unwrap();
            std::fs::create_dir(&folder).unwrap();
            std::fs::write(folder.join("base.json"), r#"{"vars":{"A":{}}}"#).unwrap();
            assert_eq!(lpm_env_verify(result.snapshot), 1);
            lpm_env_release(result);
        }
    }
}
