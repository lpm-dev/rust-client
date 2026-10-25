//! Bounded C ABI for the bundled native schema engine, GitHub Actions secret
//! sealing, the LPM home and project files an app shares with the CLI,
//! passphrase-protected backup files, and the companion storage contract.
//! Only writing a file of secrets reads the process environment, for the
//! `git` it runs.

use lpm_env_source::{ReplacedGroups, ReplacedRules, SchemaSnapshot, SourceLocation};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

mod backup;
mod companion;
mod files;

/// The engine holds env values, decrypted backups and passphrases, so all
/// memory it frees is wiped first, including what its dependencies free.
#[global_allocator]
static ALLOCATOR: lpm_env_backup::WipingAllocator = lpm_env_backup::WipingAllocator;

const ABI_VERSION: u32 = 1;
const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
/// The most a resolution's `Provenance` adds on top of `OUTPUT_LIMIT`. It
/// grows with the overrides, groups, and prefixes, whose counts and names
/// the engine bounds, so the largest valid schema stays well under it.
const PROVENANCE_LIMIT: usize = 2 * 1024 * 1024;
/// The most environments one check evaluates.
const CHECK_ENVIRONMENT_LIMIT: usize = 256;
/// The most work one check does: each environment costs a unit per
/// declaration, enum member, enum UTF-8 byte, group, group member,
/// selected stored value (including fallback values), plus one.
const CHECK_WORK_LIMIT: usize = 1 << 18;
/// The longest value one seal encrypts, above GitHub's 48 KB secret limit.
const SEAL_INPUT_LIMIT: usize = 64 * 1024;

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
        format!("{{\"abiVersion\":{ABI_VERSION},\"code\":\"{code}\"}}").into_bytes(),
        None,
    )
}

/// Where overridden groups were declared, where client prefixes come from,
/// and what lpm.json's overrides replace. Each schema it names is listed
/// once in `sources`, and entries name one by its index, so its size follows
/// the overrides rather than how long their schemas' paths are.
struct Provenance<'a> {
    sources: Vec<&'a str>,
    indexes: HashMap<&'a str, usize>,
    snapshot: &'a SchemaSnapshot,
}

impl<'a> Provenance<'a> {
    fn new(snapshot: &'a SchemaSnapshot) -> Self {
        let mut provenance = Self {
            sources: Vec::new(),
            indexes: HashMap::new(),
            snapshot,
        };
        let origins = snapshot
            .group_declaring_origins
            .values()
            .chain(snapshot.client_prefix_origins.values())
            .chain(snapshot.replaced_vars.values().flat_map(|replaced| {
                std::iter::once(&replaced.origin).chain(replaced.secret.as_ref())
            }))
            .chain(
                snapshot
                    .replaced_groups
                    .values()
                    .map(|replaced| &replaced.origin),
            );
        for origin in origins {
            if let Entry::Vacant(entry) = provenance.indexes.entry(origin.source.as_str()) {
                entry.insert(provenance.sources.len());
                provenance.sources.push(&origin.source);
            }
        }
        provenance
    }

    fn index(&self, origin: &SourceLocation) -> usize {
        self.indexes[origin.source.as_str()]
    }
}

impl Serialize for Provenance<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Replaced {
            count: usize,
            origin: usize,
            #[serde(skip_serializing_if = "Option::is_none")]
            client: Option<bool>,
            #[serde(skip_serializing_if = "Option::is_none")]
            secret: Option<usize>,
        }
        let snapshot = self.snapshot;
        let mut fields = serializer.serialize_struct("Provenance", 5)?;
        fields.serialize_field("sources", &self.sources)?;
        fields.serialize_field(
            "groupDeclaringOrigins",
            &Entries(
                &snapshot.group_declaring_origins,
                |origin: &Arc<SourceLocation>| self.index(origin),
            ),
        )?;
        fields.serialize_field(
            "clientPrefixOrigins",
            &Entries(
                &snapshot.client_prefix_origins,
                |origin: &Arc<SourceLocation>| self.index(origin),
            ),
        )?;
        fields.serialize_field(
            "replacedVars",
            &Entries(&snapshot.replaced_vars, |replaced: &ReplacedRules| {
                Replaced {
                    count: replaced.count,
                    origin: self.index(&replaced.origin),
                    client: Some(replaced.client),
                    secret: replaced.secret.as_deref().map(|origin| self.index(origin)),
                }
            }),
        )?;
        fields.serialize_field(
            "replacedGroups",
            &Entries(&snapshot.replaced_groups, |replaced: &ReplacedGroups| {
                Replaced {
                    count: replaced.count,
                    origin: self.index(&replaced.origin),
                    client: None,
                    secret: None,
                }
            }),
        )?;
        fields.end()
    }
}

/// A map serialized with each value converted on the way out.
struct Entries<'a, V, F>(&'a BTreeMap<String, V>, F);

impl<V, T: Serialize, F: Fn(&V) -> T> Serialize for Entries<'_, V, F> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(key, value)| (key, (self.1)(value))))
    }
}

/// A flat schema that doesn't decode: a field this version doesn't know, as
/// a located diagnostic, or else an invalid definition.
fn flat_definition_failure(bytes: &[u8]) -> LPMEnvResult {
    match lpm_env::first_unknown_schema_field(bytes) {
        Some(unknown) => diagnostic(&lpm_env_source::unknown_field_error("", &unknown)),
        None => failure(1, "env.invalid_definition"),
    }
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
            Err(_) => return flat_definition_failure(bytes),
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
                    origins: &'a BTreeMap<String, SourceLocation>,
                    group_origins: &'a BTreeMap<String, SourceLocation>,
                    declaring_origins: &'a BTreeMap<String, SourceLocation>,
                    #[serde(flatten)]
                    provenance: &'a Provenance<'a>,
                    dependencies: &'a [lpm_env_source::SchemaDependency],
                    fingerprint: String,
                }
                let provenance = Provenance::new(&resolved.snapshot);
                // The provenance has an allowance of its own, so a schema whose
                // output fit `OUTPUT_LIMIT` without it still resolves with it.
                let Ok(provenance_bytes) = lpm_env_source::json_size(&provenance, PROVENANCE_LIMIT)
                else {
                    return failure(4, "env.output_budget");
                };
                let output = Output {
                    abi_version: ABI_VERSION,
                    effective: lpm_env_source::ordered_schema(&resolved.schema),
                    origins: &resolved.origins,
                    group_origins: &resolved.group_origins,
                    declaring_origins: &resolved.declaring_origins,
                    provenance: &provenance,
                    dependencies: &resolved.dependencies,
                    fingerprint: hex::encode(resolved.fingerprint),
                };
                match lpm_env_source::bounded_json(&output, OUTPUT_LIMIT + provenance_bytes) {
                    Ok(bytes) => {
                        let Some(snapshot) = Arc::get_mut(&mut resolved.snapshot) else {
                            return failure(3, "env.engine_internal");
                        };
                        snapshot.origins.clear();
                        snapshot.group_origins.clear();
                        snapshot.declaring_origins.clear();
                        snapshot.group_declaring_origins.clear();
                        snapshot.client_prefix_origins.clear();
                        snapshot.replaced_vars.clear();
                        snapshot.replaced_groups.clear();
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckInput {
    environments: BTreeMap<String, HashMap<String, String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckedEnvironment {
    reads_default_environment: bool,
    problems: Vec<Problem>,
    defaults: BTreeMap<String, String>,
    ignored: Vec<String>,
}

/// A rule violation without the offending value: a stable code and the
/// declaration details that explain it.
#[derive(Serialize)]
struct Problem {
    key: String,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<lpm_env::VarFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    constraint: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<lpm_env::VarGroupMode>,
}

impl From<lpm_env::ValidationError> for Problem {
    fn from(error: lpm_env::ValidationError) -> Self {
        let code = lpm_env_source::declaration_code(&error.kind);
        let mut problem = Self {
            key: error.key,
            code,
            format: None,
            constraint: None,
            group: None,
            mode: None,
        };
        match error.kind {
            lpm_env::ValidationErrorKind::InvalidFormat { expected, .. } => {
                problem.format = Some(expected);
            }
            lpm_env::ValidationErrorKind::ConstraintViolation { constraint } => {
                problem.constraint = Some(constraint);
            }
            lpm_env::ValidationErrorKind::GroupViolation { group, mode } => {
                problem.group = Some(group);
                problem.mode = Some(mode);
            }
            _ => {}
        }
        problem
    }
}

/// Each environment's check, evaluated while it is written, so output stops,
/// and evaluation with it, at the output limit.
struct Checks<'a, 's> {
    validator: &'a lpm_env::EnvValidator<'s>,
    environments: &'a BTreeMap<String, HashMap<String, String>>,
    /// Set when an environment's names differ only in case on a host that ignores case.
    conflict: &'a std::cell::Cell<bool>,
}

impl Serialize for Checks<'_, '_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeMap};
        let mut map = serializer.serialize_map(Some(self.environments.len()))?;
        for name in self.environments.keys() {
            let Ok(check) = lpm_env::check_stored_values(self.validator, name, self.environments)
            else {
                self.conflict.set(true);
                return Err(S::Error::custom("ambiguous environment variable casing"));
            };
            map.serialize_entry(
                name,
                &CheckedEnvironment {
                    reads_default_environment: check.reads_default_environment,
                    problems: check.errors.into_iter().map(Problem::from).collect(),
                    defaults: check.defaults,
                    ignored: check.ignored,
                },
            )?;
        }
        map.end()
    }
}

/// Check the values stored for each environment against a flat schema, such
/// as the `effective` schema `lpm_env_resolve` returns, the way the runner
/// evaluates them at runtime, without project files or the process
/// environment. Problems never contain values.
/// # Safety
/// Both pointers must reference readable bytes for their lengths during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_check(
    schema: *const u8,
    schema_length: usize,
    input: *const u8,
    input_length: usize,
) -> LPMEnvResult {
    if schema.is_null()
        || input.is_null()
        || schema_length == 0
        || input_length == 0
        || schema_length > lpm_env_source::MAX_SCHEMA_BYTES
        || input_length > lpm_env_source::MAX_SCHEMA_BYTES
    {
        return failure(2, "env.invalid_input");
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller supplies live readable ranges; their lengths were bounded above.
        let (schema, input) = unsafe {
            (
                std::slice::from_raw_parts(schema, schema_length),
                std::slice::from_raw_parts(input, input_length),
            )
        };
        if std::str::from_utf8(schema).is_err() || std::str::from_utf8(input).is_err() {
            return failure(2, "env.invalid_utf8");
        }
        let Ok(schema) = serde_json::from_slice::<lpm_env::EnvSchema>(schema) else {
            return flat_definition_failure(schema);
        };
        let Ok(input) = serde_json::from_slice::<CheckInput>(input) else {
            return failure(2, "env.invalid_input");
        };
        if input.environments.iter().any(|(name, values)| {
            lpm_env::resolver::validate_env_name(name).is_err()
                || !values.keys().all(|key| lpm_env::is_valid_env_var_name(key))
        }) {
            return failure(2, "env.invalid_input");
        }
        if input.environments.len() > CHECK_ENVIRONMENT_LIMIT {
            return failure(4, "env.check_budget");
        }
        let rule_work = schema.vars.values().fold(schema.vars.len(), |work, rule| {
            rule.enum_values.as_ref().map_or(work, |allowed| {
                allowed.iter().fold(work, |work, value| {
                    work.saturating_add(1).saturating_add(value.len())
                })
            })
        });
        let per_environment = schema.groups.values().fold(
            rule_work
                .saturating_add(schema.groups.len())
                .saturating_add(1),
            |work, group| work.saturating_add(group.vars.len()),
        );
        let default_values = input
            .environments
            .get(lpm_env::DEFAULT_ENVIRONMENT)
            .map_or(0, HashMap::len);
        let work = input
            .environments
            .iter()
            .fold(0usize, |work, (name, values)| {
                let selected_values =
                    if lpm_env::reads_default_environment(name, !values.is_empty()) {
                        default_values
                    } else {
                        values.len()
                    };
                work.saturating_add(per_environment)
                    .saturating_add(selected_values)
            });
        if work > CHECK_WORK_LIMIT {
            return failure(4, "env.check_budget");
        }
        let validator = lpm_env::EnvValidator::new(&schema);
        if let Some(error) = validator.schema_errors().first() {
            return failure(1, lpm_env_source::declaration_code(&error.kind));
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Output<'a, 's> {
            abi_version: u32,
            environments: Checks<'a, 's>,
        }
        let conflict = std::cell::Cell::new(false);
        let output = Output {
            abi_version: ABI_VERSION,
            environments: Checks {
                validator: &validator,
                environments: &input.environments,
                conflict: &conflict,
            },
        };
        match lpm_env_source::bounded_json(&output, OUTPUT_LIMIT) {
            Ok(bytes) => result(0, bytes, None),
            Err(_) if conflict.get() => failure(1, "env.ambiguous_casing"),
            Err(_) => failure(4, "env.output_budget"),
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// Encrypt `plaintext` to a Curve25519 public key as a libsodium sealed box
/// (`crypto_box_seal`), the form GitHub requires for an Actions secret. The
/// output is the ephemeral public key followed by the box, 48 bytes longer
/// than the plaintext. Only the recipient's secret key opens it. A low-order
/// key, whose shared secret is all zeros, is refused as invalid input, as
/// libsodium refuses to open a box sealed to one.
/// # Safety
/// The key pointer must reference 32 readable bytes. The plaintext pointer
/// must reference readable bytes for its length during the call, and may be
/// null only when the length is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_seal_box(
    public_key: *const u8,
    public_key_length: usize,
    plaintext: *const u8,
    plaintext_length: usize,
) -> LPMEnvResult {
    if public_key.is_null()
        || public_key_length != crypto_box::KEY_SIZE
        || (plaintext.is_null() && plaintext_length != 0)
        || plaintext_length > SEAL_INPUT_LIMIT
    {
        return failure(2, "env.invalid_input");
    }
    catch_unwind(AssertUnwindSafe(|| {
        let mut key = [0u8; crypto_box::KEY_SIZE];
        // SAFETY: The caller supplies a live readable range of exactly KEY_SIZE bytes, checked above.
        key.copy_from_slice(unsafe { std::slice::from_raw_parts(public_key, public_key_length) });
        let plaintext = if plaintext_length == 0 {
            &[][..]
        } else {
            // SAFETY: The caller supplies a live readable range; its length was bounded above.
            unsafe { std::slice::from_raw_parts(plaintext, plaintext_length) }
        };
        if !is_contributory(&key) {
            return failure(2, "env.invalid_input");
        }
        match crypto_box::PublicKey::from(key).seal(&mut crypto_box::aead::OsRng, plaintext) {
            Ok(sealed) => result(0, sealed, None),
            Err(_) => failure(3, "env.seal_failed"),
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// Whether X25519 with `key` gives a shared secret that depends on the other
/// side's key. A small-order point gives all zeros for every clamped secret,
/// so a box sealed to it would be readable by anyone, and libsodium refuses
/// to open it.
fn is_contributory(key: &[u8; crypto_box::KEY_SIZE]) -> bool {
    x25519_dalek::EphemeralSecret::random_from_rng(crypto_box::aead::OsRng)
        .diffie_hellman(&x25519_dalek::PublicKey::from(*key))
        .was_contributory()
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
        unsafe { wipe_output(result.data, result.length) };
        result.data = std::ptr::null_mut();
        result.length = 0;
    }
}

/// Frees an output buffer after zeroing it, since some outputs hold secrets.
///
/// # Safety
/// `data` and `length` must be an unchanged boxed slice this ABI returned.
unsafe fn wipe_output(data: *mut u8, length: usize) {
    // SAFETY: Guaranteed by the caller.
    let mut output = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(data, length)) };
    zeroize::Zeroize::zeroize(&mut *output);
}

/// # Safety
/// Release each returned result exactly once, after all snapshot users complete.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_release(result: LPMEnvResult) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !result.data.is_null() {
            // SAFETY: The pointer and length are the unchanged boxed slice returned by this ABI.
            unsafe { wipe_output(result.data, result.length) };
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
            assert!(retained.group_declaring_origins.is_empty());
            assert!(retained.client_prefix_origins.is_empty());
            assert!(retained.replaced_vars.is_empty());
            assert!(retained.replaced_groups.is_empty());
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
    fn overrides_report_the_rules_they_replace_and_where_groups_and_prefixes_come_from() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("base.json"),
            r#"{"vars":{"SHARED_TOKEN":{"secret":true},"SHARED_REGION":{"client":true},"MIDDLE":{}},"groups":{"pair":{"mode":"allOrNone","vars":["SHARED_TOKEN","MIDDLE"]},"solo":{"mode":"atLeastOne","vars":["MIDDLE"]}},"clientPrefixes":["SHARED_","BASE_"]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("middle.json"),
            r#"{"extends":["base.json"],"overrides":{"MIDDLE":{"required":true}}}"#,
        )
        .unwrap();
        let input = br#"{"extends":["middle.json"],"clientPrefixes":["OWN_","SHARED_"],"vars":{"LOCAL":{}},"overrides":{"SHARED_TOKEN":{"client":true}},"groupOverrides":{"pair":{"mode":"exactlyOne","vars":["SHARED_TOKEN","MIDDLE"]}}}"#;
        let result = resolve(input, dir.path().to_str().unwrap());
        assert_eq!(result.status, 0, "{}", output(&result));
        let actual = output(&result);
        // SAFETY: This is the sole release of the returned result.
        unsafe {
            lpm_env_release(result);
        }
        assert_eq!(
            actual["sources"],
            serde_json::json!(["base.json", "lpm.json"]),
            "Each schema the provenance names is listed once"
        );
        assert_eq!(
            actual["replacedVars"],
            serde_json::json!({"SHARED_TOKEN": {"count": 1, "origin": 0, "client": false, "secret": 0}}),
            "Only lpm.json's own overrides report what they replace"
        );
        assert_eq!(
            actual["replacedGroups"],
            serde_json::json!({"pair": {"count": 1, "origin": 0}})
        );
        assert_eq!(actual["effective"]["vars"]["SHARED_TOKEN"]["client"], true);
        assert_eq!(actual["groupOrigins"]["pair"]["source"], "lpm.json");
        assert_eq!(
            actual["groupDeclaringOrigins"],
            serde_json::json!({"pair": 0})
        );
        assert_eq!(
            actual["clientPrefixOrigins"],
            serde_json::json!({"BASE_": 0, "OWN_": 1, "SHARED_": 0}),
            "A prefix lpm.json shares with an import names the import"
        );
        assert_eq!(
            actual["effective"]["clientPrefixes"],
            serde_json::json!(["BASE_", "OWN_", "SHARED_"])
        );
    }

    #[test]
    fn replaced_rules_are_summarized_without_their_values_and_stay_small() {
        let dir = tempfile::tempdir().unwrap();
        let description = "d".repeat(1024 * 1024);
        std::fs::write(
            dir.path().join("d.json"),
            format!(
                r#"{{"vars":{{"KEY":{{"secret":true,"default":"PRIVATE_LITERAL","enum":["PRIVATE_LITERAL"],"description":"{description}"}}}}}}"#
            ),
        )
        .unwrap();
        let paths: Vec<String> = (0..8).map(|index| format!("p{index}.json")).collect();
        for path in &paths {
            std::fs::write(dir.path().join(path), r#"{"extends":["d.json"]}"#).unwrap();
        }
        let input = serde_json::json!({"extends": paths, "overrides": {"KEY": {}}}).to_string();
        let result = resolve(input.as_bytes(), dir.path().to_str().unwrap());
        assert_eq!(result.status, 0, "{}", output(&result));
        let actual = output(&result);
        // SAFETY: This is the sole release of the returned result.
        unsafe {
            lpm_env_release(result);
        }
        let text = actual.to_string();
        assert!(
            !text.contains("PRIVATE_LITERAL"),
            "An overridden rule's values never leave the engine"
        );
        assert!(
            text.len() < 64 * 1024,
            "The summary doesn't grow with the rule or the paths: {} bytes",
            text.len()
        );
        assert_eq!(actual["replacedVars"]["KEY"]["count"], 1);
        assert_eq!(actual["sources"], serde_json::json!(["d.json"]));
        assert_eq!(actual["replacedVars"]["KEY"]["secret"], 0);
    }

    /// The resolve output's provenance fields, and the rest of it, as the engine writes them.
    fn split_provenance(output: &serde_json::Value) -> (Vec<u8>, Vec<u8>) {
        let mut rest = output.as_object().unwrap().clone();
        let mut provenance = serde_json::Map::new();
        for field in [
            "sources",
            "groupDeclaringOrigins",
            "clientPrefixOrigins",
            "replacedVars",
            "replacedGroups",
        ] {
            provenance.insert(field.into(), rest.shift_remove(field).unwrap());
        }
        (
            serde_json::to_vec(&provenance).unwrap(),
            serde_json::to_vec(&rest).unwrap(),
        )
    }

    fn long_name(prefix: char, index: usize) -> String {
        format!("{prefix}{index:0>255}")
    }

    #[test]
    fn a_schema_whose_output_fit_the_budget_before_provenance_still_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let folder = "f".repeat(250);
        std::fs::create_dir(dir.path().join(&folder)).unwrap();
        let import = format!("{folder}/{}.json", "i".repeat(244));
        let names: Vec<String> = (0..4096).map(|index| long_name('K', index)).collect();
        let rules = |rule: &str| {
            names
                .iter()
                .map(|name| format!(r#""{name}":{rule}"#))
                .collect::<Vec<_>>()
                .join(",")
        };
        std::fs::write(
            dir.path().join(&import),
            format!(r#"{{"vars":{{{}}}}}"#, rules(r#"{"secret":true}"#)),
        )
        .unwrap();
        let input = format!(
            r#"{{"extends":["{import}"],"overrides":{{{}}}}}"#,
            rules("{}")
        );
        assert!(input.len() <= lpm_env_source::MAX_SCHEMA_BYTES);
        let result = resolve(input.as_bytes(), dir.path().to_str().unwrap());
        assert_eq!(result.status, 0, "{}", output(&result));
        let length = result.length;
        let actual = output(&result);
        // SAFETY: This is the sole release of the returned result.
        unsafe {
            lpm_env_release(result);
        }
        let (provenance, rest) = split_provenance(&actual);
        assert!(
            rest.len() <= OUTPUT_LIMIT && length > OUTPUT_LIMIT,
            "The output without provenance fits the budget, and only its allowance fits the rest: {} + {} bytes",
            rest.len(),
            provenance.len()
        );
        assert_eq!(actual["sources"], serde_json::json!([import]));
        assert_eq!(actual["replacedVars"].as_object().unwrap().len(), 4096);
        assert_eq!(
            actual["replacedVars"][&names[0]],
            serde_json::json!({"count": 1, "origin": 0, "client": false, "secret": 0})
        );
    }

    #[test]
    fn provenance_of_the_largest_overrides_stays_well_within_its_allowance() {
        let dir = tempfile::tempdir().unwrap();
        let import = format!("{}.json", "i".repeat(180));
        let names: Vec<String> = (0..4096).map(|index| long_name('K', index)).collect();
        let groups: Vec<String> = (0..128).map(|index| long_name('G', index)).collect();
        let prefixes: Vec<String> = (0..32).map(|index| format!("P{index:0>254}_")).collect();
        let group = |index: usize| format!(r#"{{"mode":"allOrNone","vars":["{}"]}}"#, names[index]);
        let vars = names
            .iter()
            .map(|name| format!(r#""{name}":{{"secret":true}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let declared_groups = (0..128)
            .map(|index| format!(r#""{}":{}"#, groups[index], group(index)))
            .collect::<Vec<_>>()
            .join(",");
        std::fs::write(
            dir.path().join(&import),
            serde_json::to_string(&serde_json::json!({
                "vars": serde_json::from_str::<serde_json::Value>(&format!("{{{vars}}}")).unwrap(),
                "groups": serde_json::from_str::<serde_json::Value>(&format!("{{{declared_groups}}}")).unwrap(),
                "clientPrefixes": prefixes,
            }))
            .unwrap(),
        )
        .unwrap();
        let overrides = names
            .iter()
            .map(|name| format!(r#""{name}":{{}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let group_overrides = (0..128)
            .map(|index| format!(r#""{}":{}"#, groups[index], group(4095 - index)))
            .collect::<Vec<_>>()
            .join(",");
        let input = format!(
            r#"{{"extends":["{import}"],"overrides":{{{overrides}}},"groupOverrides":{{{group_overrides}}}}}"#
        );
        let result = resolve(input.as_bytes(), dir.path().to_str().unwrap());
        assert_eq!(result.status, 0, "{}", output(&result));
        let actual = output(&result);
        // SAFETY: This is the sole release of the returned result.
        unsafe {
            lpm_env_release(result);
        }
        assert_eq!(actual["replacedVars"].as_object().unwrap().len(), 4096);
        assert_eq!(actual["replacedGroups"].as_object().unwrap().len(), 128);
        assert_eq!(
            actual["groupDeclaringOrigins"].as_object().unwrap().len(),
            128
        );
        assert_eq!(actual["clientPrefixOrigins"].as_object().unwrap().len(), 32);
        let (provenance, _) = split_provenance(&actual);
        // What this fixture doesn't reach: a second digit in each override's
        // count and indexes, and every schema listed at full length, escaped.
        let unreached = 4096 * 3 + (lpm_env_source::MAX_NODES + 1) * (512 * 6 + 3);
        assert!(
            provenance.len() + unreached < PROVENANCE_LIMIT,
            "Every override, group, and prefix the engine accepts, named at full length: {} bytes",
            provenance.len()
        );
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
    fn root_definition_fields_named_like_the_schema_keep_the_document_prefix() {
        let dir = tempfile::tempdir().unwrap();
        for field in ["envSchemaTypo", "envSchema"] {
            let input = format!(r#"{{"{field}":{{}}}}"#);
            let result = resolve(input.as_bytes(), dir.path().to_str().unwrap());
            let diagnostic = output(&result);
            // SAFETY: This is the sole release of the returned result.
            unsafe { lpm_env_release(result) };
            assert_eq!(diagnostic["pointer"], format!("/envSchema/{field}"));
        }
    }

    #[test]
    fn root_definition_errors_name_the_declaration_and_never_echo_literals() {
        let dir = tempfile::tempdir().unwrap();
        let unknown = "This field isn't one this LPM CLI knows. Check its spelling, or update the LPM CLI if a newer version wrote it.";
        for (input, code, pointer, message) in [
            (
                r#"{"vars":{"PORT":{"rnage":"PRIVATE"}}}"#,
                "env.unknown_field",
                "/envSchema/vars/PORT/rnage",
                unknown,
            ),
            (
                r#"{"vars":{"PORT":{"required":"PRIVATE"}}}"#,
                "env.invalid_definition",
                "/envSchema/vars/PORT/required",
                "Invalid schema definition. Check the field name and value type at this location.",
            ),
            (
                r#"{"varz":{}}"#,
                "env.unknown_field",
                "/envSchema/varz",
                unknown,
            ),
        ] {
            let result = resolve(input.as_bytes(), dir.path().to_str().unwrap());
            assert_eq!(result.status, 1, "{input}");
            let diagnostic = output(&result);
            // SAFETY: This is the sole release of the returned result.
            unsafe {
                lpm_env_release(result);
            }
            assert_eq!(diagnostic["code"], code, "{input}");
            assert_eq!(diagnostic["source"], "lpm.json", "{input}");
            assert_eq!(diagnostic["pointer"], pointer, "{input}");
            assert_eq!(diagnostic["message"], message, "{input}");
            assert!(!diagnostic.to_string().contains("PRIVATE"), "{input}");
        }
    }

    #[test]
    fn flat_unknown_fields_are_located_and_their_names_escaped() {
        let schema = br#"{"vars":{"A":{"rotate\u001b[31mEvery":"PRIVATE"}}}"#;
        // SAFETY: The slice stays live for this synchronous call.
        let result = unsafe { lpm_env_validate(schema.as_ptr(), schema.len()) };
        assert_eq!(result.status, 1);
        let diagnostic = output(&result);
        // SAFETY: This is the sole release of the returned result.
        unsafe { lpm_env_release(result) };
        assert_eq!(diagnostic["code"], "env.unknown_field");
        assert_eq!(diagnostic["pointer"], "/vars/A/rotate\\u{1b}[31mEvery");
        assert_eq!(diagnostic["field"], "rotate\\u{1b}[31mEvery");
        assert!(!diagnostic.to_string().contains("PRIVATE"));
    }

    fn check(schema: &[u8], input: &[u8]) -> (u32, serde_json::Value) {
        // SAFETY: Both slices remain live throughout this synchronous call.
        let result =
            unsafe { lpm_env_check(schema.as_ptr(), schema.len(), input.as_ptr(), input.len()) };
        let status = result.status;
        let output = output(&result);
        // SAFETY: This is the sole release of the returned result.
        unsafe {
            lpm_env_release(result);
        }
        (status, output)
    }

    fn effective(schema: &[u8]) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let resolved = resolve(schema, dir.path().to_str().unwrap());
        assert_eq!(resolved.status, 0);
        let effective = serde_json::to_vec(&output(&resolved)["effective"]).unwrap();
        // SAFETY: This is the sole release of the resolve result.
        unsafe {
            lpm_env_release(resolved);
        }
        effective
    }

    #[test]
    fn checking_stored_values_against_the_effective_schema_reports_rules_without_values() {
        let schema = effective(
            br#"{"vars":{
            "API_TOKEN":{"secret":true,"requiredIn":[{"environment":["production"]}]},
            "PORT":{"format":"port","default":"3000"},
            "WORKERS":{"format":"integer","min":"1"},
            "PASSWORD":{"secret":true},
            "OAUTH_TOKEN":{"secret":true}
        },"groups":{"credentials":{"mode":"exactlyOne","vars":["PASSWORD","OAUTH_TOKEN"]}}}"#,
        );
        let input = br#"{"environments":{
            "default":{"PORT":"PRIVATE-PORT","WORKERS":"0","PASSWORD":"PRIVATE-1","OAUTH_TOKEN":"PRIVATE-2"},
            "production":{"PORT":"8080","PASSWORD":"PRIVATE-3","NODE_OPTIONS":"PRIVATE-4"},
            "staging":{}
        }}"#;
        let (status, output) = check(&schema, input);
        assert_eq!(status, 0);
        assert!(!output.to_string().contains("PRIVATE"), "{output}");
        let credentials = |key: &str| serde_json::json!({"key":key,"code":"env.group","group":"credentials","mode":"exactlyOne"});
        let default_problems = serde_json::json!([
            credentials("OAUTH_TOKEN"),
            credentials("PASSWORD"),
            {"key":"PORT","code":"env.invalid_format","format":"port"},
            {"key":"WORKERS","code":"env.constraint","constraint":"min"},
        ]);
        assert_eq!(
            output,
            serde_json::json!({
                "abiVersion": 1,
                "environments": {
                    "default": {
                        "readsDefaultEnvironment": false,
                        "problems": default_problems,
                        "defaults": {},
                        "ignored": [],
                    },
                    "production": {
                        "readsDefaultEnvironment": false,
                        "problems": [{"key":"API_TOKEN","code":"env.required"}],
                        "defaults": {},
                        "ignored": ["NODE_OPTIONS"],
                    },
                    "staging": {
                        "readsDefaultEnvironment": true,
                        "problems": default_problems,
                        "defaults": {},
                        "ignored": [],
                    },
                }
            })
        );

        let (status, output) = check(
            &schema,
            br#"{"environments":{"default":{"WORKERS":"2","PASSWORD":"x"}}}"#,
        );
        assert_eq!(status, 0);
        assert_eq!(
            output["environments"]["default"],
            serde_json::json!({
                "readsDefaultEnvironment": false,
                "problems": [],
                "defaults": {"PORT":"3000"},
                "ignored": [],
            })
        );
    }

    #[test]
    fn checking_counts_enum_members_for_every_environment() {
        let allowed: Vec<_> = (0..8_192).map(|index| index.to_string()).collect();
        let schema =
            serde_json::to_vec(&serde_json::json!({"vars":{"X":{"enum":allowed}}})).unwrap();
        let environments: BTreeMap<_, _> = (0..64)
            .map(|index| (format!("env{index}"), serde_json::json!({"X":"invalid"})))
            .collect();
        let input = serde_json::to_vec(&serde_json::json!({"environments":environments})).unwrap();
        let (status, output) = check(&schema, &input);
        assert_eq!(status, 4);
        assert_eq!(output["code"], "env.check_budget");
    }

    #[test]
    fn checking_counts_enum_bytes_before_retaining_mismatch_details() {
        let allowed: Vec<_> = (0..8)
            .map(|index| format!("{index}{}", "x".repeat(4_096)))
            .collect();
        let schema =
            serde_json::to_vec(&serde_json::json!({"vars":{"X":{"enum":allowed}}})).unwrap();
        let environments: BTreeMap<_, _> = (0..16)
            .map(|index| (format!("env{index}"), serde_json::json!({"X":"invalid"})))
            .collect();
        let input = serde_json::to_vec(&serde_json::json!({"environments":environments})).unwrap();
        let (status, output) = check(&schema, &input);
        assert_eq!(status, 4);
        assert_eq!(output["code"], "env.check_budget");
    }

    #[test]
    fn checking_refuses_work_beyond_its_budget_before_evaluating_values() {
        let small = effective(br#"{"vars":{"A":{"default":"x"}}}"#);
        let many = format!(
            r#"{{"environments":{{{}}}}}"#,
            (0..300)
                .map(|index| format!(r#""env{index}":{{}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let (status, output) = check(&small, many.as_bytes());
        assert_eq!(status, 4);
        assert_eq!(output["code"], "env.check_budget");

        let vars = (0..4096)
            .map(|index| format!(r#""V{index}":{{"default":"x"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let wide = effective(format!(r#"{{"vars":{{{vars}}}}}"#).as_bytes());
        let environments = format!(
            r#"{{"environments":{{{}}}}}"#,
            (0..100)
                .map(|index| format!(r#""env{index}":{{}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let (status, output) = check(&wide, environments.as_bytes());
        assert_eq!(status, 4);
        assert_eq!(output["code"], "env.check_budget");

        let (status, _) = check(&wide, br#"{"environments":{"default":{},"production":{}}}"#);
        assert_eq!(status, 0, "a large schema within the budget is checked");
    }

    #[test]
    fn checking_counts_default_values_for_every_environment_that_reads_them() {
        let schema = effective(br#"{"vars":{"A":{}}}"#);
        let default_values = (0..1024)
            .map(|index| format!(r#""V{index}":"x""#))
            .collect::<Vec<_>>()
            .join(",");
        let empty_environments = (0..255)
            .map(|index| format!(r#""env{index}":{{}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let input = format!(
            r#"{{"environments":{{"default":{{{default_values}}},{empty_environments}}}}}"#
        );

        let (status, output) = check(&schema, input.as_bytes());

        assert_eq!(status, 4);
        assert_eq!(output["code"], "env.check_budget");
    }

    #[test]
    fn checking_counts_each_group_member_for_every_environment() {
        let vars = (0..32)
            .map(|index| format!(r#""V{index}":{{}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let members = (0..32)
            .map(|index| format!(r#""V{index}""#))
            .collect::<Vec<_>>()
            .join(",");
        let groups = (0..128)
            .map(|index| format!(r#""G{index}":{{"mode":"allOrNone","vars":[{members}]}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let schema =
            effective(format!(r#"{{"vars":{{{vars}}},"groups":{{{groups}}}}}"#).as_bytes());
        let environments = (0..64)
            .map(|index| format!(r#""env{index}":{{}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let input = format!(r#"{{"environments":{{{environments}}}}}"#);

        let (status, output) = check(&schema, input.as_bytes());

        assert_eq!(status, 4);
        assert_eq!(output["code"], "env.check_budget");
    }

    #[test]
    fn checking_stops_at_the_output_limit() {
        let long = "x".repeat(4096);
        let vars = (0..400)
            .map(|index| format!(r#""V{index}":{{"default":"{long}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let schema = effective(format!(r#"{{"vars":{{{vars}}}}}"#).as_bytes());
        let (status, output) = check(
            &schema,
            br#"{"environments":{"a":{},"b":{},"c":{},"d":{},"e":{},"f":{}}}"#,
        );
        assert_eq!(status, 4);
        assert_eq!(output["code"], "env.output_budget");
    }

    #[test]
    fn checking_rejects_invalid_schemas_and_input_before_evaluating_values() {
        let schema = effective(br#"{"vars":{"A":{}}}"#);
        for input in [
            b"{".as_slice(),
            br#"{"environments":{"default":{"A":"x"}},"stage":"build"}"#,
            br#"{"environments":{"../escape":{"A":"x"}}}"#,
            br#"{"environments":{"default":{"not-a-name":"x"}}}"#,
            br#"{"environments":{"default":{"A":1}}}"#,
            &[0xff],
        ] {
            let (status, output) = check(&schema, input);
            assert_eq!(status, 2, "{}", String::from_utf8_lossy(input));
            assert_eq!(output["abiVersion"], 1);
            assert!(output.get("environments").is_none());
        }
        let values = br#"{"environments":{"default":{"A":"PRIVATE"}}}"#;
        for (schema, code) in [
            (
                br#"{"vars":{"A":{"rnage":"1"}}}"#.as_slice(),
                "env.unknown_field",
            ),
            (br#"{"vars":{"A":{"pattern":"["}}}"#, "env.invalid_pattern"),
            (
                br#"{"extends":["base.json"],"vars":{}}"#,
                "env.unknown_field",
            ),
            (
                br#"{"vars":{"A":{"required":"yes"}}}"#,
                "env.invalid_definition",
            ),
        ] {
            let (status, output) = check(schema, values);
            assert_eq!(status, 1, "{}", String::from_utf8_lossy(schema));
            assert_eq!(output["code"], code);
            assert!(!output.to_string().contains("PRIVATE"));
        }
        // SAFETY: Null and oversized ranges are rejected before any dereference.
        let rejected = unsafe {
            [
                lpm_env_check(std::ptr::null(), 2, values.as_ptr(), values.len()),
                lpm_env_check(
                    schema.as_ptr(),
                    schema.len(),
                    std::ptr::dangling(),
                    usize::MAX,
                ),
            ]
        };
        for result in rejected {
            assert_eq!(result.status, 2);
            // SAFETY: This is the sole release of each returned result.
            unsafe {
                lpm_env_release(result);
            }
        }
    }

    #[test]
    fn diagnostic_pointers_escape_line_and_direction_characters() {
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
            (
                "{\"vars\":{\"PORT\":{\"line\u{2028}paragraph\u{2029}\":\"PRIVATE\"}}}",
                "/envSchema/vars/PORT/line\\u{2028}paragraph\\u{2029}",
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
                ['\u{7}', '\u{2028}', '\u{2029}', '\u{202e}']
                    .into_iter()
                    .all(|character| !rendered.contains(character)),
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

    fn seal(public_key: &[u8], plaintext: &[u8]) -> LPMEnvResult {
        let plaintext_pointer = if plaintext.is_empty() {
            std::ptr::null()
        } else {
            plaintext.as_ptr()
        };
        // SAFETY: Both slices remain live throughout the synchronous call.
        unsafe {
            lpm_env_seal_box(
                public_key.as_ptr(),
                public_key.len(),
                plaintext_pointer,
                plaintext.len(),
            )
        }
    }

    fn sealed_bytes(result: LPMEnvResult) -> Vec<u8> {
        assert_eq!(result.status, 0);
        // SAFETY: The result remains owned and unreleased for the complete read.
        let bytes = unsafe { std::slice::from_raw_parts(result.data, result.length) }.to_vec();
        // SAFETY: This is the sole release of the returned result.
        unsafe {
            lpm_env_release(result);
        }
        bytes
    }

    #[test]
    fn sealed_boxes_open_with_the_recipient_key_like_libsodium() {
        // Made with libsodium's crypto_box_seed_keypair and crypto_box_seal.
        let secret = crypto_box::SecretKey::from_slice(
            &hex::decode("76bf4ad35f7569b718b6bb9fbd57d9df4e28a10b53504d455917a0893257c365")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(secret.public_key().as_bytes()),
            "ce145f7279f86e1c1d55d23d50ce327c861c4bd7b76e7895e34d24dc4fa6ab33"
        );
        let libsodium = hex::decode("64b4198082cb3ab815809e8ad791739aa39b2525e4aa3a7815db637d7d972750f0d9cd639909286ccc83a4e980ee5f2eb39be96a6bcb41aba5f8407b0180f518fdbdadb151cb264891e1b2265da3").unwrap();
        let message = "lpm-vault sealed box vector \u{e9}".as_bytes();
        assert_eq!(secret.unseal(&libsodium).unwrap(), message);

        let sealed = sealed_bytes(seal(secret.public_key().as_bytes(), message));
        assert_eq!(sealed.len(), message.len() + crypto_box::SEALBYTES);
        assert_eq!(secret.unseal(&sealed).unwrap(), message);
        let again = sealed_bytes(seal(secret.public_key().as_bytes(), message));
        assert_ne!(
            sealed[..crypto_box::KEY_SIZE],
            again[..crypto_box::KEY_SIZE],
            "Each seal uses a fresh ephemeral key"
        );
        assert_eq!(secret.unseal(&again).unwrap(), message);
    }

    #[test]
    fn sealing_accepts_an_empty_value_and_the_largest_one() {
        let secret = crypto_box::SecretKey::from([7u8; crypto_box::KEY_SIZE]);
        let public = secret.public_key();
        let empty = sealed_bytes(seal(public.as_bytes(), &[]));
        assert_eq!(empty.len(), crypto_box::SEALBYTES);
        assert!(secret.unseal(&empty).unwrap().is_empty());
        let largest = vec![0x5a; SEAL_INPUT_LIMIT];
        let sealed = sealed_bytes(seal(public.as_bytes(), &largest));
        assert_eq!(secret.unseal(&sealed).unwrap(), largest);
    }

    /// The small-order points of Curve25519 as libsodium lists them, each
    /// also with bit 255 set, which X25519 ignores.
    fn low_order_keys() -> Vec<[u8; crypto_box::KEY_SIZE]> {
        let mut keys = Vec::new();
        for text in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let mut key = [0u8; crypto_box::KEY_SIZE];
            hex::decode_to_slice(text, &mut key).unwrap();
            keys.push(key);
            key[31] |= 0x80;
            keys.push(key);
        }
        keys
    }

    #[test]
    fn sealing_refuses_a_low_order_key_libsodium_would_refuse_to_open() {
        for key in low_order_keys() {
            let shared = x25519_dalek::StaticSecret::from([7u8; crypto_box::KEY_SIZE])
                .diffie_hellman(&x25519_dalek::PublicKey::from(key));
            assert!(
                !shared.was_contributory(),
                "{} is a low-order point",
                hex::encode(key)
            );

            let result = seal(&key, b"value");
            assert_eq!(result.status, 2, "{} is refused", hex::encode(key));
            // SAFETY: The result remains owned and unreleased for the complete read.
            let body = unsafe { std::slice::from_raw_parts(result.data, result.length) };
            assert_eq!(body, br#"{"abiVersion":1,"code":"env.invalid_input"}"#);
            // SAFETY: This is the sole release of the returned result.
            unsafe {
                lpm_env_release(result);
            }
        }
    }

    #[test]
    fn sealing_refuses_keys_and_values_it_cannot_take() {
        let key = [9u8; crypto_box::KEY_SIZE];
        let mut cases = vec![
            seal(&key[..31], b"value"),
            seal(&[9u8; 33], b"value"),
            seal(&key, &vec![0; SEAL_INPUT_LIMIT + 1]),
        ];
        // SAFETY: Null pointers are rejected before anything is read.
        cases.push(unsafe {
            lpm_env_seal_box(std::ptr::null(), crypto_box::KEY_SIZE, b"v".as_ptr(), 1)
        });
        // SAFETY: Null pointers are rejected before anything is read.
        cases.push(unsafe { lpm_env_seal_box(key.as_ptr(), key.len(), std::ptr::null(), 1) });
        for result in cases {
            assert_eq!(result.status, 2);
            // SAFETY: The result remains owned and unreleased for the complete read.
            let body = unsafe { std::slice::from_raw_parts(result.data, result.length) };
            assert_eq!(body, br#"{"abiVersion":1,"code":"env.invalid_input"}"#);
            // SAFETY: This is the sole release of the returned result.
            unsafe {
                lpm_env_release(result);
            }
        }
    }
}
