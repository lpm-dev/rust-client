//! Project-contained schema composition with immutable dependency snapshots.

mod graph;
mod read;

pub use graph::decode_definition;

use lpm_env::{EnvSchema, EnvSchemaDefinition, ValidationErrorKind};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

pub const RESOLVER_VERSION: &str = "lpm-env-source-v1";
pub const MAX_SCHEMA_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_NODES: usize = 64;
pub const MAX_EDGES: usize = 256;
pub const MAX_DEPTH: usize = 16;
pub const MAX_MERGE_VISITS: usize = 65_536;

/// Diagnostics contain static codes and source locations, never value literals.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaDiagnostic {
    pub code: &'static str,
    pub phase: &'static str,
    pub source: String,
    pub pointer: String,
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<&'static str>,
    #[serde(rename = "relatedSources", skip_serializing_if = "Vec::is_empty")]
    pub related_sources: Vec<SourceLocation>,
}

#[derive(Debug, Clone)]
pub struct SourceError {
    pub diagnostic: Box<SchemaDiagnostic>,
    pub requested_paths: Vec<String>,
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at {}{}",
            self.diagnostic.code,
            DiagnosticText(&self.diagnostic.source),
            DiagnosticText(&self.diagnostic.pointer)
        )?;
        if let [first, second] = self.diagnostic.related_sources.as_slice() {
            write!(
                f,
                " (conflicting declarations: {}{} and {}{})",
                DiagnosticText(&first.source),
                DiagnosticText(&first.pointer),
                DiagnosticText(&second.source),
                DiagnosticText(&second.pointer)
            )?;
        }
        if let Some(message) = self.diagnostic.message {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

/// Characters that can hide or reorder the text around them when shown.
pub(crate) fn is_display_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// The diagnostic `key` for a declared name: only a portable variable name,
/// which is plain ASCII and safe to show.
pub(crate) fn diagnostic_key(key: &str) -> Option<String> {
    (lpm_env::is_valid_env_var_name(key) && key.len() <= 256).then(|| key.to_owned())
}

struct DiagnosticText<'a>(&'a str);
impl std::fmt::Display for DiagnosticText<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for c in self.0.chars() {
            if is_display_unsafe(c) {
                write!(f, "{}", c.escape_unicode())?;
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for SourceError {}

impl SourceError {
    pub fn new(code: &'static str, phase: &'static str, source: &str, pointer: &str) -> Self {
        Self {
            diagnostic: Box::new(SchemaDiagnostic {
                code,
                phase,
                source: source.into(),
                pointer: if source == "lpm.json"
                    && !pointer.is_empty()
                    && pointer != "/envSchema"
                    && !pointer.starts_with("/envSchema/")
                {
                    format!("/envSchema{pointer}")
                } else {
                    pointer.into()
                },
                key: None,
                message: None,
                related_sources: Vec::new(),
            }),
            requested_paths: Vec::new(),
        }
    }
}

/// The immutable origin of one effective declaration.
#[derive(Debug, Clone, Serialize)]
pub struct SourceLocation {
    pub source: String,
    pub pointer: String,
}

/// A dependency identity records the exact bytes consumed by the parser.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaDependency {
    pub path: String,
    pub digest: [u8; 32],
    pub bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ResolutionStats {
    pub nodes: usize,
    pub edges: usize,
    pub source_bytes: usize,
    pub merge_visits: usize,
}

/// The inherited rules one of lpm.json's variable overrides replaces, in
/// summary: never their values, which no validation has checked once
/// they're overridden.
#[derive(Debug, Clone, Serialize)]
pub struct ReplacedRules {
    /// How many: more than one when the override settles a conflict between
    /// imports, each import counted once however many paths reach it.
    pub count: usize,
    /// Where the first one comes from: what lpm.json's imports resolve, an
    /// import's own override when one overrides the original declaration.
    pub origin: SourceLocation,
    /// Whether every one marks the variable client-visible.
    pub client: bool,
    /// Where the first one that marks the variable secret comes from; none when none does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<SourceLocation>,
}

/// The inherited groups one of lpm.json's group overrides replaces, in summary.
#[derive(Debug, Clone, Serialize)]
pub struct ReplacedGroups {
    /// How many: more than one when the override settles a conflict between imports.
    pub count: usize,
    /// Where the first one comes from, as for `ReplacedRules`.
    pub origin: SourceLocation,
}

/// Effective declarations and provenance belong to the same retained root capability.
#[derive(Debug)]
pub struct SchemaSnapshot {
    pub origins: BTreeMap<String, SourceLocation>,
    pub group_origins: BTreeMap<String, SourceLocation>,
    /// Original declaration locations for variables replaced by overrides.
    pub declaring_origins: BTreeMap<String, SourceLocation>,
    /// Original declaration locations for groups replaced by overrides.
    pub group_declaring_origins: BTreeMap<String, SourceLocation>,
    /// Where each client prefix is listed: the first schema in resolution
    /// order that lists it, so a prefix lpm.json shares with an import names the import.
    pub client_prefix_origins: BTreeMap<String, SourceLocation>,
    /// What each of lpm.json's variable overrides replaces.
    pub replaced_vars: BTreeMap<String, ReplacedRules>,
    /// What each of lpm.json's group overrides replaces.
    pub replaced_groups: BTreeMap<String, ReplacedGroups>,
    pub dependencies: Vec<SchemaDependency>,
    pub fingerprint: [u8; 32],
    pub root_digest: [u8; 32],
    pub stats: ResolutionStats,
    root: Arc<cap_std::fs::Dir>,
    root_identity: same_file::Handle,
    named_root: Option<std::path::PathBuf>,
}

#[derive(Debug)]
pub struct ResolvedSchema {
    pub schema: EnvSchema,
    pub snapshot: Arc<SchemaSnapshot>,
}

impl std::ops::Deref for ResolvedSchema {
    type Target = SchemaSnapshot;
    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

impl SchemaSnapshot {
    pub fn matches_root_content(&self, bytes: &[u8]) -> bool {
        digest(bytes) == self.root_digest
    }
    /// Reopen every dependency from the retained directory to detect atomic replacements.
    pub fn verify_dependencies(&self) -> Result<(), SourceError> {
        if let Some(path) = &self.named_root {
            let directory = cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority())
                .map_err(|_| SourceError::new("env.source_changed", "freshness", "lpm.json", ""))?;
            let identity = same_file::Handle::from_file(directory.into_std_file())
                .map_err(|_| SourceError::new("env.source_changed", "freshness", "lpm.json", ""))?;
            if identity != self.root_identity {
                return Err(SourceError::new(
                    "env.source_changed",
                    "freshness",
                    "lpm.json",
                    "",
                ));
            }
        }
        let mut scratch = [0u8; 16 * 1024];
        for dependency in &self.dependencies {
            let unchanged =
                read::verify_fragment(&self.root, dependency, &mut scratch).map_err(|_| {
                    SourceError::new("env.source_changed", "freshness", &dependency.path, "")
                })?;
            if !unchanged {
                return Err(SourceError::new(
                    "env.source_changed",
                    "freshness",
                    &dependency.path,
                    "",
                ));
            }
        }
        Ok(())
    }
}

pub fn resolve_schema(
    project_dir: &Path,
    root_content: &[u8],
    definition: EnvSchemaDefinition,
) -> Result<ResolvedSchema, SourceError> {
    resolve_schema_input(
        project_dir,
        root_content,
        std::borrow::Cow::Owned(definition),
    )
}

/// Bound an authored definition before copying it into the effective graph.
pub fn resolve_schema_borrowed(
    project_dir: &Path,
    root_content: &[u8],
    definition: &EnvSchemaDefinition,
) -> Result<ResolvedSchema, SourceError> {
    resolve_schema_input(
        project_dir,
        root_content,
        std::borrow::Cow::Borrowed(definition),
    )
}

fn resolve_schema_input(
    project_dir: &Path,
    root_content: &[u8],
    definition: std::borrow::Cow<'_, EnvSchemaDefinition>,
) -> Result<ResolvedSchema, SourceError> {
    let named_root = std::path::absolute(project_dir).map_err(|_| {
        SourceError::new(
            "env.project_unavailable",
            "resolve",
            "lpm.json",
            "/envSchema",
        )
    })?;
    let root = open_project_directory(&named_root).map_err(|_| {
        SourceError::new(
            "env.project_unavailable",
            "resolve",
            "lpm.json",
            "/envSchema",
        )
    })?;
    graph::resolve(Arc::new(root), root_content, definition, Some(named_root))
}

#[cfg(not(windows))]
fn open_project_directory(path: &Path) -> std::io::Result<cap_std::fs::Dir> {
    cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority())
}

#[cfg(windows)]
fn open_project_directory(path: &Path) -> std::io::Result<cap_std::fs::Dir> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_SHARE_READ_WRITE_DELETE: u32 = 7;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ_WRITE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    if !file.metadata()?.is_dir() {
        return Err(std::io::Error::other("project root must be a directory"));
    }
    Ok(cap_std::fs::Dir::from_std_file(file))
}

/// Borrowed root definitions receive the same budget checks before copying.
pub fn resolve_schema_in_borrowed(
    root: Arc<cap_std::fs::Dir>,
    root_content: &[u8],
    definition: &EnvSchemaDefinition,
) -> Result<ResolvedSchema, SourceError> {
    graph::resolve(
        root,
        root_content,
        std::borrow::Cow::Borrowed(definition),
        None,
    )
}

pub(crate) fn digest(content: &[u8]) -> [u8; 32] {
    Sha256::digest(content).into()
}

pub fn declaration_code(kind: &ValidationErrorKind) -> &'static str {
    match kind {
        ValidationErrorKind::InvalidVariableName => "env.invalid_name",
        ValidationErrorKind::InvalidPattern { .. } => "env.invalid_pattern",
        ValidationErrorKind::InvalidRule { .. } => "env.invalid_rule",
        ValidationErrorKind::InvalidEnvironmentName { .. } => "env.invalid_environment",
        ValidationErrorKind::Empty => "env.empty",
        ValidationErrorKind::InvalidValue => "env.invalid_value",
        ValidationErrorKind::Missing => "env.required",
        ValidationErrorKind::InvalidFormat { .. } => "env.invalid_format",
        ValidationErrorKind::PatternMismatch { .. } => "env.pattern_mismatch",
        ValidationErrorKind::NotInEnum { .. } => "env.enum_mismatch",
        ValidationErrorKind::ConstraintViolation { .. } => "env.constraint",
        ValidationErrorKind::GroupViolation { .. } => "env.group",
    }
}

/// Enforce output size while writing, before an unbounded allocation can occur.
pub fn bounded_json<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, SourceError> {
    struct Output {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("bounded JSON output exceeded"));
            }
            let needed = self.bytes.len() + bytes.len();
            if needed > self.bytes.capacity() {
                let capacity = needed
                    .max(self.bytes.capacity().saturating_mul(2))
                    .min(self.limit);
                self.bytes.reserve_exact(capacity - self.bytes.len());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Output {
        bytes: Vec::with_capacity(limit.min(4096)),
        limit,
    };
    serde_json::to_writer(&mut output, value).map_err(|_| {
        SourceError::new("env.output_budget", "serialize", "lpm.json", "/envSchema")
    })?;
    Ok(output.bytes)
}

#[cfg(test)]
mod tests;

/// Count bounded serialized bytes without retaining a throwaway output buffer.
pub fn json_size<T: Serialize>(value: &T, limit: usize) -> Result<usize, SourceError> {
    struct Counter {
        length: usize,
        limit: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.length) {
                return Err(std::io::Error::other("bounded JSON output exceeded"));
            }
            self.length += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { length: 0, limit };
    serde_json::to_writer(&mut counter, value).map_err(|_| {
        SourceError::new("env.output_budget", "serialize", "lpm.json", "/envSchema")
    })?;
    Ok(counter.length)
}

/// Stable map ordering for generated artifacts and flattened package manifests.
pub fn schema_json(schema: &EnvSchema) -> Result<Vec<u8>, SourceError> {
    bounded_json(&ordered_schema(schema), MAX_SCHEMA_BYTES)
}

/// Borrow schema payloads while ordering declarations for deterministic serialization.
pub fn ordered_schema(schema: &EnvSchema) -> impl Serialize + '_ {
    #[derive(Serialize)]
    struct OrderedSchema<'a> {
        vars: BTreeMap<&'a str, &'a lpm_env::EnvVarRule>,
        #[serde(rename = "clientPrefixes", skip_serializing_if = "Vec::is_empty")]
        client_prefixes: &'a Vec<String>,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        groups: BTreeMap<&'a str, &'a lpm_env::VarGroup>,
    }
    OrderedSchema {
        vars: schema
            .vars
            .iter()
            .map(|(key, value)| (key.as_str(), value))
            .collect(),
        client_prefixes: &schema.client_prefixes,
        groups: schema
            .groups
            .iter()
            .map(|(key, value)| (key.as_str(), value))
            .collect(),
    }
}
