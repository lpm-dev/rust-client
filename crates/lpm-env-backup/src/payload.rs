//! What a version 1 backup holds, checked strictly before it's sealed and
//! after it's opened.
//!
//! The payload is UTF-8 JSON:
//!
//! ```json
//! {
//!   "createdAt": 1761171075,
//!   "producer": {"name": "LPM Vault", "version": "1.4.0"},
//!   "deviceName": "Studio",
//!   "projects": [{
//!     "vaultId": "550e8400-e29b-41d4-a716-446655440000",
//!     "name": "demo-api",
//!     "folder": "/Users/me/Developer/demo-api",
//!     "hidden": false,
//!     "cliAccess": "requireApproval",
//!     "environments": {"default": {"DATABASE_URL": "postgres://…"}},
//!     "sync": {"registry": "https://lpm.dev", "scope": "personal", "principalId": "…"}
//!   }],
//!   "app": {}
//! }
//! ```
//!
//! `deviceName`, `folder`, `sync` and `app` may be absent or null; `orgSlug`
//! goes with the `organization` scope only. Every object refuses unknown and
//! repeated fields. `createdAt` is a plain unsigned integer, `cliAccess` and
//! `scope` are written exactly as shown, without escapes, and each value is a
//! string.
//!
//! Names, folders and vault IDs are kept as the CLI stores them, which can be
//! any text, including direction controls: show them isolated, with controls
//! made visible. The labels this format defines (the producer, `deviceName`
//! and `principalId`) refuse controls and direction controls. A restorer
//! whose store names files after vault IDs must map them to names that are
//! valid and distinct there. A project's
//! environments as the CLI stores them, and the index record that lists them
//! with the project's name and folder, must each fit the credential store's
//! limit on one item. Registries are written as the CLI's sync bindings hold
//! them.
//!
//! `app` is an object the app that wrote the backup owns. Here it's only
//! checked as JSON whose objects repeat no key, nested at most
//! [`MAX_APP_DEPTH`] deep, with at most [`MAX_APP_KEYS`] keys between them of
//! at most [`MAX_APP_KEY_BYTES`] each, whose numbers are finite doubles. Its
//! reader must refuse what it doesn't know.
//!
//! The reader never copies a value, nor any string where an object, list,
//! number or flag belongs: it measures them where they lie. It decodes only
//! keys, names and labels. Errors carry a code and a byte offset, never text.

use std::borrow::Cow;
use std::collections::HashSet;

use lpm_common::stored_env::{
    MAX_ENVIRONMENT_NAME_BYTES, MAX_ORG_SLUG_BYTES, MAX_VAULT_ID_BYTES, is_canonical_registry_url,
    is_safe_vault_id, is_valid_environment_name, is_valid_org_slug, is_valid_variable_name,
    is_variable_name_byte,
};

/// The most projects a backup holds.
pub const MAX_PROJECTS: usize = 10_000;
/// The credential store's limit on one item, which a project's environments
/// as the CLI stores them (`{"environments":{…}}`) and its index record must
/// each fit.
pub const MAX_PROJECT_BYTES: usize = 100 * 1024;
/// The most objects and lists nested in `app`, counting `app` itself.
pub const MAX_APP_DEPTH: usize = 32;
/// The most keys `app`'s objects have between them, which bounds the memory
/// that refusing repeated keys holds.
pub const MAX_APP_KEYS: usize = 1_000_000;
/// The longest key in `app`, decoded.
pub const MAX_APP_KEY_BYTES: usize = 256;
/// The latest `createdAt`: the last second of 9999.
const MAX_CREATED_AT: u64 = 253_402_300_799;
const MAX_LABEL_BYTES: usize = 64;
const MAX_DEVICE_NAME_BYTES: usize = 256;
const MAX_REGISTRY_BYTES: usize = 2048;
const MAX_PRINCIPAL_BYTES: usize = 256;

/// Longer than any field name the format has, so a longer key can't be one.
const MAX_FIELD_NAME_BYTES: usize = 64;

/// Why a payload isn't a valid backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadError {
    pub kind: PayloadErrorKind,
    /// The byte offset in the payload where the problem was found.
    pub offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadErrorKind {
    /// Not UTF-8 JSON.
    Syntax,
    /// A field is missing, unknown or repeated, or a value is of the wrong
    /// type or spelling.
    Structure,
    CreatedAt,
    Producer,
    DeviceName,
    TooManyProjects,
    VaultId,
    DuplicateVaultId,
    EnvironmentName,
    DuplicateEnvironment,
    VariableName,
    DuplicateVariable,
    /// A value that isn't a string.
    Value,
    /// A project's environments, or its index record, over [`MAX_PROJECT_BYTES`].
    ProjectTooLarge,
    Sync,
    /// `app` isn't an object, repeats a key, nests too deep, has too many or
    /// too long keys, or holds a number out of range.
    App,
}

impl PayloadErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::Syntax => "syntax",
            Self::Structure => "structure",
            Self::CreatedAt => "created_at",
            Self::Producer => "producer",
            Self::DeviceName => "device_name",
            Self::TooManyProjects => "too_many_projects",
            Self::VaultId => "vault_id",
            Self::DuplicateVaultId => "duplicate_vault_id",
            Self::EnvironmentName => "environment_name",
            Self::DuplicateEnvironment => "duplicate_environment",
            Self::VariableName => "variable_name",
            Self::DuplicateVariable => "duplicate_variable",
            Self::Value => "value",
            Self::ProjectTooLarge => "project_too_large",
            Self::Sync => "sync",
            Self::App => "app",
        }
    }
}

/// Checks that `payload` is a valid version 1 backup.
pub fn validate(payload: &[u8]) -> Result<(), PayloadError> {
    let text = std::str::from_utf8(payload).map_err(|error| PayloadError {
        kind: PayloadErrorKind::Syntax,
        offset: error.valid_up_to(),
    })?;
    let mut reader = Reader { text, at: 0 };
    read_backup(&mut reader)?;
    reader.skip_whitespace();
    if reader.at == text.len() {
        Ok(())
    } else {
        Err(reader.error(PayloadErrorKind::Syntax))
    }
}

/// Marks a field read, refusing it the second time.
fn first(seen: &mut bool, reader: &Reader<'_>, at: usize) -> Result<(), PayloadError> {
    if std::mem::replace(seen, true) {
        Err(reader.error_at(PayloadErrorKind::Structure, at))
    } else {
        Ok(())
    }
}

fn read_backup(reader: &mut Reader<'_>) -> Result<(), PayloadError> {
    let (mut created_at, mut producer, mut device_name, mut projects, mut app) =
        (false, false, false, false, false);
    reader.object(MAX_FIELD_NAME_BYTES, |reader, key, at| {
        match key.as_deref() {
            Some("createdAt") => {
                first(&mut created_at, reader, at)?;
                let value_at = reader.at;
                if reader.unsigned()? > MAX_CREATED_AT {
                    return Err(reader.error_at(PayloadErrorKind::CreatedAt, value_at));
                }
                Ok(())
            }
            Some("producer") => {
                first(&mut producer, reader, at)?;
                read_producer(reader)
            }
            Some("deviceName") => {
                first(&mut device_name, reader, at)?;
                reader
                    .optional(|reader| {
                        let name_at = reader.at;
                        if reader
                            .text_value(MAX_DEVICE_NAME_BYTES)?
                            .is_some_and(|name| is_label(&name, MAX_DEVICE_NAME_BYTES))
                        {
                            Ok(())
                        } else {
                            Err(reader.error_at(PayloadErrorKind::DeviceName, name_at))
                        }
                    })
                    .map(|_| ())
            }
            Some("projects") => {
                first(&mut projects, reader, at)?;
                read_projects(reader)
            }
            Some("app") => {
                first(&mut app, reader, at)?;
                reader.optional(read_app).map(|_| ())
            }
            _ => Err(reader.error_at(PayloadErrorKind::Structure, at)),
        }
    })?;
    if created_at && producer && projects {
        Ok(())
    } else {
        Err(reader.error(PayloadErrorKind::Structure))
    }
}

/// `app`, which fails as [`PayloadErrorKind::App`] where it breaks the
/// section's rules once it's known to be JSON up to there: an object where
/// it breaks one, and anything else at its start, once it's read through.
fn read_app(reader: &mut Reader<'_>) -> Result<(), PayloadError> {
    reader.skip_whitespace();
    let value_at = reader.at;
    if reader.peek() == Some(b'{') {
        let mut keys = 0;
        return reader
            .app_value(1, &mut keys)
            .map_err(|error| match error.kind {
                PayloadErrorKind::Syntax => error,
                _ => reader.error_at(PayloadErrorKind::App, error.offset),
            });
    }
    reader.skip_value()?;
    if matches!(reader.peek(), Some(b',' | b'}')) {
        Err(reader.error_at(PayloadErrorKind::App, value_at))
    } else {
        Err(reader.error(PayloadErrorKind::Syntax))
    }
}

fn read_producer(reader: &mut Reader<'_>) -> Result<(), PayloadError> {
    let (mut name, mut version) = (false, false);
    reader.object(MAX_FIELD_NAME_BYTES, |reader, key, at| {
        let seen = match key.as_deref() {
            Some("name") => &mut name,
            Some("version") => &mut version,
            _ => return Err(reader.error_at(PayloadErrorKind::Structure, at)),
        };
        first(seen, reader, at)?;
        let label_at = reader.at;
        if reader
            .text_value(MAX_LABEL_BYTES)?
            .is_some_and(|label| is_label(&label, MAX_LABEL_BYTES))
        {
            Ok(())
        } else {
            Err(reader.error_at(PayloadErrorKind::Producer, label_at))
        }
    })?;
    if name && version {
        Ok(())
    } else {
        Err(reader.error(PayloadErrorKind::Structure))
    }
}

/// Text people are shown that this format defines: non-empty, bounded, and
/// without controls or direction controls.
fn is_label(text: &str, max_bytes: usize) -> bool {
    !text.is_empty()
        && text.len() <= max_bytes
        && !text
            .chars()
            .any(|character| character.is_control() || is_direction_control(character))
}

/// The characters that change the direction text runs in, which could make a
/// label read as something else.
fn is_direction_control(character: char) -> bool {
    matches!(
        character,
        '\u{61C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// The projects, checked as they're read, each vault ID once, so a payload
/// can't make the reader hold more than [`MAX_PROJECTS`] of them.
fn read_projects(reader: &mut Reader<'_>) -> Result<(), PayloadError> {
    let mut vault_ids = HashSet::new();
    reader.list(|reader| {
        reader.skip_whitespace();
        let at = reader.at;
        if vault_ids.len() == MAX_PROJECTS {
            return Err(reader.error_at(PayloadErrorKind::TooManyProjects, at));
        }
        let (vault_id, _) = read_project(reader)?;
        if vault_ids.insert(vault_id) {
            Ok(())
        } else {
            Err(reader.error_at(PayloadErrorKind::DuplicateVaultId, at))
        }
    })
}

/// The CLI's index record for a project, around its strings and summaries:
/// `{"schemaVersion":3,"storageId":"…","id":…,"name":…,"path":…,
/// "discoveryShard":…,"environmentSummaries":[…]}`, with the longest storage
/// ID and shard number.
const INDEX_RECORD_BYTES: usize = r#"{"schemaVersion":3,"storageId":"00000000-0000-4000-8000-000000000000","id":,"name":,"path":,"discoveryShard":1023,"environmentSummaries":[]}"#.len();
/// One environment's summary in the index record, around its name and count.
const INDEX_SUMMARY_BYTES: usize = r#"{"name":,"keyCount":}"#.len();

/// Reads one project and returns its vault ID and the most its index record
/// takes.
fn read_project<'a>(reader: &mut Reader<'a>) -> Result<(Cow<'a, str>, usize), PayloadError> {
    reader.skip_whitespace();
    let project_at = reader.at;
    let mut vault_id = None;
    let mut name = None;
    let mut folder: Option<Option<Cow<'a, str>>> = None;
    let (mut hidden, mut cli_access, mut sync) = (false, false, false);
    let mut environments = None;
    // A name or folder too long for the index record fails once the project's
    // read, as one that makes the record too long does.
    let mut oversized = false;
    let mut stored_text = |reader: &mut Reader<'a>| {
        Ok(reader.text_value(MAX_PROJECT_BYTES)?.unwrap_or_else(|| {
            oversized = true;
            Cow::Borrowed("")
        }))
    };
    reader.object(MAX_FIELD_NAME_BYTES, |reader, key, at| {
        match key.as_deref() {
            Some("vaultId") => {
                if vault_id.is_some() {
                    return Err(reader.error_at(PayloadErrorKind::Structure, at));
                }
                let id_at = reader.at;
                let id = reader
                    .text_value(MAX_VAULT_ID_BYTES)?
                    .filter(|id| is_safe_vault_id(id))
                    .ok_or_else(|| reader.error_at(PayloadErrorKind::VaultId, id_at))?;
                vault_id = Some(id);
            }
            Some("name") => {
                if name.is_some() {
                    return Err(reader.error_at(PayloadErrorKind::Structure, at));
                }
                name = Some(stored_text(reader)?);
            }
            Some("folder") => {
                if folder.is_some() {
                    return Err(reader.error_at(PayloadErrorKind::Structure, at));
                }
                folder = Some(reader.optional(&mut stored_text)?);
            }
            Some("hidden") => {
                first(&mut hidden, reader, at)?;
                reader.flag()?;
            }
            Some("cliAccess") => {
                first(&mut cli_access, reader, at)?;
                reader.one_of(&["automatic", "requireApproval"])?;
            }
            Some("environments") => {
                if environments.is_some() {
                    return Err(reader.error_at(PayloadErrorKind::Structure, at));
                }
                environments = Some(read_environments(reader)?.1);
            }
            Some("sync") => {
                first(&mut sync, reader, at)?;
                reader.optional(read_sync)?;
            }
            _ => return Err(reader.error_at(PayloadErrorKind::Structure, at)),
        }
        Ok(())
    })?;
    let (Some(vault_id), Some(name), true, true, Some(summary_bytes)) =
        (vault_id, name, hidden, cli_access, environments)
    else {
        return Err(reader.error(PayloadErrorKind::Structure));
    };
    let index_record_bytes = INDEX_RECORD_BYTES
        + quoted_len(&vault_id)
        + quoted_len(&name)
        + quoted_len(folder.flatten().as_deref().unwrap_or_default())
        + summary_bytes;
    if oversized || index_record_bytes > MAX_PROJECT_BYTES {
        return Err(reader.error_at(PayloadErrorKind::ProjectTooLarge, project_at));
    }
    Ok((vault_id, index_record_bytes))
}

fn read_sync(reader: &mut Reader<'_>) -> Result<(), PayloadError> {
    reader.skip_whitespace();
    let sync_at = reader.at;
    let mut registry = None;
    let mut scope = None;
    let mut principal = None;
    let mut org_slug = None;
    reader.object(MAX_FIELD_NAME_BYTES, |reader, key, at| {
        let repeated = match key.as_deref() {
            Some("registry") => registry.is_some(),
            Some("scope") => scope.is_some(),
            Some("principalId") => principal.is_some(),
            Some("orgSlug") => org_slug.is_some(),
            _ => true,
        };
        if repeated {
            return Err(reader.error_at(PayloadErrorKind::Structure, at));
        }
        match key.as_deref() {
            Some("registry") => registry = Some(reader.text_value(MAX_REGISTRY_BYTES)?),
            Some("scope") => scope = Some(reader.one_of(&["personal", "organization"])?),
            Some("principalId") => principal = Some(reader.text_value(MAX_PRINCIPAL_BYTES)?),
            _ => org_slug = Some(reader.optional(|reader| reader.text_value(MAX_ORG_SLUG_BYTES))?),
        }
        Ok(())
    })?;
    let (Some(registry), Some(scope), Some(principal)) = (registry, scope, principal) else {
        return Err(reader.error(PayloadErrorKind::Structure));
    };
    let org_matches_scope = match org_slug.flatten() {
        None => scope == 0,
        Some(slug) => scope == 1 && slug.as_deref().is_some_and(is_valid_org_slug),
    };
    if registry.as_deref().is_some_and(is_canonical_registry_url)
        && principal
            .as_deref()
            .is_some_and(|principal| is_label(principal, MAX_PRINCIPAL_BYTES))
        && org_matches_scope
    {
        Ok(())
    } else {
        Err(reader.error_at(PayloadErrorKind::Sync, sync_at))
    }
}

/// `{"environments":{}}`, around the entries.
const STORED_ENVELOPE_BYTES: usize = r#"{"environments":{}}"#.len();
/// The CLI stores a project without environments with an empty `default`,
/// which its index record then summarizes.
const EMPTY_STORED_BYTES: usize = r#"{"environments":{"default":{}}}"#.len();

/// A project's environments: the bytes they take as the CLI stores them, and
/// the bytes their comma-separated summaries take in its index record.
fn read_environments(reader: &mut Reader<'_>) -> Result<(usize, usize), PayloadError> {
    let mut names = HashSet::new();
    let mut stored_bytes = STORED_ENVELOPE_BYTES;
    let mut summary_bytes = 0;
    reader.object(MAX_ENVIRONMENT_NAME_BYTES, |reader, name, at| {
        let Some(name) = name.filter(|name| is_valid_environment_name(name)) else {
            return Err(reader.error_at(PayloadErrorKind::EnvironmentName, at));
        };
        let (count, variables) = read_variables(reader)?;
        let separator = usize::from(!names.is_empty());
        stored_bytes += separator + quoted_len(&name) + 1 + variables;
        summary_bytes +=
            separator + INDEX_SUMMARY_BYTES + quoted_len(&name) + decimal_digits(count);
        if stored_bytes > MAX_PROJECT_BYTES || summary_bytes > MAX_PROJECT_BYTES {
            return Err(reader.error_at(PayloadErrorKind::ProjectTooLarge, at));
        }
        if names.insert(name) {
            Ok(())
        } else {
            Err(reader.error_at(PayloadErrorKind::DuplicateEnvironment, at))
        }
    })?;
    if names.is_empty() {
        return Ok((
            EMPTY_STORED_BYTES,
            INDEX_SUMMARY_BYTES + quoted_len("default") + decimal_digits(0),
        ));
    }
    Ok((stored_bytes, summary_bytes))
}

/// One environment's variables: how many, and the bytes `{…}` takes stored.
fn read_variables(reader: &mut Reader<'_>) -> Result<(usize, usize), PayloadError> {
    let mut names = HashSet::new();
    let mut stored_bytes = 2;
    reader.object(MAX_PROJECT_BYTES, |reader, name, at| {
        let Some(name) = name else {
            // No name this long fits the store, but it fails as a shorter
            // one would: as a name first, then by its value.
            if !reader.decodes_to_variable_name(at) {
                return Err(reader.error_at(PayloadErrorKind::VariableName, at));
            }
            reader.measured_value()?;
            return Err(reader.error_at(PayloadErrorKind::ProjectTooLarge, at));
        };
        if !is_valid_variable_name(&name) {
            return Err(reader.error_at(PayloadErrorKind::VariableName, at));
        }
        let value = reader.measured_value()?;
        stored_bytes += usize::from(!names.is_empty()) + quoted_len(&name) + 1 + value;
        if stored_bytes > MAX_PROJECT_BYTES {
            return Err(reader.error_at(PayloadErrorKind::ProjectTooLarge, at));
        }
        if names.insert(name) {
            Ok(())
        } else {
            Err(reader.error_at(PayloadErrorKind::DuplicateVariable, at))
        }
    })?;
    Ok((names.len(), stored_bytes))
}

fn decimal_digits(value: usize) -> usize {
    value.checked_ilog10().map_or(1, |log| log as usize + 1)
}

/// The length of `text` as serde_json writes it in quotes, which is how the
/// CLI stores values.
fn quoted_len(text: &str) -> usize {
    2 + text.chars().map(escaped_len).sum::<usize>()
}

/// What `character` takes inside quotes as serde_json writes it.
fn escaped_len(character: char) -> usize {
    match character {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        '\0'..='\u{1f}' => 6,
        _ => character.len_utf8(),
    }
}

/// A strict JSON reader over the payload that reads only the shapes this
/// format has, and skips what it reads without copying it.
struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Reader<'a> {
    fn error(&self, kind: PayloadErrorKind) -> PayloadError {
        self.error_at(kind, self.at)
    }

    fn error_at(&self, kind: PayloadErrorKind, offset: usize) -> PayloadError {
        PayloadError { kind, offset }
    }

    /// What reading the wrong token as `kind` fails as: `kind`, unless the
    /// input ends or the next byte starts no JSON value at all.
    fn mismatch(&mut self, kind: PayloadErrorKind) -> PayloadError {
        match self.peek() {
            Some(b'{' | b'[' | b'"' | b't' | b'f' | b'n' | b'-' | b'0'..=b'9') => self.error(kind),
            _ => self.error(PayloadErrorKind::Syntax),
        }
    }

    fn skip_whitespace(&mut self) {
        let bytes = self.text.as_bytes();
        while matches!(bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    /// The next token's first byte, after whitespace.
    fn peek(&mut self) -> Option<u8> {
        self.skip_whitespace();
        self.text.as_bytes().get(self.at).copied()
    }

    fn take(&mut self, byte: u8) -> bool {
        let taken = self.peek() == Some(byte);
        self.at += usize::from(taken);
        taken
    }

    fn expect(&mut self, byte: u8) -> Result<(), PayloadError> {
        if self.take(byte) {
            Ok(())
        } else {
            Err(self.error(PayloadErrorKind::Syntax))
        }
    }

    /// Reads an object, giving `member` each key and where it starts, with
    /// the reader at its value, which `member` must read. A key is decoded
    /// only when it decodes to at most `max_key_bytes`, and is `None`
    /// otherwise, since none that long is valid there.
    fn object(
        &mut self,
        max_key_bytes: usize,
        mut member: impl FnMut(&mut Self, Option<Cow<'a, str>>, usize) -> Result<(), PayloadError>,
    ) -> Result<(), PayloadError> {
        if !self.take(b'{') {
            return Err(self.mismatch(PayloadErrorKind::Structure));
        }
        if self.take(b'}') {
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            let key_at = self.at;
            if self.peek() != Some(b'"') {
                return Err(self.error(PayloadErrorKind::Syntax));
            }
            let key = self.text_value(max_key_bytes)?;
            self.expect(b':')?;
            member(self, key, key_at)?;
            if self.take(b'}') {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    /// Reads a list, with `element` reading each element.
    fn list(
        &mut self,
        mut element: impl FnMut(&mut Self) -> Result<(), PayloadError>,
    ) -> Result<(), PayloadError> {
        if !self.take(b'[') {
            return Err(self.mismatch(PayloadErrorKind::Structure));
        }
        if self.take(b']') {
            return Ok(());
        }
        loop {
            element(self)?;
            if self.take(b']') {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    /// `None` for `null`, else what `read` reads.
    fn optional<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, PayloadError>,
    ) -> Result<Option<T>, PayloadError> {
        if self.peek() == Some(b'n') {
            self.word("null").map(|()| None)
        } else {
            read(self).map(Some)
        }
    }

    fn word(&mut self, word: &str) -> Result<(), PayloadError> {
        if self.text[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(())
        } else {
            Err(self.error(PayloadErrorKind::Syntax))
        }
    }

    fn flag(&mut self) -> Result<bool, PayloadError> {
        match self.peek() {
            Some(b't') => self.word("true").map(|()| true),
            Some(b'f') => self.word("false").map(|()| false),
            _ => Err(self.mismatch(PayloadErrorKind::Structure)),
        }
    }

    /// A number with no sign, fraction or exponent.
    fn unsigned(&mut self) -> Result<u64, PayloadError> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.mismatch(PayloadErrorKind::Structure));
        }
        let at = self.at;
        let token = self.number_token()?;
        token
            .parse()
            .map_err(|_| self.error_at(PayloadErrorKind::Structure, at))
    }

    /// A JSON number's text, as RFC 8259 writes them.
    fn number_token(&mut self) -> Result<&'a str, PayloadError> {
        self.skip_whitespace();
        let start = self.at;
        let bytes = self.text.as_bytes();
        let digits = |at: &mut usize| {
            let first = *at;
            while matches!(bytes.get(*at), Some(b'0'..=b'9')) {
                *at += 1;
            }
            *at > first
        };
        let mut at = start + usize::from(bytes.get(start) == Some(&b'-'));
        let integer = at;
        if !digits(&mut at) || (bytes[integer] == b'0' && at > integer + 1) {
            return Err(self.error_at(PayloadErrorKind::Syntax, start));
        }
        if bytes.get(at) == Some(&b'.') {
            at += 1;
            if !digits(&mut at) {
                return Err(self.error_at(PayloadErrorKind::Syntax, at));
            }
        }
        if matches!(bytes.get(at), Some(b'e' | b'E')) {
            at += 1;
            at += usize::from(matches!(bytes.get(at), Some(b'+' | b'-')));
            if !digits(&mut at) {
                return Err(self.error_at(PayloadErrorKind::Syntax, at));
            }
        }
        self.at = at;
        Ok(&self.text[start..at])
    }

    /// The index of `names`' string the value is, written without escapes.
    fn one_of(&mut self, names: &[&str]) -> Result<usize, PayloadError> {
        self.skip_whitespace();
        let at = self.at;
        let (start, end) = self.string_span(&mut (), PayloadErrorKind::Structure)?;
        let raw = &self.text[start..end];
        names
            .iter()
            .position(|name| *name == raw)
            .ok_or_else(|| self.error_at(PayloadErrorKind::Structure, at))
    }

    /// A string, decoded, or `None` when it decodes to more than
    /// `max_bytes`: only keys, names and labels are read this way. One
    /// without escapes is borrowed; one with them is walked again to decode,
    /// once its decoded length is known to fit.
    fn text_value(&mut self, max_bytes: usize) -> Result<Option<Cow<'a, str>>, PayloadError> {
        self.skip_whitespace();
        let opening = self.at;
        let mut length = DecodedLength::default();
        let (start, end) = self.string_span(&mut length, PayloadErrorKind::Structure)?;
        if length.bytes > max_bytes {
            return Ok(None);
        }
        if !length.escaped {
            return Ok(Some(Cow::Borrowed(&self.text[start..end])));
        }
        let mut decoded = Decoded(String::with_capacity(length.bytes));
        Reader {
            text: self.text,
            at: opening,
        }
        .string_span(&mut decoded, PayloadErrorKind::Structure)?;
        Ok(Some(Cow::Owned(decoded.0)))
    }

    /// Whether the string at `at`, already read, decodes to a variable name.
    fn decodes_to_variable_name(&self, at: usize) -> bool {
        let mut name = VariableNameShape::default();
        Reader {
            text: self.text,
            at,
        }
        .string_span(&mut name, PayloadErrorKind::Syntax)
        .is_ok()
            && name.is_valid()
    }

    /// A value: a string, measured as the CLI stores it, never copied.
    fn measured_value(&mut self) -> Result<usize, PayloadError> {
        let mut measured = Measured(2);
        self.string_span(&mut measured, PayloadErrorKind::Value)?;
        Ok(measured.0)
    }

    /// Walks the string at the reader, giving `sink` each stretch without
    /// escapes and each escaped character, and returns where its text starts
    /// and ends. Anything but a string fails as `not_string`, before any of
    /// it is read.
    fn string_span(
        &mut self,
        sink: &mut impl Sink<'a>,
        not_string: PayloadErrorKind,
    ) -> Result<(usize, usize), PayloadError> {
        if self.peek() != Some(b'"') {
            return Err(self.mismatch(not_string));
        }
        let bytes = self.text.as_bytes();
        let start = self.at + 1;
        let mut stretch = start;
        let mut at = start;
        loop {
            match bytes.get(at) {
                None => return Err(self.error_at(PayloadErrorKind::Syntax, at)),
                Some(b'"') => {
                    if stretch < at {
                        sink.run(&self.text[stretch..at]);
                    }
                    self.at = at + 1;
                    return Ok((start, at));
                }
                Some(b'\\') => {
                    if stretch < at {
                        sink.run(&self.text[stretch..at]);
                    }
                    let (character, length) = self.escape(at)?;
                    sink.escaped(character);
                    at += length;
                    stretch = at;
                }
                Some(0x00..=0x1f) => return Err(self.error_at(PayloadErrorKind::Syntax, at)),
                Some(_) => at += 1,
            }
        }
    }

    /// The character the escape at `at` stands for, and its length.
    fn escape(&self, at: usize) -> Result<(char, usize), PayloadError> {
        let bytes = self.text.as_bytes();
        let invalid = || self.error_at(PayloadErrorKind::Syntax, at);
        let hex = |from: usize| -> Option<u32> {
            let digits = self.text.get(from..from + 4)?;
            if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            u32::from_str_radix(digits, 16).ok()
        };
        let simple = match bytes.get(at + 1) {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let unit = hex(at + 2).ok_or_else(invalid)?;
                return match unit {
                    0xD800..=0xDBFF => {
                        let low = (bytes.get(at + 6..at + 8) == Some(b"\\u"))
                            .then(|| hex(at + 8))
                            .flatten()
                            .filter(|low| (0xDC00..=0xDFFF).contains(low))
                            .ok_or_else(invalid)?;
                        let scalar = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                        char::from_u32(scalar)
                            .map(|character| (character, 12))
                            .ok_or_else(invalid)
                    }
                    0xDC00..=0xDFFF => Err(invalid()),
                    _ => char::from_u32(unit)
                        .map(|character| (character, 6))
                        .ok_or_else(invalid),
                };
            }
            _ => return Err(invalid()),
        };
        Ok((simple, 2))
    }

    /// Any JSON value inside `app`, `depth` containers deep: objects with no
    /// repeated key, nested at most [`MAX_APP_DEPTH`] deep, with at most
    /// [`MAX_APP_KEYS`] keys between them, counted in `keys`, and finite
    /// numbers. Strings are walked, not decoded, except for keys.
    fn app_value(&mut self, depth: usize, keys: &mut usize) -> Result<(), PayloadError> {
        match self.peek() {
            Some(b'{' | b'[') if depth > MAX_APP_DEPTH => Err(self.error(PayloadErrorKind::App)),
            Some(b'{') => {
                let mut seen = HashSet::new();
                self.object(MAX_APP_KEY_BYTES, |reader, key, at| {
                    *keys += 1;
                    if *keys > MAX_APP_KEYS || !key.is_some_and(|key| seen.insert(key)) {
                        return Err(reader.error_at(PayloadErrorKind::App, at));
                    }
                    reader.app_value(depth + 1, keys)
                })
            }
            Some(b'[') => self.list(|reader| reader.app_value(depth + 1, keys)),
            Some(b'"') => self.string_span(&mut (), PayloadErrorKind::App).map(|_| ()),
            Some(b't' | b'f') => self.flag().map(|_| ()),
            Some(b'n') => self.word("null"),
            Some(b'-' | b'0'..=b'9') => {
                let at = self.at;
                let token = self.number_token()?;
                if token.parse::<f64>().is_ok_and(f64::is_finite) {
                    Ok(())
                } else {
                    Err(self.error_at(PayloadErrorKind::App, at))
                }
            }
            _ => Err(self.error(PayloadErrorKind::Syntax)),
        }
    }

    /// Skips any JSON value, checking nothing but its syntax, without
    /// recursing however deep it nests.
    fn skip_value(&mut self) -> Result<(), PayloadError> {
        let mut open = Containers::default();
        loop {
            match self.peek() {
                Some(b'{') => {
                    self.at += 1;
                    if !self.take(b'}') {
                        open.push(Container::Object);
                        self.skip_key()?;
                        continue;
                    }
                }
                Some(b'[') => {
                    self.at += 1;
                    if !self.take(b']') {
                        open.push(Container::List);
                        continue;
                    }
                }
                Some(b'"') => {
                    self.string_span(&mut (), PayloadErrorKind::Syntax)?;
                }
                Some(b't') => self.word("true")?,
                Some(b'f') => self.word("false")?,
                Some(b'n') => self.word("null")?,
                Some(b'-' | b'0'..=b'9') => {
                    self.number_token()?;
                }
                _ => return Err(self.error(PayloadErrorKind::Syntax)),
            }
            loop {
                let Some(container) = open.innermost() else {
                    return Ok(());
                };
                let closer = match container {
                    Container::Object => b'}',
                    Container::List => b']',
                };
                if !self.take(closer) {
                    self.expect(b',')?;
                    if container == Container::Object {
                        self.skip_key()?;
                    }
                    break;
                }
                open.pop();
            }
        }
    }

    /// Skips an object's key and the colon after it.
    fn skip_key(&mut self) -> Result<(), PayloadError> {
        if self.peek() != Some(b'"') {
            return Err(self.error(PayloadErrorKind::Syntax));
        }
        self.string_span(&mut (), PayloadErrorKind::Syntax)?;
        self.expect(b':')
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Container {
    Object,
    List,
}

/// The containers a skipped value is inside, innermost last, kept a bit
/// each: a payload can nest one in each of its bytes.
#[derive(Default)]
struct Containers {
    objects: Vec<u64>,
    depth: usize,
}

impl Containers {
    fn push(&mut self, container: Container) {
        let (word, bit) = (self.depth / 64, self.depth % 64);
        if word == self.objects.len() {
            self.objects.push(0);
        }
        match container {
            Container::Object => self.objects[word] |= 1 << bit,
            Container::List => self.objects[word] &= !(1 << bit),
        }
        self.depth += 1;
    }

    fn innermost(&self) -> Option<Container> {
        let top = self.depth.checked_sub(1)?;
        Some(if self.objects[top / 64] >> (top % 64) & 1 == 1 {
            Container::Object
        } else {
            Container::List
        })
    }

    fn pop(&mut self) {
        self.depth -= 1;
    }
}

/// What a string's walk gives its parts to.
trait Sink<'a> {
    fn run(&mut self, _run: &'a str) {}
    fn escaped(&mut self, _character: char) {}
}

/// Checks a string without keeping any of it.
impl Sink<'_> for () {}

/// A string's length decoded, and whether it has escapes.
#[derive(Default)]
struct DecodedLength {
    bytes: usize,
    escaped: bool,
}

impl Sink<'_> for DecodedLength {
    fn run(&mut self, run: &str) {
        self.bytes += run.len();
    }

    fn escaped(&mut self, character: char) {
        self.bytes += character.len_utf8();
        self.escaped = true;
    }
}

/// Whether a string decodes to a variable name, judged as it's walked.
#[derive(Default)]
struct VariableNameShape {
    started: bool,
    invalid: bool,
}

impl VariableNameShape {
    fn push(&mut self, byte: u8) {
        self.invalid |= !is_variable_name_byte(byte, !self.started);
        self.started = true;
    }

    fn is_valid(&self) -> bool {
        self.started && !self.invalid
    }
}

impl Sink<'_> for VariableNameShape {
    fn run(&mut self, run: &str) {
        run.bytes().for_each(|byte| self.push(byte));
    }

    fn escaped(&mut self, character: char) {
        // Every character a name can hold is ASCII, so any other fails it.
        self.push(u8::try_from(character).unwrap_or(u8::MAX));
    }
}

/// A string's text, decoded.
struct Decoded(String);

impl<'a> Sink<'a> for Decoded {
    fn run(&mut self, run: &'a str) {
        self.0.push_str(run);
    }

    fn escaped(&mut self, character: char) {
        self.0.push(character);
    }
}

/// A string's length as serde_json writes it, from 2 for its quotes.
struct Measured(usize);

impl Sink<'_> for Measured {
    fn run(&mut self, run: &str) {
        self.0 += run.len();
    }

    fn escaped(&mut self, character: char) {
        self.0 += escaped_len(character);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid() -> serde_json::Value {
        json!({
            "createdAt": 1_761_171_075,
            "producer": {"name": "LPM Vault", "version": "1.4.0"},
            "deviceName": "Studio",
            "projects": [{
                "vaultId": "550e8400-e29b-41d4-a716-446655440000",
                "name": "demo-api",
                "folder": "/Users/me/Developer/demo-api",
                "hidden": false,
                "cliAccess": "requireApproval",
                "environments": {
                    "default": {"DATABASE_URL": "postgres://db/app", "EMPTY": ""},
                    "production": {"DATABASE_URL": "postgres://prod/app"}
                },
                "sync": {"registry": "https://lpm.dev", "scope": "personal", "principalId": "usr_1"}
            }, {
                "vaultId": "team-vault",
                "name": "shared",
                "hidden": true,
                "cliAccess": "automatic",
                "environments": {},
                "sync": {
                    "registry": "https://lpm.dev", "scope": "organization",
                    "principalId": "usr_1", "orgSlug": "acme"
                }
            }],
            "app": {"settings": {"appearance": "dark"}, "icons": []}
        })
    }

    fn check(value: &serde_json::Value) -> Result<(), PayloadError> {
        validate(&serde_json::to_vec(value).expect("encode"))
    }

    fn kind(value: &serde_json::Value) -> Option<PayloadErrorKind> {
        check(value).err().map(|error| error.kind)
    }

    #[test]
    fn a_complete_payload_and_a_minimal_one_are_valid() {
        assert_eq!(check(&valid()), Ok(()));
        let minimal = json!({
            "createdAt": 0,
            "producer": {"name": "lpm", "version": "0.81.0"},
            "projects": []
        });
        assert_eq!(check(&minimal), Ok(()));
        let nulls = json!({
            "createdAt": 0, "producer": {"name": "lpm", "version": "1"},
            "deviceName": null, "projects": [], "app": null
        });
        assert_eq!(check(&nulls), Ok(()));
    }

    #[test]
    fn unknown_missing_and_repeated_fields_are_structure_errors() {
        let mut unknown = valid();
        unknown["extra"] = json!(1);
        assert_eq!(kind(&unknown), Some(PayloadErrorKind::Structure));
        let mut project_unknown = valid();
        project_unknown["projects"][0]["path"] = json!("/x");
        assert_eq!(kind(&project_unknown), Some(PayloadErrorKind::Structure));
        let mut missing = valid();
        missing["projects"][0]
            .as_object_mut()
            .unwrap()
            .remove("cliAccess");
        assert_eq!(kind(&missing), Some(PayloadErrorKind::Structure));
        let repeated =
            br#"{"createdAt":0,"createdAt":1,"producer":{"name":"a","version":"1"},"projects":[]}"#;
        assert_eq!(
            validate(repeated).err().map(|error| error.kind),
            Some(PayloadErrorKind::Structure)
        );
        let mut access = valid();
        access["projects"][0]["cliAccess"] = json!("sometimes");
        assert_eq!(kind(&access), Some(PayloadErrorKind::Structure));
    }

    #[test]
    fn not_json_or_trailing_text_is_a_syntax_error_with_its_position() {
        let error = validate(b"{\"createdAt\":").expect_err("truncated");
        assert_eq!(error.kind, PayloadErrorKind::Syntax);
        assert_eq!(error.offset, 13);
        let trailing = [serde_json::to_vec(&valid()).unwrap(), b" {}".to_vec()].concat();
        assert_eq!(
            validate(&trailing).err().map(|error| error.kind),
            Some(PayloadErrorKind::Syntax)
        );
        assert_eq!(
            validate(b"[]").err().map(|error| error.kind),
            Some(PayloadErrorKind::Structure)
        );
        assert_eq!(
            validate(b"{\"createdAt\":0,\"producer\":{\"name\":\"\\ud800\",\"version\":\"1\"},\"projects\":[]}")
                .err()
                .map(|error| error.kind),
            Some(PayloadErrorKind::Syntax)
        );
    }

    #[test]
    fn repeated_environments_variables_and_vault_ids_are_refused() {
        let environment = br#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":[{"vaultId":"v","name":"n","hidden":false,"cliAccess":"automatic","environments":{"default":{},"default":{}}}]}"#;
        assert_eq!(
            validate(environment).err().map(|error| error.kind),
            Some(PayloadErrorKind::DuplicateEnvironment)
        );
        let variable = br#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":[{"vaultId":"v","name":"n","hidden":false,"cliAccess":"automatic","environments":{"default":{"A":"1","A":"2"}}}]}"#;
        assert_eq!(
            validate(variable).err().map(|error| error.kind),
            Some(PayloadErrorKind::DuplicateVariable)
        );
        let escaped = br#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":[{"vaultId":"v","name":"n","hidden":false,"cliAccess":"automatic","environments":{"default":{"A":"1","\u0041":"2"}}}]}"#;
        assert_eq!(
            validate(escaped).err().map(|error| error.kind),
            Some(PayloadErrorKind::DuplicateVariable)
        );
        let mut vault = valid();
        vault["projects"][1]["vaultId"] = vault["projects"][0]["vaultId"].clone();
        assert_eq!(kind(&vault), Some(PayloadErrorKind::DuplicateVaultId));
    }

    #[test]
    fn names_follow_the_clis_storage_rules() {
        for (path, value, expected) in [
            ("vaultId", json!("../escape"), PayloadErrorKind::VaultId),
            ("vaultId", json!("__index__"), PayloadErrorKind::VaultId),
        ] {
            let mut payload = valid();
            payload["projects"][0][path] = value;
            assert_eq!(kind(&payload), Some(expected), "{path}");
        }
        let mut environment = valid();
        environment["projects"][0]["environments"] = json!({"bad name": {}});
        assert_eq!(kind(&environment), Some(PayloadErrorKind::EnvironmentName));
        let mut index = valid();
        index["projects"][0]["environments"] = json!({"__index__": {}});
        assert_eq!(kind(&index), Some(PayloadErrorKind::EnvironmentName));
        let mut variable = valid();
        variable["projects"][0]["environments"] = json!({"default": {"1ABC": "x"}});
        assert_eq!(kind(&variable), Some(PayloadErrorKind::VariableName));
        let mut emoji = valid();
        emoji["projects"][0]["name"] = json!("🚀 mobile-app");
        assert_eq!(check(&emoji), Ok(()));
    }

    #[test]
    fn non_string_values_fail_without_quoting_them() {
        for value in [
            json!(12345),
            json!(true),
            json!(null),
            json!(["x"]),
            json!({"x": "y"}),
        ] {
            let mut payload = valid();
            payload["projects"][0]["environments"] = json!({"default": {"PIN": value}});
            assert_eq!(kind(&payload), Some(PayloadErrorKind::Value));
        }
        let mut misplaced = valid();
        misplaced["projects"][0]["environments"] = json!({"default": "sk_live_secret"});
        let error = check(&misplaced).expect_err("misplaced");
        assert_eq!(error.kind, PayloadErrorKind::Structure);
        assert!(!format!("{error:?}").contains("sk_live"));
    }

    #[test]
    fn a_project_is_measured_as_the_cli_stores_it() {
        let environments = json!({
            "default": {"A": "x\"y\\z\n\u{1}\u{7f}/", "B": "é🚀"},
            "staging": {},
            "preview.eu-1": {"C": ""}
        });
        let stored = serde_json::to_string(&json!({"environments": environments})).unwrap();
        let encoded = serde_json::to_string(&environments).unwrap();
        // Escapes the CLI wouldn't write are measured as the text they stand for.
        let respelled = encoded
            .replace('é', "\\u00e9")
            .replace('🚀', "\\ud83d\\ude80")
            .replace('/', "\\/");
        assert_ne!(respelled, encoded);
        for text in [encoded.as_str(), respelled.as_str()] {
            let mut reader = Reader { text, at: 0 };
            assert_eq!(
                read_environments(&mut reader).unwrap().0,
                stored.len(),
                "{text}"
            );
        }
    }

    #[test]
    fn a_project_over_the_store_limit_is_refused_and_one_at_it_is_kept() {
        let overhead = r#"{"environments":{"default":{"A":""}}}"#.len();
        let mut fits = valid();
        fits["projects"][0]["environments"] =
            json!({"default": {"A": "v".repeat(MAX_PROJECT_BYTES - overhead)}});
        assert_eq!(check(&fits), Ok(()));
        let mut over = valid();
        over["projects"][0]["environments"] =
            json!({"default": {"A": "v".repeat(MAX_PROJECT_BYTES - overhead + 1)}});
        assert_eq!(kind(&over), Some(PayloadErrorKind::ProjectTooLarge));
        let mut spread = valid();
        let half = "v".repeat(MAX_PROJECT_BYTES / 2);
        spread["projects"][0]["environments"] =
            json!({"default": {"A": half}, "staging": {"A": half}});
        assert_eq!(kind(&spread), Some(PayloadErrorKind::ProjectTooLarge));
    }

    #[test]
    fn more_than_ten_thousand_projects_are_refused_while_reading() {
        let project = |index: usize| {
            json!({
                "vaultId": format!("v{index}"), "name": "n", "hidden": false,
                "cliAccess": "automatic", "environments": {}
            })
        };
        let mut payload = valid();
        payload["projects"] = (0..MAX_PROJECTS).map(project).collect();
        assert_eq!(check(&payload), Ok(()));
        payload["projects"]
            .as_array_mut()
            .unwrap()
            .push(project(MAX_PROJECTS));
        assert_eq!(kind(&payload), Some(PayloadErrorKind::TooManyProjects));
    }

    #[test]
    fn sync_evidence_names_a_registry_principal_and_scope() {
        for sync in [
            json!({"registry": "ftp://lpm.dev", "scope": "personal", "principalId": "u"}),
            json!({"registry": "https://user@lpm.dev", "scope": "personal", "principalId": "u"}),
            json!({"registry": "https://lpm.dev/", "scope": "personal", "principalId": "u"}),
            json!({"registry": "https://lpm.dev?x", "scope": "personal", "principalId": "u"}),
            json!({"registry": "https://lpm.dev", "scope": "personal", "principalId": ""}),
            json!({"registry": "https://lpm.dev", "scope": "personal", "principalId": "u", "orgSlug": "acme"}),
            json!({"registry": "https://lpm.dev", "scope": "organization", "principalId": "u"}),
            json!({"registry": "https://lpm.dev", "scope": "organization", "principalId": "u", "orgSlug": "-x"}),
        ] {
            let mut payload = valid();
            payload["projects"][0]["sync"] = sync.clone();
            assert_eq!(kind(&payload), Some(PayloadErrorKind::Sync), "{sync}");
        }
        let mut team = valid();
        team["projects"][0]["sync"] = json!({"registry": "http://localhost:3000/registry", "scope": "personal", "principalId": "u"});
        assert_eq!(check(&team), Ok(()));
    }

    #[test]
    fn header_fields_are_bounded_and_app_must_be_an_object() {
        for (field, value, expected) in [
            (
                "createdAt",
                json!(MAX_CREATED_AT + 1),
                PayloadErrorKind::CreatedAt,
            ),
            ("createdAt", json!(-1), PayloadErrorKind::Structure),
            ("deviceName", json!(""), PayloadErrorKind::DeviceName),
            (
                "deviceName",
                json!("d".repeat(257)),
                PayloadErrorKind::DeviceName,
            ),
            (
                "producer",
                json!({"name": "", "version": "1"}),
                PayloadErrorKind::Producer,
            ),
            ("app", json!([]), PayloadErrorKind::App),
            ("app", json!("text"), PayloadErrorKind::App),
        ] {
            let mut payload = valid();
            payload[field] = value;
            assert_eq!(kind(&payload), Some(expected), "{field}");
        }
    }

    #[test]
    fn objects_and_enum_values_have_only_their_documented_spelling() {
        let positional = br#"[0,["lpm","1"],null,[],null]"#;
        assert_eq!(
            validate(positional).err().map(|error| error.kind),
            Some(PayloadErrorKind::Structure)
        );
        let positional_producer = br#"{"createdAt":0,"producer":["lpm","1"],"projects":[]}"#;
        assert_eq!(
            validate(positional_producer).err().map(|error| error.kind),
            Some(PayloadErrorKind::Structure)
        );
        for (path, value) in [
            (
                "projects",
                json!([["v", "n", null, false, "automatic", {}, null]]),
            ),
            (
                "projects",
                json!([{"vaultId": "v", "name": "n", "hidden": false,
                "cliAccess": {"automatic": null}, "environments": {}}]),
            ),
            (
                "projects",
                json!([{"vaultId": "v", "name": "n", "hidden": false,
                "cliAccess": "automatic", "environments": {},
                "sync": ["https://lpm.dev", "personal", "u", null]}]),
            ),
            (
                "projects",
                json!([{"vaultId": "v", "name": "n", "hidden": false,
                "cliAccess": "automatic", "environments": {},
                "sync": {"registry": "https://lpm.dev", "scope": {"personal": null}, "principalId": "u"}}]),
            ),
        ] {
            let mut payload = valid();
            payload[path] = value.clone();
            assert_eq!(kind(&payload), Some(PayloadErrorKind::Structure), "{value}");
        }
    }

    #[test]
    fn names_and_folders_the_cli_stores_are_kept_as_they_are() {
        for name in [
            "n".repeat(201),
            "tab\tname".to_owned(),
            " padded ".to_owned(),
        ] {
            let mut payload = valid();
            payload["projects"][0]["name"] = json!(name);
            assert_eq!(check(&payload), Ok(()), "{name:?}");
        }
        for folder in [
            "/Users/me/a\nb",
            "/Users/me/tab\there",
            "C:\\Users\\me\\project",
            "relative/path",
        ] {
            let mut payload = valid();
            payload["projects"][0]["folder"] = json!(folder);
            assert_eq!(check(&payload), Ok(()), "{folder:?}");
        }
    }

    #[test]
    fn a_project_whose_index_record_would_pass_the_store_limit_is_refused() {
        let many: serde_json::Map<String, serde_json::Value> = (0..4000)
            .map(|index| (format!("e{index:04}"), json!({})))
            .collect();
        let mut payload = valid();
        payload["projects"][0]["environments"] = serde_json::Value::Object(many);
        assert_eq!(kind(&payload), Some(PayloadErrorKind::ProjectTooLarge));
        let fits: serde_json::Map<String, serde_json::Value> = (0..2000)
            .map(|index| (format!("e{index:04}"), json!({})))
            .collect();
        payload["projects"][0]["environments"] = serde_json::Value::Object(fits);
        assert_eq!(check(&payload), Ok(()));
    }

    #[test]
    fn the_index_record_is_measured_as_the_cli_writes_it() {
        let project = json!({
            "vaultId": "550e8400-e29b-41d4-a716-446655440000", "name": "demo \"api\" ✓",
            "folder": "/Users/me/a\nb", "hidden": false, "cliAccess": "automatic",
            "environments": {"default": {"A": "1", "B": "2"}, "staging": {}, "preview.eu": {"C": ""}}
        });
        let text = serde_json::to_string(&project).unwrap();
        let (_, index_record_bytes) = read_project(&mut Reader { text: &text, at: 0 }).unwrap();
        let record = json!({
            "schemaVersion": 3,
            "storageId": "00000000-0000-4000-8000-000000000000",
            "id": project["vaultId"], "name": project["name"], "path": project["folder"],
            "discoveryShard": 1023,
            "environmentSummaries": [
                {"name": "default", "keyCount": 2}, {"name": "staging", "keyCount": 0},
                {"name": "preview.eu", "keyCount": 1}
            ]
        });
        assert_eq!(
            index_record_bytes,
            serde_json::to_string(&record).unwrap().len()
        );
    }

    #[test]
    fn registries_must_be_canonical_urls_as_the_cli_stores_them() {
        for registry in [
            "https://:",
            "https://[",
            "https://lpm.dev:bad",
            "https://LPM.dev",
            "https://lpm.dev:443",
            "https://lpm.dev/registry/",
            "https://lpm.dev/a b",
            "https://lpm.dev#x",
        ] {
            let mut payload = valid();
            payload["projects"][0]["sync"]["registry"] = json!(registry);
            assert_eq!(kind(&payload), Some(PayloadErrorKind::Sync), "{registry}");
        }
        for registry in [
            "https://lpm.dev",
            "http://localhost:3000",
            "http://localhost:3000/registry",
            "https://[::1]:8443",
        ] {
            let mut payload = valid();
            payload["projects"][0]["sync"]["registry"] = json!(registry);
            assert_eq!(check(&payload), Ok(()), "{registry}");
        }
    }

    const DIRECTION_CONTROLS: [char; 12] = [
        '\u{61C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
        '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ];

    #[test]
    fn labels_the_format_defines_refuse_direction_controls() {
        for control in DIRECTION_CONTROLS {
            let text = format!("safe{control}txt");
            let mut producer = valid();
            producer["producer"]["name"] = json!(text);
            assert_eq!(
                kind(&producer),
                Some(PayloadErrorKind::Producer),
                "{control:?}"
            );
            let mut version = valid();
            version["producer"]["version"] = json!(text);
            assert_eq!(
                kind(&version),
                Some(PayloadErrorKind::Producer),
                "{control:?}"
            );
            let mut device = valid();
            device["deviceName"] = json!(text);
            assert_eq!(
                kind(&device),
                Some(PayloadErrorKind::DeviceName),
                "{control:?}"
            );
            let mut principal = valid();
            principal["projects"][0]["sync"]["principalId"] = json!(text);
            assert_eq!(
                kind(&principal),
                Some(PayloadErrorKind::Sync),
                "{control:?}"
            );
            let mut registry = valid();
            registry["projects"][0]["sync"]["registry"] = json!(format!("https://lpm.dev/{text}"));
            assert_eq!(kind(&registry), Some(PayloadErrorKind::Sync), "{control:?}");
        }
        let mut emoji = valid();
        emoji["deviceName"] = json!("Studio \u{2764}\u{FE0F} \u{1F468}\u{200D}\u{1F4BB}");
        assert_eq!(check(&emoji), Ok(()));
    }

    #[test]
    fn stored_names_folders_and_vault_ids_keep_direction_controls() {
        let mut payload = valid();
        payload["projects"][0]["name"] = json!("safe\u{202E}txt");
        payload["projects"][0]["folder"] = json!("/Users/me/\u{2067}x\u{2069}");
        payload["projects"][0]["vaultId"] = json!("vault\u{202E}id");
        assert_eq!(check(&payload), Ok(()));
    }

    #[test]
    fn the_app_section_refuses_repeated_keys_deep_nesting_and_numbers_out_of_range() {
        let with_app = |app: &str| {
            format!(
                r#"{{"createdAt":0,"producer":{{"name":"a","version":"1"}},"projects":[],"app":{app}}}"#
            )
        };
        let app_kind = |app: &str| {
            validate(with_app(app).as_bytes())
                .err()
                .map(|error| error.kind)
        };
        for app in [
            r#"{"settings":1,"settings":2}"#,
            r#"{"a":{"b":1,"\u0062":2}}"#,
            r#"{"n":1e400}"#,
            r#"{"n":-1e400}"#,
        ] {
            assert_eq!(app_kind(app), Some(PayloadErrorKind::App), "{app}");
        }
        assert_eq!(
            app_kind(r#"{"s":"\ud800"}"#),
            Some(PayloadErrorKind::Syntax)
        );
        let nested = |depth: usize| format!("{}{}", "[".repeat(depth - 1), "]".repeat(depth - 1));
        let deepest = format!(r#"{{"x":{}}}"#, nested(MAX_APP_DEPTH));
        assert_eq!(app_kind(&deepest), None);
        let too_deep = format!(r#"{{"x":{}}}"#, nested(MAX_APP_DEPTH + 1));
        assert_eq!(app_kind(&too_deep), Some(PayloadErrorKind::App));
        let ordinary = r#"{"settings":{"appearance":"dark","n":12345678901234567890,"f":-0.5e3},"list":[true,null,"s"]}"#;
        assert_eq!(app_kind(ordinary), None);
    }

    #[test]
    fn the_reader_accepts_exactly_the_json_serde_json_does() {
        let corpus = [
            r#"{}"#,
            r#" { "a" : [ 1 , 2 ] , "b" : { } } "#,
            r#"{"a":-0,"b":0.5e-3,"c":1E+2,"d":12345678901234567890,"e":-1.25E-7}"#,
            r#"{"a":true,"b":false,"c":null}"#,
            r#"{"a":"\u00e9\ud83d\ude80\/\b\f\n\r\t\"\\"}"#,
            "{\"a\":\"\u{7f}\u{e9}\"}",
            r#"{"a":01}"#,
            r#"{"a":1.}"#,
            r#"{"a":.5}"#,
            r#"{"a":+1}"#,
            r#"{"a":1e}"#,
            r#"{"a":-}"#,
            r#"{"a":"\x"}"#,
            r#"{"a":"\u12"}"#,
            r#"{"a":"\ud800\u0041"}"#,
            r#"{"a":"\udc00"}"#,
            r#"{"a":[1,]}"#,
            r#"{"a":1,}"#,
            r#"{a:1}"#,
            r#"{"a":tru}"#,
            r#"{"a":nul}"#,
            r#"{"a":"x"#,
            "{\"a\":\"raw\ttab\"}",
            r#"{"a":Infinity}"#,
            r#"{"a":NaN}"#,
            r#"{"a" 1}"#,
            r#"{"a":1 "b":2}"#,
            "{\"a\":1}\u{feff}",
        ];
        let with_app = |app: &str| {
            format!(
                r#"{{"createdAt":0,"producer":{{"name":"a","version":"1"}},"projects":[],"app":{app}}}"#
            )
        };
        for app in corpus {
            let payload = with_app(app);
            let serde_accepts = serde_json::from_str::<serde_json::Value>(&payload).is_ok();
            assert_eq!(validate(payload.as_bytes()).is_ok(), serde_accepts, "{app}");

            let listed = with_app(&format!("[{app}]"));
            let serde_accepts = serde_json::from_str::<serde_json::Value>(&listed).is_ok();
            let expected = if serde_accepts {
                PayloadErrorKind::App
            } else {
                PayloadErrorKind::Syntax
            };
            assert_eq!(
                validate(listed.as_bytes()).err().map(|error| error.kind),
                Some(expected),
                "[{app}]"
            );
        }
    }

    #[test]
    fn empty_environments_are_measured_as_the_cli_stores_its_default_one() {
        let mut reader = Reader { text: "{}", at: 0 };
        let (stored, summaries) = read_environments(&mut reader).unwrap();
        assert_eq!(stored, r#"{"environments":{"default":{}}}"#.len());
        assert_eq!(summaries, r#"{"name":"default","keyCount":0}"#.len());

        let fixed = r#"{"schemaVersion":3,"storageId":"00000000-0000-4000-8000-000000000000","id":"v","name":"","path":"","discoveryShard":1023,"environmentSummaries":[{"name":"default","keyCount":0}]}"#.len();
        let project = |name_len: usize| {
            json!({
                "createdAt": 0, "producer": {"name": "a", "version": "1"},
                "projects": [{
                    "vaultId": "v", "name": "n".repeat(name_len), "hidden": false,
                    "cliAccess": "automatic", "environments": {}
                }]
            })
        };
        assert_eq!(check(&project(MAX_PROJECT_BYTES - fixed)), Ok(()));
        assert_eq!(
            kind(&project(MAX_PROJECT_BYTES - fixed + 1)),
            Some(PayloadErrorKind::ProjectTooLarge)
        );
    }

    #[test]
    fn numbers_that_round_to_the_largest_double_are_finite() {
        for number in [
            "1.7976931348623158e308",
            "-1.7976931348623158e308",
            "17976931348623158e292",
        ] {
            let payload = format!(
                r#"{{"createdAt":0,"producer":{{"name":"a","version":"1"}},"projects":[],"app":{{"n":{number}}}}}"#
            );
            assert_eq!(validate(payload.as_bytes()), Ok(()), "{number}");
            assert!(serde_json::from_str::<serde::de::IgnoredAny>(&payload).is_ok());
        }
        for number in ["1.7976931348623159e308", "1e309", "-1e309"] {
            let payload = format!(
                r#"{{"createdAt":0,"producer":{{"name":"a","version":"1"}},"projects":[],"app":{{"n":{number}}}}}"#
            );
            let error = validate(payload.as_bytes()).expect_err(number);
            assert_eq!(error.kind, PayloadErrorKind::App, "{number}");
        }
    }

    #[test]
    fn malformed_json_inside_app_is_a_syntax_error_at_its_offset() {
        let head = r#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":[],"app":"#;
        for (app, offset) in [
            (r#"{"x":}"#, 5),
            (r#"{"x":1,}"#, 7),
            (r#"{"x":"\x"}"#, 6),
            (r#"{"x":[1 2]}"#, 8),
            (r#"{"x":tru}"#, 5),
            (r#"{"x":"#, 5),
        ] {
            let payload = format!("{head}{app}}}");
            let error = validate(payload.as_bytes()).expect_err(app);
            assert_eq!(
                (error.kind, error.offset),
                (PayloadErrorKind::Syntax, head.len() + offset),
                "{app}"
            );
        }
    }

    #[test]
    fn app_is_a_syntax_error_when_no_json_value_follows_and_an_app_error_when_one_isnt_an_object() {
        let head = r#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":[],"app":"#;
        for (app, kind, offset) in [
            ("@}", PayloadErrorKind::Syntax, 0),
            (" @}", PayloadErrorKind::Syntax, 1),
            ("}", PayloadErrorKind::Syntax, 0),
            ("", PayloadErrorKind::Syntax, 0),
            ("tru}", PayloadErrorKind::Syntax, 0),
            ("[1 2]}", PayloadErrorKind::Syntax, 3),
            ("[1]}", PayloadErrorKind::App, 0),
            (" [1]}", PayloadErrorKind::App, 1),
            (r#""x"}"#, PayloadErrorKind::App, 0),
            ("1}", PayloadErrorKind::App, 0),
            ("true}", PayloadErrorKind::App, 0),
        ] {
            let payload = format!("{head}{app}");
            let error = validate(payload.as_bytes()).expect_err(app);
            assert_eq!(
                (error.kind, error.offset),
                (kind, head.len() + offset),
                "{app:?}"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_string_over_its_limit_is_refused_before_it_is_decoded() {
        use crate::freed_memory_probe::largest_allocation;
        use PayloadErrorKind::*;
        // Each escape is six bytes that decode to one.
        let long = "\\u0061".repeat(120_000);
        let head = r#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":"#;
        let project = |vault_id: &str, name: &str, fields: &str| {
            format!(
                r#"{head}[{{"vaultId":"{vault_id}","name":"{name}","hidden":false,"cliAccess":"automatic",{fields}}}]}}"#
            )
        };
        let sync = |registry: &str, principal: &str, org: &str| {
            project(
                "v",
                "n",
                &format!(
                    r#""environments":{{}},"sync":{{"registry":"{registry}","scope":"organization","principalId":"{principal}","orgSlug":"{org}"}}"#
                ),
            )
        };
        let cases = [
            (format!(r#"{{"{long}":0}}"#), Structure),
            (
                format!(
                    r#"{{"createdAt":0,"producer":{{"name":"{long}","version":"1"}},"projects":[]}}"#
                ),
                Producer,
            ),
            (
                format!(
                    r#"{{"createdAt":0,"producer":{{"name":"a","version":"1"}},"deviceName":"{long}","projects":[]}}"#
                ),
                DeviceName,
            ),
            (format!(r#"{head}[],"app":{{"{long}":0}}}}"#), App),
            (project(&long, "n", r#""environments":{}"#), VaultId),
            (project("v", &long, r#""environments":{}"#), ProjectTooLarge),
            (
                project(
                    "v",
                    "n",
                    &format!(r#""folder":"{long}","environments":{{}}"#),
                ),
                ProjectTooLarge,
            ),
            (
                project("v", "n", &format!(r#""environments":{{"{long}":{{}}}}"#)),
                EnvironmentName,
            ),
            (
                project(
                    "v",
                    "n",
                    &format!(r#""environments":{{"default":{{"{long}":""}}}}"#),
                ),
                ProjectTooLarge,
            ),
            (sync(&long, "u", "acme"), Sync),
            (sync("https://lpm.dev", &long, "acme"), Sync),
            (sync("https://lpm.dev", "u", &long), Sync),
        ];
        assert_eq!(
            validate(sync("https://lpm.dev", "u", "acme").as_bytes()),
            Ok(())
        );
        for (payload, expected) in cases {
            let mut result = Ok(());
            let largest = largest_allocation(|| result = validate(payload.as_bytes()));
            assert_eq!(result.map_err(|error| error.kind), Err(expected));
            assert!(
                largest < 64 * 1024,
                "{expected:?} allocated {largest} bytes before refusing"
            );
        }
    }

    /// Where `needle` first starts in `haystack`.
    fn offset_of(haystack: &str, needle: &str) -> usize {
        haystack.find(needle).expect("the needle is in the payload")
    }

    /// `key` with its first character written as a `\u` escape.
    fn escaping_first(key: &str) -> String {
        let first = key.chars().next().expect("a key");
        format!("\\u{:04x}{}", u32::from(first), &key[first.len_utf8()..])
    }

    #[test]
    fn an_oversized_key_fails_as_it_would_have_once_decoded() {
        let head = r#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":[{"vaultId":"v","name":"n","hidden":false,"cliAccess":"automatic","environments":{"default":{"#;
        let long =
            |first: &str, last: &str| format!("{first}{}{last}", "a".repeat(MAX_PROJECT_BYTES - 1));
        let variable = |key: &str, value: &str| format!(r#"{head}"{key}":{value}}}}}}}]}}"#);
        for (key, value, kind, at_value) in [
            (
                long("1", "a"),
                r#""v""#,
                PayloadErrorKind::VariableName,
                false,
            ),
            (
                long("a", "-"),
                r#""v""#,
                PayloadErrorKind::VariableName,
                false,
            ),
            (
                long("a", r"é"),
                r#""v""#,
                PayloadErrorKind::VariableName,
                false,
            ),
            (
                long("a", r"\n"),
                r#""v""#,
                PayloadErrorKind::VariableName,
                false,
            ),
            (long("a", "a"), "null", PayloadErrorKind::Value, true),
            (long("a", "a"), "@", PayloadErrorKind::Syntax, true),
            (
                long("a", "a"),
                r#""v""#,
                PayloadErrorKind::ProjectTooLarge,
                false,
            ),
            (
                long("a", r"_"),
                r#""v""#,
                PayloadErrorKind::ProjectTooLarge,
                false,
            ),
        ] {
            for key in [escaping_first(&key), key] {
                let payload = variable(&key, value);
                let error = validate(payload.as_bytes()).expect_err(value);
                let expected = if at_value {
                    offset_of(&payload, &format!(":{value}")) + 1
                } else {
                    head.len()
                };
                assert_eq!(
                    (error.kind, error.offset),
                    (kind, expected),
                    "{}…{} then {value}",
                    &key[..6],
                    &key[key.len() - 6..]
                );
            }
        }
        let unterminated = variable(&long("a", "a"), r#""v"#);
        assert_eq!(
            validate(unterminated.as_bytes())
                .err()
                .map(|error| error.kind),
            Some(PayloadErrorKind::Syntax)
        );

        let app_head =
            r#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":[],"app":{"#;
        let environment_head = &head[..head.len() - r#""default":{"#.len()];
        for (head, key) in [
            ("{", "a".repeat(65)),
            (environment_head, "a".repeat(65)),
            (head, long("a", "a")),
            (app_head, "a".repeat(MAX_APP_KEY_BYTES + 1)),
        ] {
            for key in [escaping_first(&key), key] {
                let payload = format!(r#"{head}"{key}" 0}}"#);
                let error = validate(payload.as_bytes()).expect_err("missing colon");
                assert_eq!(
                    (error.kind, error.offset),
                    (PayloadErrorKind::Syntax, head.len() + key.len() + 3),
                    "{head}"
                );
            }
        }
    }

    #[test]
    fn a_non_object_app_fails_at_its_start_unless_its_json_is_malformed() {
        let head = r#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":[],"app":"#;
        let long_key = "k".repeat(MAX_APP_KEY_BYTES + 1);
        let too_deep = format!(
            "{}{}",
            "[".repeat(MAX_APP_DEPTH + 1),
            "]".repeat(MAX_APP_DEPTH + 1)
        );
        for app in [
            r#"[ {"a":0,"a":1}]}"#.to_owned(),
            format!(r#"[{{"{long_key}":0}}]}}"#),
            format!("{too_deep}}}"),
            "[1e400]}".to_owned(),
            "1e400}".to_owned(),
            r#""text" }"#.to_owned(),
            "true}".to_owned(),
            r#"[{"a":[{"b":{}},[]]}],"deviceName":null}"#.to_owned(),
        ] {
            let error = validate(format!("{head}{app}").as_bytes()).expect_err(&app);
            assert_eq!(
                (error.kind, error.offset),
                (PayloadErrorKind::App, head.len()),
                "{app}"
            );
        }
        for (app, suffix) in [
            ("trueX}", "X"),
            ("falseX}", "X"),
            ("1x}", "x"),
            (r#""x"y}"#, "y"),
            ("[{}]x}", "x"),
            ("[1] z}", "z"),
            ("[1,]}", "]}"),
            ("[}", "}"),
            (r#"[{"a" 1}]}"#, "1}"),
            ("[{1:2}]}", "1:"),
            (r#"[{"a":1,}]}"#, "}]"),
            ("[", ""),
        ] {
            let payload = format!("{head}{app}");
            let error = validate(payload.as_bytes()).expect_err(app);
            let expected = if suffix.is_empty() {
                payload.len()
            } else {
                head.len() + offset_of(app, suffix)
            };
            assert_eq!(
                (error.kind, error.offset),
                (PayloadErrorKind::Syntax, expected),
                "{app}"
            );
        }
    }

    #[test]
    fn a_non_object_app_is_read_through_however_deep_it_nests() {
        let head = r#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":[],"app":"#;
        let depth = 1_000_000;
        let nested = format!("{head}{}{}}}", "[".repeat(depth), "]".repeat(depth));
        let error = validate(nested.as_bytes()).expect_err("a list");
        assert_eq!(
            (error.kind, error.offset),
            (PayloadErrorKind::App, head.len())
        );
        let mut unbalanced = nested.into_bytes();
        let middle = head.len() + depth + depth / 2;
        unbalanced[middle] = b'}';
        let error = validate(&unbalanced).expect_err("unbalanced");
        assert_eq!(
            (error.kind, error.offset),
            (PayloadErrorKind::Syntax, middle)
        );

        // Objects and lists alternate past several words of the stack that
        // tracks them, so a closer of the wrong kind at any depth is caught.
        let levels = 150;
        let opening = r#"[{"k":"#.repeat(levels);
        let closing = "}]".repeat(levels);
        let mixed = format!("{head}{opening}0{closing}}}");
        let error = validate(mixed.as_bytes()).expect_err("mixed");
        assert_eq!(
            (error.kind, error.offset),
            (PayloadErrorKind::App, head.len())
        );
        for swapped in [0, 63, 64, 65, 127, 128, 2 * levels - 1] {
            let mut wrong = mixed.clone().into_bytes();
            let at = head.len() + opening.len() + 1 + swapped;
            wrong[at] = if wrong[at] == b'}' { b']' } else { b'}' };
            let error = validate(&wrong).expect_err("a wrong closer");
            assert_eq!(
                (error.kind, error.offset),
                (PayloadErrorKind::Syntax, at),
                "closer {swapped}"
            );
        }
    }

    #[test]
    fn the_app_section_is_held_to_a_key_budget_however_its_keys_are_spread() {
        let with_app = |app: &str| {
            format!(
                r#"{{"createdAt":0,"producer":{{"name":"a","version":"1"}},"projects":[],"app":{app}}}"#
            )
        };
        let wide = |count: usize| {
            let members: Vec<String> = (0..count).map(|key| format!(r#""{key}":0"#)).collect();
            format!("{{{}}}", members.join(","))
        };
        // `app` is itself an object, so its own keys count.
        assert_eq!(validate(with_app(&wide(MAX_APP_KEYS)).as_bytes()), Ok(()));
        let over = validate(with_app(&wide(MAX_APP_KEYS + 1)).as_bytes()).expect_err("over");
        assert_eq!(over.kind, PayloadErrorKind::App);
        let half = wide(MAX_APP_KEYS / 2);
        let spread = format!(r#"{{"a":{half},"b":{half}}}"#);
        assert_eq!(
            validate(with_app(&spread).as_bytes())
                .err()
                .map(|error| error.kind),
            Some(PayloadErrorKind::App)
        );
        let longest = format!(r#"{{"{}":0}}"#, "k".repeat(MAX_APP_KEY_BYTES));
        assert_eq!(validate(with_app(&longest).as_bytes()), Ok(()));
        let too_long = format!(r#"{{"{}":0}}"#, "k".repeat(MAX_APP_KEY_BYTES + 1));
        assert_eq!(
            validate(with_app(&too_long).as_bytes())
                .err()
                .map(|error| error.kind),
            Some(PayloadErrorKind::App)
        );
    }

    #[test]
    fn every_error_code_is_distinct() {
        use PayloadErrorKind::*;
        let kinds = [
            Syntax,
            Structure,
            CreatedAt,
            Producer,
            DeviceName,
            TooManyProjects,
            VaultId,
            DuplicateVaultId,
            EnvironmentName,
            DuplicateEnvironment,
            VariableName,
            DuplicateVariable,
            Value,
            ProjectTooLarge,
            Sync,
            App,
        ];
        let codes: HashSet<_> = kinds.iter().map(|kind| kind.code()).collect();
        assert_eq!(codes.len(), kinds.len());
    }
}
