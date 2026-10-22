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
//! goes with the `organization` scope only. `app` is an object the app that
//! wrote the backup owns; it's checked here only as JSON. Every other object
//! refuses unknown and repeated fields.
//!
//! Values are read once, in place, to check them and measure them, and never
//! copied. Errors carry a code and a position, never the text they're about.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;

use lpm_common::stored_env::{
    is_safe_vault_id, is_valid_environment_name, is_valid_org_slug, is_valid_variable_name,
};
use serde::Deserialize;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;

/// The most projects a backup holds.
pub const MAX_PROJECTS: usize = 10_000;
/// The most a project's environments take as the CLI stores them, as
/// `{"environments":{…}}`: the credential store's limit on one item.
pub const MAX_PROJECT_BYTES: usize = 100 * 1024;
/// The latest `createdAt`: the last second of 9999.
const MAX_CREATED_AT: u64 = 253_402_300_799;
const MAX_LABEL_BYTES: usize = 64;
const MAX_DEVICE_NAME_BYTES: usize = 256;
const MAX_PROJECT_NAME_UTF16: usize = 200;
const MAX_FOLDER_BYTES: usize = 4096;
const MAX_REGISTRY_BYTES: usize = 2048;
const MAX_PRINCIPAL_BYTES: usize = 256;

/// Why a payload isn't a valid backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadError {
    pub kind: PayloadErrorKind,
    /// The 1-based line and column the JSON reader had reached.
    pub position: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadErrorKind {
    /// Not JSON, or not one JSON object.
    Syntax,
    /// A field is missing, unknown, repeated, or of the wrong type.
    Structure,
    CreatedAt,
    Producer,
    DeviceName,
    TooManyProjects,
    VaultId,
    DuplicateVaultId,
    ProjectName,
    Folder,
    EnvironmentName,
    DuplicateEnvironment,
    VariableName,
    DuplicateVariable,
    /// A value that isn't a string.
    Value,
    /// A project's environments over [`MAX_PROJECT_BYTES`].
    ProjectTooLarge,
    Sync,
    /// `app` isn't an object.
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
            Self::ProjectName => "project_name",
            Self::Folder => "folder",
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

    const ALL: [Self; 18] = [
        Self::Syntax,
        Self::Structure,
        Self::CreatedAt,
        Self::Producer,
        Self::DeviceName,
        Self::TooManyProjects,
        Self::VaultId,
        Self::DuplicateVaultId,
        Self::ProjectName,
        Self::Folder,
        Self::EnvironmentName,
        Self::DuplicateEnvironment,
        Self::VariableName,
        Self::DuplicateVariable,
        Self::Value,
        Self::ProjectTooLarge,
        Self::Sync,
        Self::App,
    ];
}

/// The message a check gives serde: a marker and the code, which
/// [`PayloadError::from_json`] finds again. It never holds the text it's
/// about, as serde's own type errors would.
struct Rejection(PayloadErrorKind);

const REJECTION_MARKER: &str = "lpm-env-backup:";

impl fmt::Display for Rejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{REJECTION_MARKER}{}", self.0.code())
    }
}

fn reject<E: de::Error>(kind: PayloadErrorKind) -> E {
    E::custom(Rejection(kind))
}

impl PayloadError {
    fn whole(kind: PayloadErrorKind) -> Self {
        Self {
            kind,
            position: None,
        }
    }

    fn from_json(error: &serde_json::Error) -> Self {
        let message = error.to_string();
        let kind = message
            .strip_prefix(REJECTION_MARKER)
            .and_then(|rest| {
                let code = rest.split(' ').next().unwrap_or_default();
                PayloadErrorKind::ALL
                    .into_iter()
                    .find(|kind| kind.code() == code)
            })
            .unwrap_or(match error.classify() {
                serde_json::error::Category::Data => PayloadErrorKind::Structure,
                _ => PayloadErrorKind::Syntax,
            });
        Self {
            kind,
            position: (error.line() > 0).then(|| (error.line(), error.column())),
        }
    }
}

/// Checks that `payload` is a valid version 1 backup.
pub fn validate(payload: &[u8]) -> Result<(), PayloadError> {
    let backup: Backup<'_> =
        serde_json::from_slice(payload).map_err(|error| PayloadError::from_json(&error))?;
    backup.check()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Backup<'a> {
    created_at: u64,
    #[serde(borrow)]
    producer: Producer<'a>,
    #[serde(borrow, default)]
    device_name: Option<Cow<'a, str>>,
    #[serde(rename = "projects")]
    _projects: Projects,
    #[serde(borrow, default)]
    app: Option<&'a RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Producer<'a> {
    #[serde(borrow)]
    name: Cow<'a, str>,
    #[serde(borrow)]
    version: Cow<'a, str>,
}

impl Backup<'_> {
    fn check(&self) -> Result<(), PayloadError> {
        if self.created_at > MAX_CREATED_AT {
            return Err(PayloadError::whole(PayloadErrorKind::CreatedAt));
        }
        if !is_label(&self.producer.name, MAX_LABEL_BYTES)
            || !is_label(&self.producer.version, MAX_LABEL_BYTES)
        {
            return Err(PayloadError::whole(PayloadErrorKind::Producer));
        }
        if self
            .device_name
            .as_deref()
            .is_some_and(|name| !is_label(name, MAX_DEVICE_NAME_BYTES))
        {
            return Err(PayloadError::whole(PayloadErrorKind::DeviceName));
        }
        if self.app.is_some_and(|app| !app.get().starts_with('{')) {
            return Err(PayloadError::whole(PayloadErrorKind::App));
        }
        Ok(())
    }
}

/// Text shown to people: non-empty, bounded, and without control characters.
fn is_label(text: &str, max_bytes: usize) -> bool {
    !text.is_empty() && text.len() <= max_bytes && !text.chars().any(char::is_control)
}

/// The projects, checked as they're read so a payload can't make the reader
/// hold more than [`MAX_PROJECTS`] of them, with each vault ID once.
struct Projects;

impl<'de> Deserialize<'de> for Projects {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(ProjectsVisitor)
    }
}

struct ProjectsVisitor;

impl<'de> Visitor<'de> for ProjectsVisitor {
    type Value = Projects;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a list of projects")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut projects: A) -> Result<Projects, A::Error> {
        let mut vault_ids = HashSet::new();
        while let Some(project) = projects.next_element::<Project<'de>>()? {
            if vault_ids.len() == MAX_PROJECTS {
                return Err(reject(PayloadErrorKind::TooManyProjects));
            }
            project.check()?;
            if !vault_ids.insert(project.vault_id) {
                return Err(reject(PayloadErrorKind::DuplicateVaultId));
            }
        }
        Ok(Projects)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Project<'a> {
    #[serde(borrow)]
    vault_id: Cow<'a, str>,
    #[serde(borrow)]
    name: Cow<'a, str>,
    #[serde(borrow, default)]
    folder: Option<Cow<'a, str>>,
    #[serde(rename = "hidden")]
    _hidden: bool,
    #[serde(rename = "cliAccess")]
    _cli_access: CliAccess,
    environments: Environments,
    #[serde(borrow, default)]
    sync: Option<Sync<'a>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum CliAccess {
    Automatic,
    RequireApproval,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Sync<'a> {
    #[serde(borrow)]
    registry: Cow<'a, str>,
    scope: SyncScope,
    #[serde(borrow)]
    principal_id: Cow<'a, str>,
    #[serde(borrow, default)]
    org_slug: Option<Cow<'a, str>>,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum SyncScope {
    Personal,
    Organization,
}

impl Project<'_> {
    fn check<E: de::Error>(&self) -> Result<(), E> {
        if !is_safe_vault_id(&self.vault_id) {
            return Err(reject(PayloadErrorKind::VaultId));
        }
        if self.name.is_empty()
            || self.name.encode_utf16().count() > MAX_PROJECT_NAME_UTF16
            || self.name.chars().any(char::is_control)
        {
            return Err(reject(PayloadErrorKind::ProjectName));
        }
        if self.folder.as_deref().is_some_and(|folder| {
            !folder.starts_with('/')
                || folder.len() > MAX_FOLDER_BYTES
                || folder.chars().any(char::is_control)
        }) {
            return Err(reject(PayloadErrorKind::Folder));
        }
        if self.environments.stored_bytes > MAX_PROJECT_BYTES {
            return Err(reject(PayloadErrorKind::ProjectTooLarge));
        }
        if self.sync.as_ref().is_some_and(|sync| !sync.is_valid()) {
            return Err(reject(PayloadErrorKind::Sync));
        }
        Ok(())
    }
}

impl Sync<'_> {
    fn is_valid(&self) -> bool {
        let registry = &self.registry;
        let after_scheme = registry
            .strip_prefix("https://")
            .or_else(|| registry.strip_prefix("http://"));
        let well_formed_registry = registry.len() <= MAX_REGISTRY_BYTES
            && after_scheme.is_some_and(|rest| {
                !rest.is_empty()
                    && !rest.starts_with('/')
                    && !rest.ends_with('/')
                    && !rest.chars().any(|character| {
                        character.is_control()
                            || character.is_whitespace()
                            || matches!(character, '?' | '#' | '@' | '\\')
                    })
            });
        let org_matches_scope = match self.scope {
            SyncScope::Personal => self.org_slug.is_none(),
            SyncScope::Organization => self.org_slug.as_deref().is_some_and(is_valid_org_slug),
        };
        well_formed_registry
            && is_label(&self.principal_id, MAX_PRINCIPAL_BYTES)
            && org_matches_scope
    }
}

/// A project's environments, read for their names and for the size the CLI
/// stores them at, without keeping a value.
struct Environments {
    stored_bytes: usize,
}

/// `{"environments":{}}`, around the entries.
const STORED_ENVELOPE_BYTES: usize = r#"{"environments":{}}"#.len();

// The visitors below read with `deserialize_any`, so a value of the wrong
// type reaches them: serde_json's own message for it would quote the text.
impl<'de> Deserialize<'de> for Environments {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(EnvironmentsVisitor)
    }
}

/// Fails every JSON type a visitor doesn't take, without describing the
/// value, which serde's default messages would quote.
macro_rules! refuse_other_types {
    ($kind:expr) => {
        fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Err(reject($kind))
        }
        fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Err(reject($kind))
        }
        fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Err(reject($kind))
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Err(reject($kind))
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Err(reject($kind))
        }
        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Err(reject($kind))
        }
    };
}

macro_rules! refuse_strings_and_lists {
    ($kind:expr) => {
        fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
            Err(reject($kind))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
            Err(reject($kind))
        }
    };
}

struct EnvironmentsVisitor;

impl<'de> Visitor<'de> for EnvironmentsVisitor {
    type Value = Environments;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("environments")
    }

    refuse_other_types!(PayloadErrorKind::Structure);
    refuse_strings_and_lists!(PayloadErrorKind::Structure);

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Environments, A::Error> {
        let mut names = HashSet::new();
        let mut stored_bytes = STORED_ENVELOPE_BYTES;
        while let Some(Name(name)) =
            map.next_key_seed(NameSeed(PayloadErrorKind::EnvironmentName))?
        {
            if !is_valid_environment_name(&name) {
                return Err(reject(PayloadErrorKind::EnvironmentName));
            }
            let variables = map.next_value_seed(VariablesSeed)?;
            stored_bytes += usize::from(!names.is_empty()) + quoted_len(&name) + 1 + variables;
            if stored_bytes > MAX_PROJECT_BYTES {
                return Err(reject(PayloadErrorKind::ProjectTooLarge));
            }
            if !names.insert(name) {
                return Err(reject(PayloadErrorKind::DuplicateEnvironment));
            }
        }
        Ok(Environments { stored_bytes })
    }
}

/// One environment's variables; reads as the bytes `{…}` takes when stored.
struct VariablesSeed;

impl<'de> DeserializeSeed<'de> for VariablesSeed {
    type Value = usize;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<usize, D::Error> {
        deserializer.deserialize_any(VariablesVisitor)
    }
}

struct VariablesVisitor;

impl<'de> Visitor<'de> for VariablesVisitor {
    type Value = usize;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("variables")
    }

    refuse_other_types!(PayloadErrorKind::Structure);
    refuse_strings_and_lists!(PayloadErrorKind::Structure);

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<usize, A::Error> {
        let mut names = HashSet::new();
        let mut stored_bytes = 2;
        while let Some(Name(name)) = map.next_key_seed(NameSeed(PayloadErrorKind::VariableName))? {
            if !is_valid_variable_name(&name) {
                return Err(reject(PayloadErrorKind::VariableName));
            }
            let value = map.next_value_seed(ValueSeed)?;
            stored_bytes += usize::from(!names.is_empty()) + quoted_len(&name) + 1 + value;
            if stored_bytes > MAX_PROJECT_BYTES {
                return Err(reject(PayloadErrorKind::ProjectTooLarge));
            }
            if !names.insert(name) {
                return Err(reject(PayloadErrorKind::DuplicateVariable));
            }
        }
        Ok(stored_bytes)
    }
}

/// A value; reads as its length quoted as the CLI stores it, so it's
/// measured where it lies and never copied.
struct ValueSeed;

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = usize;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<usize, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = usize;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string value")
    }

    refuse_other_types!(PayloadErrorKind::Value);

    fn visit_str<E: de::Error>(self, value: &str) -> Result<usize, E> {
        Ok(quoted_len(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, _: A) -> Result<usize, A::Error> {
        Err(reject(PayloadErrorKind::Value))
    }

    fn visit_map<A: MapAccess<'de>>(self, _: A) -> Result<usize, A::Error> {
        Err(reject(PayloadErrorKind::Value))
    }
}

/// A map key, borrowed from the payload where it has no escapes.
struct Name<'de>(Cow<'de, str>);

struct NameSeed(PayloadErrorKind);

impl<'de> DeserializeSeed<'de> for NameSeed {
    type Value = Name<'de>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Name<'de>, D::Error> {
        deserializer.deserialize_str(NameVisitor(self.0))
    }
}

struct NameVisitor(PayloadErrorKind);

impl<'de> Visitor<'de> for NameVisitor {
    type Value = Name<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a name")
    }

    fn visit_borrowed_str<E: de::Error>(self, name: &'de str) -> Result<Name<'de>, E> {
        Ok(Name(Cow::Borrowed(name)))
    }

    fn visit_str<E: de::Error>(self, name: &str) -> Result<Name<'de>, E> {
        Ok(Name(Cow::Owned(name.to_owned())))
    }

    fn visit_bytes<E: de::Error>(self, _: &[u8]) -> Result<Name<'de>, E> {
        Err(reject(self.0))
    }
}

/// The length of `text` as serde_json writes it in quotes, which is how the
/// CLI stores values.
fn quoted_len(text: &str) -> usize {
    2 + text
        .bytes()
        .map(|byte| match byte {
            b'"' | b'\\' | b'\x08' | b'\x0c' | b'\n' | b'\r' | b'\t' => 2,
            0x00..=0x1f => 6,
            _ => 1,
        })
        .sum::<usize>()
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
        assert_eq!(error.position, Some((1, 13)));
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
            ("name", json!(""), PayloadErrorKind::ProjectName),
            ("name", json!("tab\tname"), PayloadErrorKind::ProjectName),
            (
                "name",
                json!("n".repeat(201)),
                PayloadErrorKind::ProjectName,
            ),
            ("folder", json!("relative/path"), PayloadErrorKind::Folder),
            ("folder", json!("/new\nline"), PayloadErrorKind::Folder),
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
        let encoded = serde_json::to_vec(&environments).unwrap();
        let measured =
            Environments::deserialize(&mut serde_json::Deserializer::from_slice(&encoded))
                .unwrap()
                .stored_bytes;
        assert_eq!(measured, stored.len());
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
    fn every_error_code_is_distinct_and_found_again_from_its_message() {
        let codes: HashSet<_> = PayloadErrorKind::ALL
            .iter()
            .map(|kind| kind.code())
            .collect();
        assert_eq!(codes.len(), PayloadErrorKind::ALL.len());
        for kind in PayloadErrorKind::ALL {
            let error = <serde_json::Error as de::Error>::custom(Rejection(kind));
            assert_eq!(PayloadError::from_json(&error).kind, kind);
        }
    }
}
