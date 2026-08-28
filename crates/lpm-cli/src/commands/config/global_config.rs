use lpm_common::{LpmError, LpmRoot};

use super::io::read_config;
use super::wizards::{
    INTEGRITY_KEY, INTEGRITY_VALUES, TRUST_POLICY_KEY, TYPOSQUAT_GUARD_KEY,
    TyposquatGuardSelection, parse_integrity_policy_selection,
};

/// Read the global config file (~/.lpm/config.toml) once and provide
/// typed accessors. Cheap to construct (one file read, cached in struct).
pub struct GlobalConfig {
    pub(in crate::commands::config) table: toml::map::Map<String, toml::Value>,
}

impl GlobalConfig {
    pub(in crate::commands::config) fn from_value(value: toml::Value) -> Result<Self, LpmError> {
        match value {
            toml::Value::Table(table) => Ok(Self { table }),
            _ => Err(LpmError::Registry(
                "config.toml must be a TOML table at the top level".to_string(),
            )),
        }
    }

    pub(crate) fn table(&self) -> &toml::map::Map<String, toml::Value> {
        &self.table
    }

    pub(crate) fn table_mut(&mut self) -> &mut toml::map::Map<String, toml::Value> {
        &mut self.table
    }

    pub(in crate::commands::config) fn into_value(self) -> toml::Value {
        toml::Value::Table(self.table)
    }

    pub(in crate::commands::config) fn into_table(self) -> toml::map::Map<String, toml::Value> {
        self.table
    }

    /// Load from the configured LPM root's config.toml. Returns empty
    /// config if missing or unreadable.
    pub fn load() -> Self {
        Self::load_checked().unwrap_or_else(|_| Self {
            table: toml::map::Map::new(),
        })
    }

    /// Load from the configured LPM root's config.toml and propagate
    /// parse/read errors to security-sensitive command paths.
    pub fn load_checked() -> Result<Self, LpmError> {
        let config_path = LpmRoot::from_env()?.root().join("config.toml");
        let table = match read_config(&config_path)? {
            toml::Value::Table(table) => table,
            _ => {
                return Err(LpmError::Registry(format!(
                    "{} must contain a TOML table",
                    config_path.display()
                )));
            }
        };
        Ok(Self { table })
    }

    /// Construct an empty config — used by in-crate tests that need a
    /// deterministic "no overrides" baseline without touching
    /// `~/.lpm/config.toml`. `pub(crate)` because no external caller
    /// has a legitimate use; `#[cfg(test)]` because no production code
    /// path constructs an empty config — `load()` is the production
    /// path and a missing file already produces an empty table.
    pub(crate) fn empty() -> Self {
        Self {
            table: toml::map::Map::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_table(table: toml::map::Map<String, toml::Value>) -> Self {
        Self { table }
    }

    /// Get a string value.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.table.get(key)?.as_str()
    }

    /// Get a boolean value. Accepts "true"/"false" strings or native bools.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.table.get(key)? {
            toml::Value::Boolean(b) => Some(*b),
            toml::Value::String(s) => match s.as_str() {
                "true" | "1" | "yes" | "on" | "enabled" => Some(true),
                "false" | "0" | "no" | "off" | "disabled" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    /// Get a top-level table value, returning a reference to the
    /// underlying `toml::Table` for nested-key walks.
    ///
    /// Used by the `UserBound` reader to navigate into
    /// `[sandbox.limits]` without adding a bespoke per-section
    /// accessor to this struct. Callers chain through the returned
    /// table's own `get(...)` / `as_*` methods.
    ///
    /// Returns `None` for absent keys, dotted-key paths that don't
    /// resolve to a table, and any non-table value at this key.
    pub fn get_table(&self, key: &str) -> Option<&toml::value::Table> {
        self.table.get(key)?.as_table()
    }

    pub fn get_value(&self, key: &str) -> Option<&toml::Value> {
        self.table.get(key)
    }

    /// Read `[sigstore] verify`. Returns the raw string (`"deny"`
    /// / `"warn"` / `"off"`) if present, or `None` for absent /
    /// non-table / non-string / unknown values. The parse happens
    /// at the consumer ([`crate::provenance_fetch::EnforceMode::resolve_from_chain`])
    /// so unknown values fall back to the next tier in the
    /// precedence chain with a `tracing::debug` — the gap is
    /// diagnosable without crashing the install.
    ///
    /// The nested-table key path (`[sigstore].verify`, not flat
    /// `sigstore-verify = "..."`) matches the
    /// `[sandbox] mode = "..."` precedent; leaves room for future
    /// sigstore-scoped knobs (trust-root override path, custom
    /// Rekor URL) without polluting the top-level table.
    pub fn get_sigstore_verify(&self) -> Option<String> {
        let raw = self
            .get_table("sigstore")?
            .get("verify")?
            .as_str()
            .map(String::from)?;
        match raw.as_str() {
            "deny" | "warn" | "off" => Some(raw),
            _ => None,
        }
    }

    pub fn get_sigstore_scope(&self) -> Option<String> {
        self.get_table("sigstore")?
            .get("scope")?
            .as_str()
            .map(String::from)
    }

    pub fn get_sigstore_availability(&self) -> Option<String> {
        self.get_table("sigstore")?
            .get("availability")?
            .as_str()
            .map(String::from)
    }

    pub fn get_trust_policy(&self) -> Option<String> {
        let raw = self.get_str(TRUST_POLICY_KEY)?.to_string();
        match raw.as_str() {
            "off" | "no-downgrade" => Some(raw),
            _ => None,
        }
    }

    pub(crate) fn get_typosquat_guard_mode(&self) -> Option<TyposquatGuardSelection> {
        self.get_str(TYPOSQUAT_GUARD_KEY)
            .and_then(TyposquatGuardSelection::parse)
    }

    pub(crate) fn get_integrity_policy(
        &self,
    ) -> Result<Option<lpm_store::v2::ObjectIntegrityPolicy>, LpmError> {
        let Some(value) = self.get_value(INTEGRITY_KEY) else {
            return Ok(None);
        };
        let Some(raw) = value.as_str() else {
            return Err(LpmError::Registry(format!(
                "invalid `{INTEGRITY_KEY}`; must be one of: {}",
                INTEGRITY_VALUES.join(" | ")
            )));
        };
        parse_integrity_policy_selection(raw).map(Some)
    }

    /// Get a value that should be an array of strings, returning the
    /// entries as owned `Vec<String>`. Accepts:
    /// - A native TOML array of strings: `foo = ["a", "b"]` → `vec!["a", "b"]`.
    /// - A generic `lpm config set foo "a,b"`-style comma-separated
    ///   string is NOT auto-split here (to avoid silently accepting
    ///   comma-containing paths as two separate entries). A user who
    ///   wants multiple values must write a native TOML array.
    /// - Any other shape (integer, bool, single string, etc.) returns
    ///   `None` — callers treat that as "key absent" per the
    ///   `max-sandbox-write-roots` contract where
    ///   empty/unset means "no constraint".
    ///
    /// Used by the `max-sandbox-write-roots` reader on the sandbox
    /// write-root enforcement path; a generic accessor is cheaper to
    /// maintain than one bespoke config reader per key.
    pub fn get_str_array(&self, key: &str) -> Option<Vec<String>> {
        let arr = self.table.get(key)?.as_array()?;
        let mut out = Vec::with_capacity(arr.len());
        for entry in arr {
            // Skip non-string entries rather than erroring — config
            // readers on this path are advisory (absent-or-malformed
            // means default behavior). A caller that needs strict
            // validation should read the TOML directly.
            if let Some(s) = entry.as_str() {
                out.push(s.to_string());
            }
        }
        Some(out)
    }

    /// Get a non-negative integer value. Accepts `toml::Value::Integer`
    /// natively AND string-coerced values because the generic
    /// `lpm config set` command serializes values as strings. Returns
    /// `None` for absent keys, negative integers, or strings that don't
    /// parse as `u64`.
    ///
    /// This is a convenience reader for callers that don't need
    /// file-pathed error surfacing. For strict config loaders, read the
    /// file directly (see `release_age_config::read_global_min_age_from_file`
    /// for the path-aware pattern).
    ///
    /// String coercion routes through
    /// [`crate::release_age_config::parse_strict_u64_string`] so the
    /// rule "no sign prefix" stays uniform across the CLI flag, the
    /// global-TOML loader, and this convenience accessor. Without that
    /// shared helper, `"+5"` would parse as `5` on this path while the
    /// CLI flag rejects `+5h` — an inconsistency that would silently
    /// let persistent config accept inputs the CLI rejects.
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        match self.table.get(key)? {
            toml::Value::Integer(i) => u64::try_from(*i).ok(),
            toml::Value::String(s) => crate::release_age_config::parse_strict_u64_string(s),
            _ => None,
        }
    }
}
