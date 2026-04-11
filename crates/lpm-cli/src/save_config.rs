//! Phase 33 save-policy config loader.
//!
//! Resolves the [`SaveConfig`] that flows into
//! [`crate::save_spec::decide_saved_dependency_spec`] from two TOML files:
//!
//! 1. **Project config**: `./lpm.toml` (in the install root). Highest
//!    precedence — a project that wants exact pins for everything sets
//!    `save-exact = true` here and every developer's install honors it.
//! 2. **Global config**: `~/.lpm/config.toml`. The user's personal
//!    default for projects that don't specify one. Read via the existing
//!    [`crate::commands::config::GlobalConfig`] reader so users can set
//!    these keys with the existing `lpm config set save-prefix '~'`
//!    command without learning a new file format.
//! 3. **Built-in defaults**: `save-prefix = "^"`, `save-exact = false`.
//!
//! Per-project values **always** win over per-user values; per-user
//! values win over the built-in default. Per-command CLI flags
//! (`--exact`/`--tilde`/`--save-prefix`) sit above this entire chain
//! and are applied in [`crate::save_spec::decide_saved_dependency_spec`]
//! itself (tier 2 in the precedence table).
//!
//! ## File format
//!
//! Both files are TOML. Phase 33 uses two top-level keys:
//!
//! ```toml
//! save-prefix = "^"   # one of "^", "~", or "" (empty for exact)
//! save-exact = false  # bool; true forces exact regardless of save-prefix
//! ```
//!
//! Invalid values (`save-prefix = "*"`, `save-prefix = ">="`, etc.) are
//! rejected at load time with a clear error pointing at the offending
//! file path. Unknown keys are accepted silently for forward
//! compatibility — Phase 33 is intentionally only adding two keys.
//!
//! ## Why not `package.json`?
//!
//! Phase 33 explicitly chose not to put save-policy keys under a `"lpm"`
//! block in `package.json`. Save policy is **tool behavior**, not
//! publishable package metadata. Mixing it into the manifest creates
//! avoidable churn and ambiguity (the manifest gets a diff every time
//! you tweak a personal preference). Keeping it in a sibling
//! `lpm.toml` lets the file be project-shared OR `.gitignore`'d
//! depending on the team's preference.

use crate::save_spec::{SaveConfig, SavePrefix};
use lpm_common::LpmError;
use std::path::Path;

/// Phase 33 save-policy config loader. Resolves the effective
/// [`SaveConfig`] for an install command from project + global TOML.
///
/// Construct with [`Self::load_for_project`] just before invoking the
/// install pipeline. The struct is cheap to build (two file reads, no
/// caching needed across commands — each `lpm install` gets a fresh
/// view of the on-disk config).
pub struct SaveConfigLoader;

impl SaveConfigLoader {
    /// Build the effective [`SaveConfig`] for `project_dir`.
    ///
    /// Reads `<project_dir>/lpm.toml` first, then `~/.lpm/config.toml`,
    /// then merges with built-in defaults. Per-project values win over
    /// per-user values; either may be partially specified.
    ///
    /// Returns `Err(LpmError::Registry)` if either file exists but is
    /// malformed (e.g. invalid TOML, `save-prefix = "*"`, unknown
    /// `save-prefix` value). Missing files are NOT errors — they fall
    /// through to the next tier.
    pub fn load_for_project(project_dir: &Path) -> Result<SaveConfig, LpmError> {
        let project_path = project_dir.join("lpm.toml");
        let project = read_save_keys_from_file(&project_path)?;

        let global_path = dirs::home_dir().map(|h| h.join(".lpm").join("config.toml"));
        let global = match global_path {
            Some(ref p) => read_save_keys_from_file(p)?,
            None => RawSaveKeys::default(),
        };

        Ok(merge(project, global))
    }
}

/// Raw key snapshot from a single TOML file. `None` means the key is
/// absent (fall through to the next tier); `Some` means the file
/// explicitly set it.
#[derive(Debug, Default, PartialEq, Eq)]
struct RawSaveKeys {
    save_prefix: Option<SavePrefix>,
    save_exact: Option<bool>,
}

/// Read the Phase 33 save keys from a single TOML file. Missing file →
/// empty `RawSaveKeys`. Malformed file or invalid value → error with
/// the file path baked in for diagnostics.
fn read_save_keys_from_file(path: &Path) -> Result<RawSaveKeys, LpmError> {
    if !path.exists() {
        return Ok(RawSaveKeys::default());
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|e| LpmError::Registry(format!("failed to read {}: {e}", path.display())))?;

    let parsed: toml::Value = toml::from_str(&raw)
        .map_err(|e| LpmError::Registry(format!("failed to parse {}: {e}", path.display())))?;

    let table = match parsed {
        toml::Value::Table(t) => t,
        _ => {
            return Err(LpmError::Registry(format!(
                "{} must be a TOML table at the top level",
                path.display()
            )));
        }
    };

    let mut keys = RawSaveKeys::default();

    if let Some(value) = table.get("save-prefix") {
        let s = value.as_str().ok_or_else(|| {
            LpmError::Registry(format!(
                "{}: `save-prefix` must be a string (\"^\", \"~\", or \"\"), got {value}",
                path.display()
            ))
        })?;
        keys.save_prefix = Some(
            SavePrefix::parse(s)
                .map_err(|e| LpmError::Registry(format!("{}: {e}", path.display())))?,
        );
    }

    if let Some(value) = table.get("save-exact") {
        keys.save_exact = Some(coerce_bool(value).ok_or_else(|| {
            LpmError::Registry(format!(
                "{}: `save-exact` must be a boolean (`true`, `false`) or one of \
                 the string aliases (\"true\", \"false\", \"1\", \"0\", \"yes\", \
                 \"no\"), got {value}",
                path.display()
            ))
        })?);
    }

    // Phase 33 deliberately accepts unknown keys without warning. Other
    // commands write to the same `~/.lpm/config.toml` (linker, no_skills,
    // etc.) and we don't want this loader to fail on those keys.

    Ok(keys)
}

/// Coerce a TOML value into a `bool` using the same string-alias rules
/// that [`crate::commands::config::GlobalConfig::get_bool`] uses.
///
/// **Audit Finding A:** the generic `lpm config set <key> <value>`
/// command (in `commands/config.rs`) writes every value as
/// `toml::Value::String`, regardless of the key's intended type. So
/// `lpm config set save-exact true` literally produces
/// `save-exact = "true"` on disk. The Phase 33 loader MUST accept that
/// form, otherwise the documented persistent-config path is unusable.
///
/// We deliberately match `GlobalConfig::get_bool`'s string set —
/// `"true" | "1" | "yes"` for true, `"false" | "0" | "no"` for false —
/// so the loader and the rest of the LPM config readers all coerce
/// the same way. Native `Boolean(b)` is also accepted for users who
/// hand-edit `lpm.toml` directly. Anything else returns `None` and the
/// caller surfaces a clear, file-pathed error.
fn coerce_bool(value: &toml::Value) -> Option<bool> {
    match value {
        toml::Value::Boolean(b) => Some(*b),
        toml::Value::String(s) => match s.as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Merge per-project and per-global key snapshots into a final
/// `SaveConfig`. Per-project always wins over global; either may
/// contribute partially.
fn merge(project: RawSaveKeys, global: RawSaveKeys) -> SaveConfig {
    SaveConfig {
        save_prefix: project.save_prefix.or(global.save_prefix),
        save_exact: project.save_exact.or(global.save_exact).unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_config(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    // ── read_save_keys_from_file ─────────────────────────────────

    #[test]
    fn missing_file_returns_empty_keys() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_save_keys_from_file(&dir.path().join("lpm.toml")).unwrap();
        assert_eq!(result, RawSaveKeys::default());
    }

    #[test]
    fn empty_file_returns_empty_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, "");
        let result = read_save_keys_from_file(&path).unwrap();
        assert_eq!(result, RawSaveKeys::default());
    }

    #[test]
    fn save_prefix_caret_parsed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, r#"save-prefix = "^""#);
        let result = read_save_keys_from_file(&path).unwrap();
        assert_eq!(result.save_prefix, Some(SavePrefix::Caret));
        assert_eq!(result.save_exact, None);
    }

    #[test]
    fn save_prefix_tilde_parsed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, r#"save-prefix = "~""#);
        let result = read_save_keys_from_file(&path).unwrap();
        assert_eq!(result.save_prefix, Some(SavePrefix::Tilde));
    }

    #[test]
    fn save_prefix_empty_string_parsed_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, r#"save-prefix = """#);
        let result = read_save_keys_from_file(&path).unwrap();
        assert_eq!(result.save_prefix, Some(SavePrefix::Empty));
    }

    #[test]
    fn save_prefix_wildcard_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, r#"save-prefix = "*""#);
        let err = read_save_keys_from_file(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("lpm.toml"), "error must name the file: {msg}");
        assert!(
            msg.contains("not allowed") || msg.contains("'*'"),
            "error must explain why `*` is rejected: {msg}"
        );
    }

    #[test]
    fn save_prefix_garbage_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, r#"save-prefix = "garbage""#);
        assert!(read_save_keys_from_file(&path).is_err());
    }

    #[test]
    fn save_prefix_must_be_string_not_int() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, "save-prefix = 42");
        let err = read_save_keys_from_file(&path).unwrap_err();
        assert!(err.to_string().contains("must be a string"));
    }

    #[test]
    fn save_exact_true_parsed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, "save-exact = true");
        let result = read_save_keys_from_file(&path).unwrap();
        assert_eq!(result.save_exact, Some(true));
        assert_eq!(result.save_prefix, None);
    }

    #[test]
    fn save_exact_false_parsed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, "save-exact = false");
        let result = read_save_keys_from_file(&path).unwrap();
        assert_eq!(result.save_exact, Some(false));
    }

    /// **Audit Finding A regression.** `lpm config set save-exact true`
    /// writes `save-exact = "true"` (a TOML string, not a boolean) because
    /// the generic `lpm config set` command serializes every value as a
    /// string. The Phase 33 loader MUST accept this form so the documented
    /// persistent-config path actually works.
    #[test]
    fn save_exact_string_true_accepted_for_lpm_config_set_compat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        // The exact form `lpm config set save-exact true` would write.
        write_config(&path, r#"save-exact = "true""#);
        let result = read_save_keys_from_file(&path).unwrap();
        assert_eq!(
            result.save_exact,
            Some(true),
            "string-form `save-exact = \"true\"` must parse as bool true \
             so `lpm config set save-exact true` is honored"
        );
    }

    #[test]
    fn save_exact_string_false_accepted_for_lpm_config_set_compat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, r#"save-exact = "false""#);
        let result = read_save_keys_from_file(&path).unwrap();
        assert_eq!(result.save_exact, Some(false));
    }

    /// `GlobalConfig::get_bool` accepts `"1"|"yes"|"0"|"no"` as bool aliases.
    /// The Phase 33 loader matches that semantics so `lpm config set
    /// save-exact yes` and `lpm config set save-exact 0` also work.
    #[test]
    fn save_exact_string_yes_no_one_zero_accepted() {
        for (input, expected) in [("yes", true), ("1", true), ("no", false), ("0", false)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("lpm.toml");
            write_config(&path, &format!(r#"save-exact = "{input}""#));
            let result = read_save_keys_from_file(&path).unwrap();
            assert_eq!(
                result.save_exact,
                Some(expected),
                "string `save-exact = \"{input}\"` must parse as {expected}"
            );
        }
    }

    /// Garbage strings (not in the bool-alias set) are still rejected.
    /// `lpm config set save-exact maybe` would write `"maybe"`, which is
    /// not a known alias, so the loader surfaces a clear error pointing
    /// at the file.
    #[test]
    fn save_exact_string_garbage_rejected_with_filename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, r#"save-exact = "maybe""#);
        let err = read_save_keys_from_file(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("lpm.toml"), "error must name the file: {msg}");
        assert!(
            msg.contains("save-exact"),
            "error must name the offending key: {msg}"
        );
    }

    /// Numeric values (not strings, not bools) are still rejected.
    /// `save-exact = 1` is invalid TOML for our purposes — the user must
    /// either write `true`/`false` or one of the documented string aliases.
    #[test]
    fn save_exact_integer_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, "save-exact = 1");
        let err = read_save_keys_from_file(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("save-exact"),
            "error must name the offending key: {msg}"
        );
    }

    #[test]
    fn both_keys_parsed_together() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, "save-prefix = \"~\"\nsave-exact = true\n");
        let result = read_save_keys_from_file(&path).unwrap();
        assert_eq!(result.save_prefix, Some(SavePrefix::Tilde));
        assert_eq!(result.save_exact, Some(true));
    }

    #[test]
    fn unknown_keys_silently_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        // Other commands (linker, noSkills, etc.) write to the same
        // ~/.lpm/config.toml. Phase 33 must not error on those keys.
        write_config(
            &path,
            r#"
save-prefix = "^"
linker = "isolated"
noSkills = true
some-future-key = 42
"#,
        );
        let result = read_save_keys_from_file(&path).unwrap();
        assert_eq!(result.save_prefix, Some(SavePrefix::Caret));
    }

    #[test]
    fn malformed_toml_returns_error_with_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.toml");
        write_config(&path, "not valid toml === [[[");
        let err = read_save_keys_from_file(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("lpm.toml"), "error must name the file: {msg}");
    }

    // ── merge ────────────────────────────────────────────────────

    #[test]
    fn merge_empty_returns_defaults() {
        let cfg = merge(RawSaveKeys::default(), RawSaveKeys::default());
        assert_eq!(cfg.save_prefix, None);
        assert!(!cfg.save_exact);
    }

    #[test]
    fn merge_global_only_uses_global_values() {
        let global = RawSaveKeys {
            save_prefix: Some(SavePrefix::Tilde),
            save_exact: Some(true),
        };
        let cfg = merge(RawSaveKeys::default(), global);
        assert_eq!(cfg.save_prefix, Some(SavePrefix::Tilde));
        assert!(cfg.save_exact);
    }

    #[test]
    fn merge_project_overrides_global() {
        let project = RawSaveKeys {
            save_prefix: Some(SavePrefix::Caret),
            save_exact: Some(false),
        };
        let global = RawSaveKeys {
            save_prefix: Some(SavePrefix::Tilde),
            save_exact: Some(true),
        };
        let cfg = merge(project, global);
        assert_eq!(cfg.save_prefix, Some(SavePrefix::Caret));
        assert!(
            !cfg.save_exact,
            "project save_exact=false must beat global save_exact=true"
        );
    }

    #[test]
    fn merge_partial_project_falls_through_to_global_for_unset_keys() {
        // Project sets save-prefix but not save-exact → save-exact comes
        // from global.
        let project = RawSaveKeys {
            save_prefix: Some(SavePrefix::Empty),
            save_exact: None,
        };
        let global = RawSaveKeys {
            save_prefix: Some(SavePrefix::Caret),
            save_exact: Some(true),
        };
        let cfg = merge(project, global);
        assert_eq!(cfg.save_prefix, Some(SavePrefix::Empty));
        assert!(cfg.save_exact);
    }

    #[test]
    fn merge_save_exact_falls_through_when_neither_specified() {
        // Neither file sets save-exact → defaults to false.
        let project = RawSaveKeys {
            save_prefix: Some(SavePrefix::Tilde),
            save_exact: None,
        };
        let global = RawSaveKeys {
            save_prefix: None,
            save_exact: None,
        };
        let cfg = merge(project, global);
        assert!(!cfg.save_exact);
    }

    // ── load_for_project (integration with both files) ──────────

    #[test]
    fn load_for_project_no_files_returns_defaults() {
        // Use a synthetic project dir under a temp HOME so the global
        // reader doesn't pick up the developer's actual config.
        let project_dir = tempfile::tempdir().unwrap();
        let _home_lock = scoped_home_dir();
        let cfg = SaveConfigLoader::load_for_project(project_dir.path()).unwrap();
        assert_eq!(cfg.save_prefix, None);
        assert!(!cfg.save_exact);
    }

    #[test]
    fn load_for_project_only_project_file() {
        let project_dir = tempfile::tempdir().unwrap();
        write_config(&project_dir.path().join("lpm.toml"), r#"save-prefix = "~""#);
        let _home_lock = scoped_home_dir();
        let cfg = SaveConfigLoader::load_for_project(project_dir.path()).unwrap();
        assert_eq!(cfg.save_prefix, Some(SavePrefix::Tilde));
    }

    #[test]
    fn load_for_project_only_global_file() {
        let project_dir = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_config(
            &home.path().join(".lpm").join("config.toml"),
            "save-exact = true",
        );
        let cfg = SaveConfigLoader::load_for_project(project_dir.path()).unwrap();
        assert_eq!(cfg.save_prefix, None);
        assert!(cfg.save_exact);
    }

    #[test]
    fn load_for_project_project_overrides_global() {
        let project_dir = tempfile::tempdir().unwrap();
        write_config(&project_dir.path().join("lpm.toml"), r#"save-prefix = "^""#);
        let home = scoped_home_dir();
        write_config(
            &home.path().join(".lpm").join("config.toml"),
            r#"save-prefix = "~""#,
        );
        let cfg = SaveConfigLoader::load_for_project(project_dir.path()).unwrap();
        assert_eq!(
            cfg.save_prefix,
            Some(SavePrefix::Caret),
            "project lpm.toml must override ~/.lpm/config.toml"
        );
    }

    #[test]
    fn load_for_project_surfaces_invalid_project_value() {
        let project_dir = tempfile::tempdir().unwrap();
        write_config(&project_dir.path().join("lpm.toml"), r#"save-prefix = "*""#);
        let _home_lock = scoped_home_dir();
        let err = SaveConfigLoader::load_for_project(project_dir.path()).unwrap_err();
        assert!(err.to_string().contains("lpm.toml"));
    }

    #[test]
    fn load_for_project_surfaces_invalid_global_value() {
        let project_dir = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_config(
            &home.path().join(".lpm").join("config.toml"),
            r#"save-prefix = "garbage""#,
        );
        let err = SaveConfigLoader::load_for_project(project_dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("config.toml"),
            "error must name the global file: {msg}"
        );
    }

    /// Test helper: redirect HOME to a per-test temp directory so the
    /// global config reader doesn't pick up the developer's actual
    /// `~/.lpm/config.toml`. Returns a `TempDir` whose lifetime brackets
    /// the override — drop it at the end of the test to restore.
    ///
    /// **Concurrency note:** uses `std::env::set_var`, which is process-
    /// global. The test runner may run these tests in parallel, so we
    /// serialize them under a mutex.
    fn scoped_home_dir() -> ScopedHomeDir {
        use std::sync::Mutex;
        // Keep the lock for the lifetime of the returned guard so
        // concurrent tests don't stomp on each other's HOME.
        static HOME_LOCK: Mutex<()> = Mutex::new(());
        let guard = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("HOME");
        // SAFETY: tests are serialized via HOME_LOCK above; mutating
        // the process-wide environment under a mutex is sound here.
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
        ScopedHomeDir {
            dir,
            prev_home: prev,
            _guard: guard,
        }
    }

    struct ScopedHomeDir {
        dir: tempfile::TempDir,
        prev_home: Option<std::ffi::OsString>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl ScopedHomeDir {
        fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    impl Drop for ScopedHomeDir {
        fn drop(&mut self) {
            // SAFETY: still holding the mutex via `_guard`, so this
            // mutation is serialized with other tests using the helper.
            unsafe {
                match &self.prev_home {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }
}
