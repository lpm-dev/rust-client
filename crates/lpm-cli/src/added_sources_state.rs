//! — `.lpm/added-sources.json` persistence for `lpm add` / `lpm remove`.
//!
//! Successful `lpm add` runs record the exact source-delivery outputs they
//! wrote into `<project_dir>/.lpm/added-sources.json`. `lpm remove` consults
//! that manifest first so it can reverse custom `--path` installs and npm /
//! `.npmrc`-routed source packages precisely, without guessing from a fixed
//! candidate-directory list.

use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u32 = 1;
pub const FILENAME: &str = "added-sources.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddedSourcesState {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub packages: BTreeMap<String, AddedSourceRecord>,
}

impl Default for AddedSourcesState {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            packages: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddedSourceRecord {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub files: BTreeSet<PathBuf>,
    #[serde(
        default,
        rename = "skillPackageShort",
        skip_serializing_if = "Option::is_none"
    )]
    pub skill_package_short: Option<String>,
}

impl AddedSourcesState {
    pub fn package(&self, package: &str) -> Option<&AddedSourceRecord> {
        self.packages.get(package)
    }

    pub fn take_package(&mut self, package: &str) -> Option<AddedSourceRecord> {
        self.packages.remove(package)
    }

    pub fn record_package_files(
        &mut self,
        package: &str,
        files: impl IntoIterator<Item = PathBuf>,
        skill_package_short: Option<&str>,
    ) {
        self.schema_version = SCHEMA_VERSION;
        let entry = self.packages.entry(package.to_string()).or_default();
        entry.files.extend(files);
        if let Some(short) = skill_package_short {
            entry.skill_package_short = Some(short.to_string());
        }
    }
}

pub fn state_path(project_dir: &Path) -> PathBuf {
    project_dir.join(".lpm").join(FILENAME)
}

pub fn manifest_path_for_file(project_dir: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(project_dir)
    .map_or_else(|_| path.to_path_buf(), Path::to_path_buf)
}

pub fn resolve_manifest_path(project_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        project_dir.join(path)
    }
}

pub fn display_manifest_path(path: &Path) -> String {
    path.display().to_string()
}

pub fn read_state(project_dir: &Path) -> Result<Option<AddedSourcesState>, LpmError> {
    let path = state_path(project_dir);
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(LpmError::Io(error)),
    };

    let state: AddedSourcesState = serde_json::from_str(&content).map_err(|error| {
        LpmError::Registry(format!(
            "failed to parse {}: {error}",
            path.display()
        ))
    })?;

    if state.schema_version > SCHEMA_VERSION {
        return Err(LpmError::Registry(format!(
            "{} uses schema version {} but this lpm binary supports up to {}",
            path.display(),
            state.schema_version,
            SCHEMA_VERSION
        )));
    }

    Ok(Some(state))
}

pub fn load_state(project_dir: &Path) -> Result<AddedSourcesState, LpmError> {
    Ok(read_state(project_dir)?.unwrap_or_default())
}

pub fn write_state(project_dir: &Path, state: &AddedSourcesState) -> Result<(), LpmError> {
    let path = state_path(project_dir);

    if state.packages.is_empty() {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(LpmError::Io(error)),
        };
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
    }

    let body = serde_json::to_string_pretty(state).map_err(|error| {
        LpmError::Registry(format!(
            "failed to serialize added-sources state: {error}"
        ))
    })?;

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, format!("{body}\n")).map_err(LpmError::Io)?;
    std::fs::rename(&tmp, &path).map_err(LpmError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_and_read_round_trip_package_entries() {
        let dir = tempdir().unwrap();
        let mut state = AddedSourcesState::default();
        state.record_package_files(
            "source-pkg",
            [PathBuf::from("custom/widgets/Foo.tsx")],
            None,
        );

        write_state(dir.path(), &state).unwrap();
        let loaded = load_state(dir.path()).unwrap();

        assert_eq!(loaded.schema_version, SCHEMA_VERSION);
        let record = loaded.package("source-pkg").unwrap();
        assert!(record.files.contains(Path::new("custom/widgets/Foo.tsx")));
    }

    #[test]
    fn write_state_removes_file_when_no_entries_remain() {
        let dir = tempdir().unwrap();
        let mut state = AddedSourcesState::default();
        state.record_package_files("source-pkg", [PathBuf::from("Foo.tsx")], None);
        write_state(dir.path(), &state).unwrap();

        write_state(dir.path(), &AddedSourcesState::default()).unwrap();

        assert!(!state_path(dir.path()).exists());
    }
}