use crate::added_sources_state::{
    AddedSourceDependency, AddedSourceFile, AddedSourceFileAction, AddedSourceRecord,
    AddedSourcesState,
};
use lpm_common::LpmError;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub(super) struct SourceContent<'a> {
    pub configured: bool,
    pub author_alias: Option<&'a str>,
    pub buyer_alias: Option<&'a str>,
    pub src_to_dest: &'a HashMap<&'a str, &'a str>,
    pub dest_files: &'a HashSet<&'a str>,
}

impl SourceContent<'_> {
    pub fn prepare(
        &self,
        source: &Path,
        source_relative: &str,
        destination_relative: &str,
        external_imports: &mut HashSet<String>,
    ) -> Result<Option<String>, LpmError> {
        let content = super::source::read_runtime_source_text(source)?;
        let rewritten = content.as_deref().and_then(|text| {
            if self.configured {
                crate::import_rewriter::rewrite_imports_indexed(
                    text,
                    source_relative,
                    destination_relative,
                    self.author_alias,
                    self.buyer_alias,
                    self.src_to_dest,
                    self.dest_files,
                )
            } else {
                crate::import_rewriter::rewrite_imports_indexed_collecting_bare(
                    text,
                    source_relative,
                    destination_relative,
                    self.author_alias,
                    self.buyer_alias,
                    self.src_to_dest,
                    self.dest_files,
                    external_imports,
                )
            }
        });
        Ok(rewritten.or(content))
    }
}

pub(super) fn managed_file_matches(
    previous: Option<&AddedSourceFile>,
    current_digest: Option<&str>,
) -> bool {
    previous.is_some_and(|file| {
        file.action.is_some()
            && file.installed_digest.as_deref() == current_digest
            && current_digest.is_some()
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StaleFileAction {
    Preserve,
    Remove,
    Forget,
    Restore,
}

impl StaleFileAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preserve => "preserve",
            Self::Remove => "remove",
            Self::Forget => "forget",
            Self::Restore => "restore",
        }
    }
}

pub(super) fn stale_file_action(
    shared: bool,
    file: &AddedSourceFile,
    current_digest: Option<&str>,
) -> StaleFileAction {
    if shared
        || file.installed_digest.is_none()
        || current_digest.is_some_and(|digest| Some(digest) != file.installed_digest.as_deref())
    {
        return StaleFileAction::Preserve;
    }
    match (file.action, current_digest.is_some()) {
        (Some(AddedSourceFileAction::Create), true) => StaleFileAction::Remove,
        (Some(AddedSourceFileAction::Create), false) => StaleFileAction::Forget,
        (Some(AddedSourceFileAction::Overwrite), _) => StaleFileAction::Restore,
        (None, _) => StaleFileAction::Preserve,
    }
}

pub(super) fn stale_dependency_candidates(
    state: &mut AddedSourcesState,
    previous: Option<&AddedSourceRecord>,
    desired: &HashSet<&str>,
) -> Vec<(String, AddedSourceDependency)> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let stale_names = previous
        .dependencies
        .iter()
        .filter(|(name, dependency)| dependency.inserted && !desired.contains(name.as_str()))
        .map(|(name, _)| name.as_str())
        .collect::<HashSet<_>>();
    let mut replacement_owners = HashMap::<String, String>::with_capacity(stale_names.len());
    let mut inserted_elsewhere = HashSet::with_capacity(stale_names.len());
    for (other_package, record) in &state.packages {
        for (name, candidate) in &record.dependencies {
            if !stale_names.contains(name.as_str()) {
                continue;
            }
            if candidate.inserted {
                inserted_elsewhere.insert(name.clone());
            }
            let prior = &previous.dependencies[name];
            if candidate.spec == prior.spec && candidate.section == prior.section {
                replacement_owners
                    .entry(name.clone())
                    .or_insert_with(|| other_package.clone());
            }
        }
    }
    for name in &stale_names {
        if let Some(owner) = replacement_owners.get(*name)
            && let Some(replacement) = state
                .packages
                .get_mut(owner)
                .and_then(|record| record.dependencies.get_mut(*name))
        {
            replacement.inserted = true;
            inserted_elsewhere.insert((*name).to_string());
        }
    }
    previous
        .dependencies
        .iter()
        .filter(|(name, dependency)| {
            dependency.inserted
                && !desired.contains(name.as_str())
                && !inserted_elsewhere.contains(name.as_str())
        })
        .map(|(name, dependency)| (name.clone(), dependency.clone()))
        .collect()
}

#[derive(Serialize)]
pub(super) struct RemovedDependency {
    pub name: String,
    pub section: String,
    pub spec: String,
}

pub(super) fn remove_unchanged_dependencies(
    manifest: &mut serde_json::Value,
    candidates: &[(String, AddedSourceDependency)],
) -> Result<Vec<RemovedDependency>, LpmError> {
    let object = manifest
        .as_object_mut()
        .ok_or_else(|| LpmError::Registry("package.json root must be a JSON object".into()))?;
    let mut removed = Vec::new();
    for (name, dependency) in candidates {
        let Some(section) = object
            .get_mut(&dependency.section)
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        if section.get(name).and_then(serde_json::Value::as_str) == Some(dependency.spec.as_str()) {
            section.remove(name);
            removed.push(RemovedDependency {
                name: name.clone(),
                section: dependency.section.clone(),
                spec: dependency.spec.clone(),
            });
        }
    }
    Ok(removed)
}
