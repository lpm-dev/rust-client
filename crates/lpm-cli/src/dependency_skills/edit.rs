use super::policy::{MAX_POLICY_ENTRIES, POLICY_KEY, PolicySource};
use lpm_common::LpmError;
use lpm_security::query::parse_selector;
use std::path::{Path, PathBuf};

/// A skills policy read for an edit: a project's `package.json`, or the
/// global policy file.
#[derive(Clone)]
pub(crate) struct PolicyEdit {
    path: PathBuf,
    source: PolicySource,
    /// For the global policy, the LPM root whose `global` folder holds it,
    /// opened afresh, never through a link, for each read and write.
    lpm_root: Option<lpm_common::LpmRoot>,
    /// The file's text as read; `None` for a global policy not written yet.
    reviewed: Option<String>,
    /// The whole document: the manifest, or the global policy object.
    pub(crate) value: serde_json::Value,
}

/// Which list of the policy an edit changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyList {
    Allow,
    Deny,
}

impl PolicyList {
    fn key(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

impl PolicyEdit {
    /// The policy in `project_dir`'s `package.json`.
    pub(crate) fn project(project_dir: &Path) -> Result<Self, LpmError> {
        let path = project_dir.join("package.json");
        let (reviewed, _) = lpm_common::read_text_regular_file_capped_with_metadata(
            &path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )?;
        let value = serde_json::from_str(lpm_common::strip_utf8_bom_str(&reviewed))
            .map_err(|error| LpmError::Registry(format!("invalid {}: {error}", path.display())))?;
        Ok(Self {
            path,
            source: PolicySource::Manifest,
            lpm_root: None,
            reviewed: Some(reviewed),
            value,
        })
    }

    /// The global policy of `lpm_root`, shown as `path`, empty when the file
    /// doesn't exist.
    pub(crate) fn global(lpm_root: lpm_common::LpmRoot, path: PathBuf) -> Result<Self, LpmError> {
        let reviewed = read_global(&lpm_root, &path)?;
        let value = match &reviewed {
            Some(text) => {
                serde_json::from_str(lpm_common::strip_utf8_bom_str(text)).map_err(|error| {
                    LpmError::Registry(format!("invalid {}: {error}", path.display()))
                })?
            }
            None => serde_json::Value::Object(serde_json::Map::new()),
        };
        Ok(Self {
            path,
            source: PolicySource::Global,
            lpm_root: Some(lpm_root),
            reviewed,
            value,
        })
    }

    /// Adds `selectors` to the list, skipping any whose canonical form it
    /// already holds. Returns the ones added, in canonical form.
    pub(crate) fn add(
        &mut self,
        list: PolicyList,
        selectors: &[String],
    ) -> Result<Vec<String>, LpmError> {
        if selectors.is_empty() {
            return Ok(Vec::new());
        }
        let source = self.source;
        let entries = self.list_mut(list)?;
        let mut present: Vec<String> = entries
            .iter()
            .filter_map(serde_json::Value::as_str)
            .filter_map(|text| parse_selector(text).ok())
            .map(|selector| selector.to_string())
            .collect();
        let mut added = Vec::new();
        for selector in selectors {
            let canonical = parse_selector(selector)
                .map_err(|error| {
                    LpmError::Registry(format!(
                        "`{selector}` is not a valid selector: {}",
                        error.message
                    ))
                })?
                .to_string();
            if !present.contains(&canonical) {
                if entries.len() >= MAX_POLICY_ENTRIES {
                    return Err(LpmError::Registry(format!(
                        "{} already holds {MAX_POLICY_ENTRIES} selectors; remove some before adding `{canonical}`",
                        source.key(&format!(".{}", list.key()))
                    )));
                }
                entries.push(serde_json::Value::String(canonical.clone()));
                present.push(canonical.clone());
                added.push(canonical);
            }
        }
        self.prune_empty();
        Ok(added)
    }

    /// Removes the entries of the list whose canonical form equals one of
    /// `selectors`. Returns the ones removed, as written.
    pub(crate) fn remove(&mut self, list: PolicyList, selectors: &[String]) -> Vec<String> {
        let wanted: Vec<String> = selectors
            .iter()
            .filter_map(|selector| parse_selector(selector).ok())
            .map(|selector| selector.to_string())
            .collect();
        let Some(entries) = self
            .policy_object_mut()
            .and_then(|policy| policy.get_mut(list.key()))
            .and_then(serde_json::Value::as_array_mut)
        else {
            return Vec::new();
        };
        let mut removed = Vec::new();
        entries.retain(|entry| {
            let matches = entry
                .as_str()
                .and_then(|text| parse_selector(text).ok())
                .is_some_and(|selector| wanted.contains(&selector.to_string()));
            if matches {
                removed.push(entry.as_str().unwrap_or_default().to_string());
            }
            !matches
        });
        self.prune_empty();
        removed
    }

    /// Removes every entry of the list. Returns the entries removed.
    pub(crate) fn clear(&mut self, list: PolicyList) -> Vec<String> {
        let removed = self
            .policy_object_mut()
            .and_then(|policy| policy.shift_remove(list.key()))
            .and_then(|entries| match entries {
                serde_json::Value::Array(entries) => Some(entries),
                _ => None,
            })
            .unwrap_or_default()
            .into_iter()
            .filter_map(|entry| entry.as_str().map(str::to_string))
            .collect();
        self.prune_empty();
        removed
    }

    /// Writes the edited document, unless the file changed since it was
    /// read. A global policy left empty is removed.
    pub(crate) fn write(&self) -> Result<(), LpmError> {
        let text = serde_json::to_string_pretty(&self.value).map_err(|error| {
            LpmError::Registry(format!(
                "failed to serialize {}: {error}",
                self.path.display()
            ))
        })?;
        let Some(lpm_root) = &self.lpm_root else {
            let current = lpm_common::read_text_regular_file_capped_with_metadata(
                &self.path,
                lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
            )?
            .0;
            self.ensure_unchanged(Some(current))?;
            lpm_common::write_file_atomic(&self.path, format!("{text}\n"))?;
            return Ok(());
        };
        let directory = lpm_common::open_or_create_global_directory(lpm_root)?;
        self.ensure_unchanged(super::global::read_policy_text(&directory, &self.path)?)?;
        let file = std::ffi::OsStr::new(super::global::POLICY_FILE);
        if self
            .value
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        {
            return match directory.remove_file(file) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            };
        }
        lpm_common::write_file_atomic_in_dir_with(&directory, file, |output| {
            use std::io::Write as _;
            output.write_all(text.as_bytes())?;
            output.write_all(b"\n")
        })?;
        Ok(())
    }

    /// Refuses the edit when the policy file changed since the edit read it,
    /// for a caller that writes other things first under the same lock.
    pub(crate) fn ensure_current(&self) -> Result<(), LpmError> {
        match &self.lpm_root {
            Some(lpm_root) => self.ensure_unchanged(read_global(lpm_root, &self.path)?),
            None => self.ensure_unchanged(Some(
                lpm_common::read_text_regular_file_capped_with_metadata(
                    &self.path,
                    lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
                )?
                .0,
            )),
        }
    }

    /// Refuses to write over a policy file that changed since the edit read
    /// it: `current` is its text now, `None` when it doesn't exist.
    fn ensure_unchanged(&self, current: Option<String>) -> Result<(), LpmError> {
        if current == self.reviewed {
            return Ok(());
        }
        Err(LpmError::Script(format!(
            "{} changed while its skills policy was being edited; nothing was written. Retry against the current file.",
            self.path.display()
        )))
    }

    /// The policy object, created when missing.
    fn policy_mut(&mut self) -> Result<&mut serde_json::Value, LpmError> {
        let source = self.source;
        let document = describe(source);
        match source {
            PolicySource::Manifest => {
                let lpm = object_entry(&mut self.value, "lpm", "`lpm`", &document)?;
                object_entry(lpm, POLICY_KEY, "`lpm.skills`", &document)
            }
            PolicySource::Global if self.value.is_object() => Ok(&mut self.value),
            PolicySource::Global => Err(LpmError::Registry(format!(
                "{document} is not a JSON object; refusing to edit it"
            ))),
        }
    }

    /// The policy object, when there is one.
    fn policy_object_mut(&mut self) -> Option<&mut serde_json::Map<String, serde_json::Value>> {
        match self.source {
            PolicySource::Manifest => self
                .value
                .get_mut("lpm")
                .and_then(|lpm| lpm.get_mut(POLICY_KEY))
                .and_then(serde_json::Value::as_object_mut),
            PolicySource::Global => self.value.as_object_mut(),
        }
    }

    fn list_mut(&mut self, list: PolicyList) -> Result<&mut Vec<serde_json::Value>, LpmError> {
        let source = self.source;
        let entries = self
            .policy_mut()?
            .as_object_mut()
            .expect("policy_mut returns an object")
            .entry(list.key())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        entries.as_array_mut().ok_or_else(|| {
            LpmError::Registry(format!(
                "{} is not an array; refusing to edit it",
                source.key(&format!(".{}", list.key()))
            ))
        })
    }

    /// Drops empty policy lists and, in a manifest, an empty policy and an
    /// empty `lpm`.
    fn prune_empty(&mut self) {
        if let Some(policy) = self.policy_object_mut() {
            for key in ["allow", "deny"] {
                if policy
                    .get(key)
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty)
                {
                    policy.shift_remove(key);
                }
            }
        }
        if self.source == PolicySource::Global {
            return;
        }
        let Some(lpm) = self
            .value
            .get_mut("lpm")
            .and_then(serde_json::Value::as_object_mut)
        else {
            return;
        };
        if lpm
            .get(POLICY_KEY)
            .and_then(serde_json::Value::as_object)
            .is_some_and(serde_json::Map::is_empty)
        {
            lpm.shift_remove(POLICY_KEY);
        }
        if lpm.is_empty()
            && let Some(object) = self.value.as_object_mut()
        {
            object.shift_remove("lpm");
        }
    }
}

/// How messages name the edited file.
fn describe(source: PolicySource) -> String {
    match source {
        PolicySource::Manifest => "package.json".to_string(),
        PolicySource::Global => "the global skills policy".to_string(),
    }
}

/// The global policy file's text, shown as `path`: `None` when it or the
/// global folder doesn't exist.
fn read_global(lpm_root: &lpm_common::LpmRoot, path: &Path) -> Result<Option<String>, LpmError> {
    match lpm_common::open_global_directory(lpm_root)? {
        Some(directory) => super::global::read_policy_text(&directory, path),
        None => Ok(None),
    }
}

fn object_entry<'a>(
    value: &'a mut serde_json::Value,
    key: &str,
    label: &str,
    document: &str,
) -> Result<&'a mut serde_json::Value, LpmError> {
    let object = value.as_object_mut().ok_or_else(|| {
        LpmError::Registry(format!(
            "{document} is not a JSON object; refusing to edit it"
        ))
    })?;
    let entry = object
        .entry(key)
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !entry.is_object() {
        return Err(LpmError::Registry(format!(
            "{document} {label} is not an object; refusing to edit it"
        )));
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(json: &str) -> (tempfile::TempDir, PolicyEdit) {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), json).unwrap();
        let edit = PolicyEdit::project(project.path()).unwrap();
        (project, edit)
    }

    #[test]
    fn adding_selectors_creates_the_policy_and_skips_equal_entries() {
        let (project, mut edit) = open(r#"{"name":"app","version":"1.0.0"}"#);
        let added = edit
            .add(
                PolicyList::Allow,
                &["#a".into(), "#a ".into(), "#b:skill(x,y)".into()],
            )
            .unwrap();
        assert_eq!(added, ["#a", "#b:skill(x, y)"]);
        edit.write().unwrap();

        let written = std::fs::read_to_string(project.path().join("package.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(
            value["lpm"]["skills"]["allow"],
            serde_json::json!(["#a", "#b:skill(x, y)"])
        );
        assert!(written.starts_with("{\n  \"name\": \"app\""));
        assert!(written.ends_with("}\n"));
    }

    #[test]
    fn adding_nothing_leaves_the_manifest_untouched() {
        let (_project, mut edit) = open(r#"{"name":"app"}"#);
        assert!(edit.add(PolicyList::Deny, &[]).unwrap().is_empty());
        assert_eq!(edit.value, serde_json::json!({"name": "app"}));
    }

    #[test]
    fn removing_the_last_entry_removes_the_policy_and_an_empty_lpm() {
        let (_project, mut edit) =
            open(r##"{"name":"app","lpm":{"skills":{"allow":["#a , #b"]}}}"##);
        assert_eq!(
            edit.remove(PolicyList::Allow, &["#a,#b".into()]),
            ["#a , #b"]
        );
        assert!(edit.value.get("lpm").is_none());
    }

    #[test]
    fn clearing_the_allow_list_keeps_the_deny_list_and_other_lpm_settings() {
        let (_project, mut edit) = open(
            r##"{"name":"app","lpm":{"linker":"hoisted","skills":{"allow":["#a","#b"],"deny":["#c"]}}}"##,
        );
        assert_eq!(edit.clear(PolicyList::Allow), ["#a", "#b"]);
        assert_eq!(
            edit.value["lpm"],
            serde_json::json!({"linker": "hoisted", "skills": {"deny": ["#c"]}})
        );
        assert_eq!(edit.clear(PolicyList::Deny), ["#c"]);
        assert_eq!(edit.value["lpm"], serde_json::json!({"linker": "hoisted"}));
    }

    #[test]
    fn a_manifest_that_changed_after_review_is_not_overwritten() {
        let (project, mut edit) = open(r#"{"name":"app"}"#);
        edit.add(PolicyList::Allow, &["#a".into()]).unwrap();
        std::fs::write(project.path().join("package.json"), r#"{"name":"edited"}"#).unwrap();
        assert!(edit.write().is_err());
        assert_eq!(
            std::fs::read_to_string(project.path().join("package.json")).unwrap(),
            r#"{"name":"edited"}"#
        );
    }

    #[test]
    fn a_malformed_policy_is_refused_rather_than_replaced() {
        let (_project, mut edit) = open(r##"{"lpm":{"skills":["#a"]}}"##);
        assert!(edit.add(PolicyList::Allow, &["#b".into()]).is_err());
        let (_project, mut edit) = open(r##"{"lpm":{"skills":{"allow":"#a"}}}"##);
        assert!(edit.add(PolicyList::Allow, &["#b".into()]).is_err());
    }

    fn global_edit(root: &lpm_common::LpmRoot) -> PolicyEdit {
        PolicyEdit::global(root.clone(), root.global_root().join("skills.json")).unwrap()
    }

    #[test]
    fn the_global_policy_file_is_created_on_the_first_entry_and_removed_when_empty() {
        let home = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(home.path().join(".lpm"));
        let path = root.global_root().join("skills.json");
        let mut edit = global_edit(&root);
        assert_eq!(edit.add(PolicyList::Allow, &["#a".into()]).unwrap(), ["#a"]);
        edit.write().unwrap();
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written, serde_json::json!({ "allow": ["#a"] }));

        let mut edit = global_edit(&root);
        assert_eq!(edit.remove(PolicyList::Allow, &["#a".into()]), ["#a"]);
        edit.write().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn a_global_policy_written_by_someone_else_meanwhile_is_not_overwritten() {
        let home = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(home.path());
        std::fs::create_dir_all(root.global_root()).unwrap();
        let path = root.global_root().join("skills.json");
        let mut edit = global_edit(&root);
        edit.add(PolicyList::Allow, &["#a".into()]).unwrap();
        std::fs::write(&path, r##"{"allow":["#b"]}"##).unwrap();
        assert!(edit.write().is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r##"{"allow":["#b"]}"##
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_global_policy_read_before_its_folder_became_a_link_is_never_written_through_it() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(home.path());
        std::fs::create_dir_all(root.global_root()).unwrap();
        let mut edit = global_edit(&root);
        edit.add(PolicyList::Allow, &["#a".into()]).unwrap();
        std::fs::remove_dir_all(root.global_root()).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), root.global_root()).unwrap();

        assert!(edit.write().is_err());
        assert!(edit.ensure_current().is_err());
        assert!(!elsewhere.path().join("skills.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_global_policy_is_never_read_or_written_through_a_linked_file_or_folder() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(home.path());
        std::fs::create_dir_all(root.global_root()).unwrap();
        std::fs::write(
            elsewhere.path().join("skills.json"),
            r##"{"allow":["#b"]}"##,
        )
        .unwrap();
        std::os::unix::fs::symlink(
            elsewhere.path().join("skills.json"),
            root.global_root().join("skills.json"),
        )
        .unwrap();
        assert!(PolicyEdit::global(root.clone(), root.global_root().join("skills.json")).is_err());

        std::fs::remove_dir_all(root.global_root()).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), root.global_root()).unwrap();
        assert!(PolicyEdit::global(root.clone(), root.global_root().join("skills.json")).is_err());
        assert_eq!(
            std::fs::read_to_string(elsewhere.path().join("skills.json")).unwrap(),
            r##"{"allow":["#b"]}"##
        );
    }
}
