use super::policy::{MAX_POLICY_ENTRIES, POLICY_KEY};
use lpm_common::LpmError;
use lpm_security::query::parse_selector;
use std::path::{Path, PathBuf};

/// A project's `package.json`, read for an edit to its skills policy.
#[derive(Clone)]
pub(crate) struct ManifestEdit {
    path: PathBuf,
    reviewed: String,
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

impl ManifestEdit {
    pub(crate) fn read(project_dir: &Path) -> Result<Self, LpmError> {
        let path = project_dir.join("package.json");
        let (reviewed, _) = lpm_common::read_text_regular_file_capped_with_metadata(
            &path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )?;
        let value = serde_json::from_str(lpm_common::strip_utf8_bom_str(&reviewed))
            .map_err(|error| LpmError::Registry(format!("invalid {}: {error}", path.display())))?;
        Ok(Self {
            path,
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
                        "`lpm.{POLICY_KEY}.{}` already holds {MAX_POLICY_ENTRIES} selectors; remove some before adding `{canonical}`",
                        list.key()
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
            .value
            .get_mut("lpm")
            .and_then(|lpm| lpm.get_mut(POLICY_KEY))
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
            .value
            .get_mut("lpm")
            .and_then(|lpm| lpm.get_mut(POLICY_KEY))
            .and_then(serde_json::Value::as_object_mut)
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

    /// Writes the edited manifest, unless the file changed since it was
    /// read.
    pub(crate) fn write(&self) -> Result<(), LpmError> {
        let (current, _) = lpm_common::read_text_regular_file_capped_with_metadata(
            &self.path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )?;
        if current != self.reviewed {
            return Err(LpmError::Script(
                "package.json changed while its skills policy was being edited; nothing was written. Retry against the current manifest."
                    .into(),
            ));
        }
        let text = serde_json::to_string_pretty(&self.value).map_err(|error| {
            LpmError::Registry(format!("failed to serialize package.json: {error}"))
        })?;
        lpm_common::write_file_atomic(&self.path, format!("{text}\n"))?;
        Ok(())
    }

    fn list_mut(&mut self, list: PolicyList) -> Result<&mut Vec<serde_json::Value>, LpmError> {
        let lpm = object_entry(&mut self.value, "lpm", "`lpm`")?;
        let policy = object_entry(lpm, POLICY_KEY, "`lpm.skills`")?;
        let entries = policy
            .as_object_mut()
            .expect("object_entry returns an object")
            .entry(list.key())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        entries.as_array_mut().ok_or_else(|| {
            LpmError::Registry(format!(
                "package.json `lpm.skills.{}` is not an array; refusing to edit it",
                list.key()
            ))
        })
    }

    /// Drops empty policy lists, an empty policy, and an empty `lpm`.
    fn prune_empty(&mut self) {
        let Some(lpm) = self
            .value
            .get_mut("lpm")
            .and_then(serde_json::Value::as_object_mut)
        else {
            return;
        };
        if let Some(policy) = lpm
            .get_mut(POLICY_KEY)
            .and_then(serde_json::Value::as_object_mut)
        {
            for key in ["allow", "deny"] {
                if policy
                    .get(key)
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty)
                {
                    policy.shift_remove(key);
                }
            }
            if policy.is_empty() {
                lpm.shift_remove(POLICY_KEY);
            }
        }
        if lpm.is_empty()
            && let Some(object) = self.value.as_object_mut()
        {
            object.shift_remove("lpm");
        }
    }
}

fn object_entry<'a>(
    value: &'a mut serde_json::Value,
    key: &str,
    label: &str,
) -> Result<&'a mut serde_json::Value, LpmError> {
    let object = value.as_object_mut().ok_or_else(|| {
        LpmError::Registry("package.json is not a JSON object; refusing to edit it".into())
    })?;
    let entry = object
        .entry(key)
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !entry.is_object() {
        return Err(LpmError::Registry(format!(
            "package.json {label} is not an object; refusing to edit it"
        )));
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(json: &str) -> (tempfile::TempDir, ManifestEdit) {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), json).unwrap();
        let edit = ManifestEdit::read(project.path()).unwrap();
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
}
