use lpm_common::LpmError;
use std::path::Path;

const SCHEMA_VERSION: u32 = 1;
const PROJECT_COMMAND: &str = "trust release-age-exclude";
const USER_COMMAND: &str = "config release-age-exclude";
const PROJECT_SCOPE: &str = "project";
const USER_SCOPE: &str = "user";
const PROJECT_KEY: &str = "minimumReleaseAgeExclude";
const USER_KEY: &str = "minimum-release-age-exclude";

#[derive(Clone, Copy, Debug)]
pub(crate) enum ReleaseAgeExcludeOperation<'a> {
    Add(&'a str),
    Remove(&'a str),
    List,
}

impl<'a> ReleaseAgeExcludeOperation<'a> {
    fn action(self) -> &'static str {
        match self {
            Self::Add(_) => "add",
            Self::Remove(_) => "remove",
            Self::List => "list",
        }
    }

    fn selector(self) -> Option<&'a str> {
        match self {
            Self::Add(selector) | Self::Remove(selector) => Some(selector),
            Self::List => None,
        }
    }

    pub(crate) fn mutates(self) -> bool {
        !matches!(self, Self::List)
    }
}

#[derive(Debug)]
struct EditResult {
    exclusions: Vec<String>,
    selector: Option<String>,
    changed: bool,
}

pub(crate) fn parse_config_operation<'a>(
    action: Option<&'a str>,
    selector: Option<&'a str>,
    set: Option<&str>,
) -> Result<ReleaseAgeExcludeOperation<'a>, LpmError> {
    if set.is_some() {
        return Err(usage_error());
    }
    match (action, selector) {
        (Some("add"), Some(selector)) => Ok(ReleaseAgeExcludeOperation::Add(selector)),
        (Some("remove"), Some(selector)) => Ok(ReleaseAgeExcludeOperation::Remove(selector)),
        (Some("list"), None) => Ok(ReleaseAgeExcludeOperation::List),
        _ => Err(usage_error()),
    }
}

fn usage_error() -> LpmError {
    LpmError::Registry(
        "usage: `lpm config release-age-exclude add <selector>`, `remove <selector>`, or `list`"
            .into(),
    )
}

pub(crate) fn run_project(
    project_dir: &Path,
    operation: ReleaseAgeExcludeOperation<'_>,
    json_output: bool,
) -> Result<(), LpmError> {
    let manifest_path = project_dir.join("package.json");
    let content = match lpm_common::read_text_file_capped(
        &manifest_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return Err(LpmError::NotFound(
                "lpm trust release-age-exclude requires a package.json in the current directory."
                    .into(),
            ));
        }
        Err(error) => return Err(LpmError::Registry(error.to_string())),
    };
    let mut manifest: serde_json::Value = serde_json::from_str(&content)
        .map_err(|error| LpmError::Registry(format!("failed to parse package.json: {error}")))?;
    if !manifest.is_object() {
        return Err(LpmError::Registry(
            "package.json must contain a JSON object at the top level".into(),
        ));
    }

    let existing = project_exclusions(&manifest)?;
    let result = edit_exclusions(
        "package.json > lpm > minimumReleaseAgeExclude",
        existing,
        operation,
    )?;
    if operation.mutates() && result.changed {
        set_project_exclusions(&mut manifest, &result.exclusions)?;
        write_project_manifest(&manifest_path, &manifest)?;
    }
    print_result(
        PROJECT_COMMAND,
        PROJECT_SCOPE,
        operation,
        &result,
        json_output,
    )
}

pub(crate) fn run_user(
    config_path: &Path,
    operation: ReleaseAgeExcludeOperation<'_>,
    json_output: bool,
) -> Result<(), LpmError> {
    let mut config = read_user_config(config_path)?;
    let existing = user_exclusions(config_path, &config)?;
    let result = edit_exclusions(
        "~/.lpm/config.toml > minimum-release-age-exclude",
        existing,
        operation,
    )?;
    if operation.mutates() && result.changed {
        set_user_exclusions(&mut config, &result.exclusions)?;
        write_user_config(config_path, &config)?;
    }
    print_result(USER_COMMAND, USER_SCOPE, operation, &result, json_output)
}

fn edit_exclusions(
    source: &str,
    existing: Vec<String>,
    operation: ReleaseAgeExcludeOperation<'_>,
) -> Result<EditResult, LpmError> {
    let mut exclusions =
        crate::release_age_config::validate_release_age_excludes(source, &existing)?;
    let normalized_existing = exclusions != existing;
    let selector = operation
        .selector()
        .map(|selector| {
            crate::release_age_config::validate_release_age_excludes(
                source,
                &[selector.to_string()],
            )
            .map(|mut selectors| {
                selectors
                    .pop()
                    .expect("one selector validates to one value")
            })
        })
        .transpose()?;
    let changed = match operation {
        ReleaseAgeExcludeOperation::Add(_) => {
            let selector = selector.as_ref().expect("add has a selector");
            if exclusions.iter().any(|entry| entry == selector) {
                normalized_existing
            } else {
                exclusions.push(selector.clone());
                true
            }
        }
        ReleaseAgeExcludeOperation::Remove(_) => {
            let selector = selector.as_ref().expect("remove has a selector");
            let previous_len = exclusions.len();
            exclusions.retain(|entry| entry != selector);
            normalized_existing || exclusions.len() != previous_len
        }
        ReleaseAgeExcludeOperation::List => false,
    };
    Ok(EditResult {
        exclusions,
        selector,
        changed,
    })
}

fn project_exclusions(manifest: &serde_json::Value) -> Result<Vec<String>, LpmError> {
    let Some(lpm) = manifest.get("lpm") else {
        return Ok(Vec::new());
    };
    let Some(lpm) = lpm.as_object() else {
        return Err(LpmError::Registry(
            "package.json > lpm must be an object".into(),
        ));
    };
    let Some(value) = lpm.get(PROJECT_KEY) else {
        return Ok(Vec::new());
    };
    string_array(
        value,
        "package.json > lpm > minimumReleaseAgeExclude must be an array of strings",
    )
}

fn set_project_exclusions(
    manifest: &mut serde_json::Value,
    exclusions: &[String],
) -> Result<(), LpmError> {
    let root = manifest.as_object_mut().ok_or_else(|| {
        LpmError::Registry("package.json must contain a JSON object at the top level".into())
    })?;
    if exclusions.is_empty() {
        let remove_lpm = if let Some(lpm) = root.get_mut("lpm") {
            let lpm = lpm
                .as_object_mut()
                .ok_or_else(|| LpmError::Registry("package.json > lpm must be an object".into()))?;
            lpm.remove(PROJECT_KEY);
            lpm.is_empty()
        } else {
            false
        };
        if remove_lpm {
            root.remove("lpm");
        }
        return Ok(());
    }

    let lpm = root
        .entry("lpm")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| LpmError::Registry("package.json > lpm must be an object".into()))?;
    lpm.insert(PROJECT_KEY.to_string(), serde_json::json!(exclusions));
    Ok(())
}

fn write_project_manifest(path: &Path, manifest: &serde_json::Value) -> Result<(), LpmError> {
    let content = serde_json::to_string_pretty(manifest).map_err(|error| {
        LpmError::Registry(format!("failed to serialize package.json: {error}"))
    })?;
    lpm_common::write_file_atomic(path, format!("{content}\n")).map_err(LpmError::Io)
}

fn read_user_config(path: &Path) -> Result<toml::Value, LpmError> {
    let content =
        match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => {
                return Ok(toml::Value::Table(toml::map::Map::new()));
            }
            Err(error) => return Err(LpmError::Registry(error.to_string())),
        };
    let config: toml::Value = toml::from_str(&content).map_err(|error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    })?;
    if !config.is_table() {
        return Err(LpmError::Registry(format!(
            "{} must be a TOML table at the top level",
            path.display()
        )));
    }
    Ok(config)
}

fn user_exclusions(path: &Path, config: &toml::Value) -> Result<Vec<String>, LpmError> {
    let Some(value) = config.get(USER_KEY) else {
        return Ok(Vec::new());
    };
    string_array(
        value,
        &format!(
            "{}: `{USER_KEY}` must be an array of strings",
            path.display()
        ),
    )
}

fn string_array<T>(value: &T, shape_error: &str) -> Result<Vec<String>, LpmError>
where
    T: StringArrayValue,
{
    value
        .string_array()
        .ok_or_else(|| LpmError::Registry(shape_error.to_string()))
}

trait StringArrayValue {
    fn string_array(&self) -> Option<Vec<String>>;
}

impl StringArrayValue for serde_json::Value {
    fn string_array(&self) -> Option<Vec<String>> {
        self.as_array()?
            .iter()
            .map(|entry| entry.as_str().map(str::to_string))
            .collect()
    }
}

impl StringArrayValue for toml::Value {
    fn string_array(&self) -> Option<Vec<String>> {
        self.as_array()?
            .iter()
            .map(|entry| entry.as_str().map(str::to_string))
            .collect()
    }
}

fn set_user_exclusions(config: &mut toml::Value, exclusions: &[String]) -> Result<(), LpmError> {
    let table = config.as_table_mut().ok_or_else(|| {
        LpmError::Registry("~/.lpm/config.toml must be a TOML table at the top level".into())
    })?;
    if exclusions.is_empty() {
        table.remove(USER_KEY);
    } else {
        table.insert(
            USER_KEY.to_string(),
            toml::Value::Array(
                exclusions
                    .iter()
                    .map(|entry| toml::Value::String(entry.clone()))
                    .collect(),
            ),
        );
    }
    Ok(())
}

fn write_user_config(path: &Path, config: &toml::Value) -> Result<(), LpmError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(config)
        .map_err(|error| LpmError::Registry(format!("config serialize error: {error}")))?;
    lpm_common::write_file_atomic(path, content).map_err(LpmError::Io)
}

fn print_result(
    command: &str,
    scope: &str,
    operation: ReleaseAgeExcludeOperation<'_>,
    result: &EditResult,
    json_output: bool,
) -> Result<(), LpmError> {
    if json_output {
        let envelope = if let Some(selector) = result.selector.as_ref() {
            serde_json::json!({
                "success": true,
                "schema_version": SCHEMA_VERSION,
                "command": command,
                "scope": scope,
                "action": operation.action(),
                "selector": selector,
                "changed": result.changed,
                "exclusions": result.exclusions,
            })
        } else {
            serde_json::json!({
                "success": true,
                "schema_version": SCHEMA_VERSION,
                "command": command,
                "scope": scope,
                "action": operation.action(),
                "changed": result.changed,
                "exclusions": result.exclusions,
            })
        };
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }

    match operation {
        ReleaseAgeExcludeOperation::List => {
            if result.exclusions.is_empty() {
                println!("No {scope} release-age exclusions configured");
            } else {
                println!("{} release-age exclusions", title_case(scope));
                for exclusion in &result.exclusions {
                    println!("  {}", lpm_common::sanitize_terminal_inline(exclusion));
                }
            }
        }
        ReleaseAgeExcludeOperation::Add(_) => {
            let selector = display_selector(result);
            if result.changed {
                crate::install_ui::done_untrusted(&format!(
                    "Added {selector} to {scope} release-age exclusions"
                ));
            } else {
                crate::install_ui::done_untrusted(&format!(
                    "{selector} is already in {scope} release-age exclusions"
                ));
            }
        }
        ReleaseAgeExcludeOperation::Remove(_) => {
            let selector = display_selector(result);
            if result.changed {
                crate::install_ui::done_untrusted(&format!(
                    "Removed {selector} from {scope} release-age exclusions"
                ));
            } else {
                crate::install_ui::done_untrusted(&format!(
                    "{selector} was not in {scope} release-age exclusions"
                ));
            }
        }
    }
    Ok(())
}

fn display_selector(result: &EditResult) -> String {
    lpm_common::sanitize_terminal_inline(
        result
            .selector
            .as_deref()
            .expect("add and remove results have selectors"),
    )
    .into_owned()
}

fn title_case(value: &str) -> String {
    let mut characters = value.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().chain(characters).collect(),
        None => String::new(),
    }
}
