use lpm_common::{LpmError, LpmRoot};
use std::num::NonZeroUsize;
use std::path::Path;

pub(crate) fn default_workspace_concurrency() -> NonZeroUsize {
    std::thread::available_parallelism()
        .unwrap_or_else(|_| NonZeroUsize::new(4).expect("fallback concurrency is non-zero"))
}

pub(crate) fn parse_workspace_concurrency(value: &str) -> Result<NonZeroUsize, String> {
    if value.is_empty() || !value.as_bytes().iter().all(|byte| byte.is_ascii_digit()) {
        return Err("workspace concurrency must be a positive integer".to_string());
    }

    let parsed = value
        .parse::<usize>()
        .map_err(|_| "workspace concurrency must fit in usize".to_string())?;
    NonZeroUsize::new(parsed)
        .ok_or_else(|| "workspace concurrency must be greater than zero".to_string())
}

pub(crate) fn resolve_workspace_concurrency(
    workspace_root: &Path,
    cli_value: Option<NonZeroUsize>,
) -> Result<NonZeroUsize, LpmError> {
    if let Some(value) = cli_value {
        return Ok(value);
    }

    let project_path = workspace_root.join("lpm.toml");
    if let Some(value) = read_project_workspace_concurrency_from_file(&project_path)? {
        return Ok(value);
    }

    let global_path = LpmRoot::from_env()?.root().join("config.toml");
    if let Some(value) = read_global_workspace_concurrency_from_file(&global_path)? {
        return Ok(value);
    }

    Ok(default_workspace_concurrency())
}

pub(crate) fn resolve_workspace_concurrency_from_tables(
    project: &toml::map::Map<String, toml::Value>,
    global: &crate::commands::config::GlobalConfig,
    project_source: &Path,
    global_source: &Path,
) -> Result<NonZeroUsize, LpmError> {
    if let Some(workspace) = project.get("workspace") {
        let workspace = workspace.as_table().ok_or_else(|| {
            LpmError::Registry(format!(
                "{}: `workspace` must be a TOML table when present",
                project_source.display()
            ))
        })?;
        if let Some(value) = workspace.get("concurrency") {
            return parse_config_value(project_source, "workspace.concurrency", value);
        }
    }
    if let Some(value) = global.get_value("workspace-concurrency") {
        return parse_config_value(global_source, "workspace-concurrency", value);
    }
    Ok(default_workspace_concurrency())
}

fn read_project_workspace_concurrency_from_file(
    path: &Path,
) -> Result<Option<NonZeroUsize>, LpmError> {
    let Some(table) = read_toml_table(path)? else {
        return Ok(None);
    };

    let Some(workspace) = table.get("workspace") else {
        return Ok(None);
    };

    let workspace_table = workspace.as_table().ok_or_else(|| {
        LpmError::Registry(format!(
            "{}: `workspace` must be a TOML table when present",
            path.display()
        ))
    })?;

    let Some(value) = workspace_table.get("concurrency") else {
        return Ok(None);
    };

    parse_config_value(path, "workspace.concurrency", value).map(Some)
}

fn read_global_workspace_concurrency_from_file(
    path: &Path,
) -> Result<Option<NonZeroUsize>, LpmError> {
    let Some(table) = read_toml_table(path)? else {
        return Ok(None);
    };

    let Some(value) = table.get("workspace-concurrency") else {
        return Ok(None);
    };

    parse_config_value(path, "workspace-concurrency", value).map(Some)
}

fn read_toml_table(path: &Path) -> Result<Option<toml::map::Map<String, toml::Value>>, LpmError> {
    let raw = match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
    {
        Ok(raw) => raw,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(None),
        Err(error) => return Err(LpmError::Registry(error.to_string())),
    };
    let parsed: toml::Value = toml::from_str(&raw)
        .map_err(|e| LpmError::Registry(format!("failed to parse {}: {e}", path.display())))?;

    match parsed {
        toml::Value::Table(table) => Ok(Some(table)),
        _ => Err(LpmError::Registry(format!(
            "{} must be a TOML table at the top level",
            path.display()
        ))),
    }
}

fn parse_config_value(
    path: &Path,
    key: &str,
    value: &toml::Value,
) -> Result<NonZeroUsize, LpmError> {
    let parsed = match value {
        toml::Value::Integer(raw) => usize::try_from(*raw).ok().and_then(NonZeroUsize::new),
        toml::Value::String(raw) => parse_workspace_concurrency(raw).ok(),
        _ => None,
    };

    parsed.ok_or_else(|| {
        LpmError::Registry(format!(
            "{}: `{key}` must be a positive integer, got {value}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::ScopedEnv;
    use std::ffi::OsString;
    use std::fs;

    struct Fixture {
        project: tempfile::TempDir,
        lpm_home: tempfile::TempDir,
        _env: ScopedEnv,
    }

    impl Fixture {
        fn new() -> Self {
            let project = tempfile::tempdir().unwrap();
            let lpm_home = tempfile::tempdir().unwrap();
            let _env = ScopedEnv::set([("LPM_HOME", OsString::from(lpm_home.path().as_os_str()))]);
            Self {
                project,
                lpm_home,
                _env,
            }
        }

        fn write_project_config(&self, contents: &str) {
            fs::write(self.project.path().join("lpm.toml"), contents).unwrap();
        }

        fn write_global_config(&self, contents: &str) {
            fs::write(self.lpm_home.path().join("config.toml"), contents).unwrap();
        }
    }

    #[test]
    fn parser_accepts_positive_integer() {
        assert_eq!(parse_workspace_concurrency("8").unwrap().get(), 8);
    }

    #[test]
    fn parser_rejects_zero() {
        assert!(parse_workspace_concurrency("0").is_err());
    }

    #[test]
    fn parser_rejects_non_integer_values() {
        assert!(parse_workspace_concurrency("-1").is_err());
        assert!(parse_workspace_concurrency("+1").is_err());
        assert!(parse_workspace_concurrency("1.5").is_err());
        assert!(parse_workspace_concurrency("Infinity").is_err());
    }

    #[test]
    fn cli_value_overrides_project_and_global_config() {
        let fixture = Fixture::new();
        fixture.write_project_config("[workspace]\nconcurrency = 2\n");
        fixture.write_global_config("workspace-concurrency = 3\n");

        let resolved =
            resolve_workspace_concurrency(fixture.project.path(), NonZeroUsize::new(1)).unwrap();

        assert_eq!(resolved.get(), 1);
    }

    #[test]
    fn project_config_overrides_global_config() {
        let fixture = Fixture::new();
        fixture.write_project_config("[workspace]\nconcurrency = 2\n");
        fixture.write_global_config("workspace-concurrency = 3\n");

        let resolved = resolve_workspace_concurrency(fixture.project.path(), None).unwrap();

        assert_eq!(resolved.get(), 2);
    }

    #[test]
    fn global_config_accepts_string_value_written_by_config_set() {
        let fixture = Fixture::new();
        fixture.write_global_config(r#"workspace-concurrency = "3""#);

        let resolved = resolve_workspace_concurrency(fixture.project.path(), None).unwrap();

        assert_eq!(resolved.get(), 3);
    }

    #[test]
    fn project_config_zero_errors_with_file_path() {
        let fixture = Fixture::new();
        fixture.write_project_config("[workspace]\nconcurrency = 0\n");

        let err = resolve_workspace_concurrency(fixture.project.path(), None)
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("lpm.toml"),
            "error should name the project config file: {err}"
        );
        assert!(
            err.contains("workspace.concurrency"),
            "error should name the invalid key: {err}"
        );
    }
}
