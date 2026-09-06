use crate::sandbox_config::ResolvedSandboxMode;
use crate::source_analysis_config::INSTALL_TIME_SOURCE_ANALYSIS_KEY;
use lpm_common::LpmError;

use super::GlobalConfig;
use super::wizards::{
    RELEASE_AGE_KEY, RELEASE_AGE_POLICY_KEY, SCRIPT_POLICY_KEY, TYPOSQUAT_GUARD_KEY,
    TyposquatGuardSelection, parse_config_bool, reject_looser_typosquat_guard_write,
};

pub(super) fn read_config(path: &std::path::Path) -> Result<toml::Value, LpmError> {
    let content = match lpm_common::read_text_file_capped_nofollow(
        path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return Ok(toml::Value::Table(toml::map::Map::new()));
        }
        Err(error) => return Err(LpmError::Registry(error.to_string())),
    };
    toml::from_str(&content).map_err(|e| LpmError::Registry(format!("config parse error: {e}")))
}

pub(crate) async fn update_config<R>(
    path: &std::path::Path,
    update: impl FnOnce(&mut GlobalConfig) -> Result<(R, bool), LpmError>,
) -> Result<R, LpmError> {
    ensure_config_parent(path)?;
    let lock_path = path.with_file_name(".config.lock");
    let _lock = acquire_config_lock(&lock_path).await?;
    let snapshot = ConfigFileSnapshot::capture(path)?;
    let posture_transaction = crate::security_approval::begin_authorized_posture_transaction()?;
    let mut config = GlobalConfig::from_value(snapshot.parse(path)?)?;
    let (result, storage_changed) = update(&mut config)?;
    let config = config.into_value();
    let config_changed = storage_changed && snapshot.differs_from(&config, path)?;
    if config_changed {
        write_config(path, &config, snapshot.content.as_deref())?;
    }
    if let Err(error) = posture_transaction.commit() {
        if config_changed && let Err(rollback_error) = snapshot.restore(path) {
            return Err(LpmError::Registry(format!(
                "failed to commit approved security posture: {error}; config rollback also failed: {rollback_error}"
            )));
        }
        return Err(error);
    }
    Ok(result)
}

fn ensure_config_parent(path: &std::path::Path) -> Result<(), LpmError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let create_parent = !parent.exists();
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    if create_parent {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

async fn acquire_config_lock(
    path: &std::path::Path,
) -> Result<lpm_common::ExclusiveLockHandle, LpmError> {
    acquire_config_lock_with_timeout(path, std::time::Duration::from_secs(30)).await
}

async fn acquire_config_lock_with_timeout(
    path: &std::path::Path,
    timeout: std::time::Duration,
) -> Result<lpm_common::ExclusiveLockHandle, LpmError> {
    let started = std::time::Instant::now();
    loop {
        if let Some(lock) = lpm_common::try_acquire_exclusive_lock(path)? {
            return Ok(lock);
        }
        if started.elapsed() >= timeout {
            return Err(LpmError::Registry(format!(
                "timed out after {} seconds waiting for the config transaction lock {}",
                timeout.as_secs_f64(),
                path.display()
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

struct ConfigFileSnapshot {
    content: Option<String>,
    #[cfg(unix)]
    mode: Option<u32>,
}

impl ConfigFileSnapshot {
    fn capture(path: &std::path::Path) -> Result<Self, LpmError> {
        match lpm_common::read_text_file_capped_nofollow(
            path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(content) => {
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt as _;
                    Some(std::fs::metadata(path)?.permissions().mode() & 0o7777)
                };
                Ok(Self {
                    content: Some(content),
                    #[cfg(unix)]
                    mode,
                })
            }
            Err(lpm_common::BoundedReadError::NotFound { .. }) => Ok(Self {
                content: None,
                #[cfg(unix)]
                mode: None,
            }),
            Err(error) => Err(LpmError::Registry(error.to_string())),
        }
    }

    fn restore(&self, path: &std::path::Path) -> Result<(), LpmError> {
        if let Some(content) = self.content.as_ref() {
            let mut options = lpm_common::AtomicWriteOptions::new();
            #[cfg(unix)]
            if let Some(mode) = self.mode {
                options = options.unix_mode(mode);
            }
            lpm_common::write_file_atomic_with_options(path, content.as_bytes(), options)?;
        } else {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(LpmError::Io(error)),
            }
        }
        Ok(())
    }

    fn parse(&self, path: &std::path::Path) -> Result<toml::Value, LpmError> {
        match self.content.as_deref() {
            Some(content) => toml::from_str(content)
                .map_err(|error| LpmError::Registry(format!("config parse error: {error}"))),
            None => Ok(toml::Value::Table(toml::map::Map::new())),
        }
        .map_err(|error| match error {
            LpmError::Registry(message) => {
                LpmError::Registry(format!("{}: {message}", path.display()))
            }
            error => error,
        })
    }

    fn differs_from(&self, config: &toml::Value, path: &std::path::Path) -> Result<bool, LpmError> {
        match self.content.as_deref() {
            Some(content) => {
                let current: toml::Value = toml::from_str(content).map_err(|error| {
                    LpmError::Registry(format!("config parse error in {}: {error}", path.display()))
                })?;
                Ok(current != *config)
            }
            None => Ok(config.as_table().is_some_and(|table| !table.is_empty())),
        }
    }
}

fn write_config(
    path: &std::path::Path,
    config: &toml::Value,
    existing: Option<&str>,
) -> Result<(), LpmError> {
    ensure_config_parent(path)?;
    let content = render_config_preserving_layout(path, existing.unwrap_or_default(), config)?;
    if content.len() as u64 > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Registry(format!(
            "config serialize error: {} exceeds the {}-byte limit after serialization",
            path.display(),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )));
    }
    lpm_common::write_file_atomic_with_options(
        path,
        content,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o600),
    )
    .map_err(LpmError::Io)
}

fn render_config_preserving_layout(
    path: &std::path::Path,
    existing: &str,
    config: &toml::Value,
) -> Result<String, LpmError> {
    let mut document = existing
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| {
            LpmError::Registry(format!("config parse error in {}: {error}", path.display()))
        })?;
    let replacement = toml::to_string_pretty(config)
        .map_err(|error| LpmError::Registry(format!("config serialize error: {error}")))?
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| LpmError::Registry(format!("config serialize error: {error}")))?;
    merge_document_table(document.as_table_mut(), replacement.as_table());
    Ok(document.to_string())
}

fn merge_document_table(target: &mut toml_edit::Table, replacement: &toml_edit::Table) {
    let removed: Vec<_> = target
        .iter()
        .filter(|(key, _)| !replacement.contains_key(key))
        .map(|(key, _)| key.to_string())
        .collect();
    for key in removed {
        target.remove(&key);
    }

    for (key, replacement_item) in replacement {
        let Some(target_item) = target.get_mut(key) else {
            target.insert(key, replacement_item.clone());
            continue;
        };
        if document_items_equal(target_item, replacement_item) {
            continue;
        }
        if let (Some(target_table), Some(replacement_table)) =
            (target_item.as_table_mut(), replacement_item.as_table())
        {
            merge_document_table(target_table, replacement_table);
        } else {
            let mut item = replacement_item.clone();
            preserve_item_decor(target_item, &mut item);
            *target_item = item;
        }
    }
}

fn document_items_equal(left: &toml_edit::Item, right: &toml_edit::Item) -> bool {
    match (left, right) {
        (toml_edit::Item::None, toml_edit::Item::None) => true,
        (toml_edit::Item::Value(left), toml_edit::Item::Value(right)) => {
            document_values_equal(left, right)
        }
        (toml_edit::Item::Table(left), toml_edit::Item::Table(right)) => {
            document_tables_equal(left, right)
        }
        (toml_edit::Item::ArrayOfTables(left), toml_edit::Item::ArrayOfTables(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right.iter())
                    .all(|(left, right)| document_tables_equal(left, right))
        }
        _ => false,
    }
}

fn document_values_equal(left: &toml_edit::Value, right: &toml_edit::Value) -> bool {
    match (left, right) {
        (toml_edit::Value::String(left), toml_edit::Value::String(right)) => {
            left.value() == right.value()
        }
        (toml_edit::Value::Integer(left), toml_edit::Value::Integer(right)) => {
            left.value() == right.value()
        }
        (toml_edit::Value::Float(left), toml_edit::Value::Float(right)) => {
            left.value() == right.value()
        }
        (toml_edit::Value::Boolean(left), toml_edit::Value::Boolean(right)) => {
            left.value() == right.value()
        }
        (toml_edit::Value::Datetime(left), toml_edit::Value::Datetime(right)) => {
            left.value() == right.value()
        }
        (toml_edit::Value::Array(left), toml_edit::Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right.iter())
                    .all(|(left, right)| document_values_equal(left, right))
        }
        (toml_edit::Value::InlineTable(left), toml_edit::Value::InlineTable(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, left)| {
                    right
                        .get(key)
                        .is_some_and(|right| document_values_equal(left, right))
                })
        }
        _ => false,
    }
}

fn document_tables_equal(left: &toml_edit::Table, right: &toml_edit::Table) -> bool {
    left.len() == right.len()
        && left.iter().all(|(key, left)| {
            right
                .get(key)
                .is_some_and(|right| document_items_equal(left, right))
        })
}

fn preserve_item_decor(previous: &toml_edit::Item, replacement: &mut toml_edit::Item) {
    match (previous, replacement) {
        (toml_edit::Item::Value(previous), toml_edit::Item::Value(replacement)) => {
            *replacement.decor_mut() = previous.decor().clone();
        }
        (toml_edit::Item::Table(previous), toml_edit::Item::Table(replacement)) => {
            *replacement.decor_mut() = previous.decor().clone();
        }
        _ => {}
    }
}

pub(super) fn config_value_to_json(value: &toml::Value) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

pub(super) fn redact_config_json_value(key: &str, value: serde_json::Value) -> serde_json::Value {
    if config_key_is_sensitive(key) {
        return serde_json::Value::String("[REDACTED]".to_string());
    }
    match value {
        serde_json::Value::String(value) => {
            serde_json::Value::String(redact_url_credentials(value))
        }
        serde_json::Value::Array(values) if key == "command" || key.ends_with(".command") => {
            serde_json::Value::Array(redact_command_arguments(values))
        }
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .into_iter()
                .map(|value| redact_config_json_value(key, value))
                .collect(),
        ),
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(child, value)| {
                    let child_key = if key.is_empty() {
                        child.clone()
                    } else {
                        format!("{key}.{child}")
                    };
                    (child, redact_config_json_value(&child_key, value))
                })
                .collect(),
        ),
        value => value,
    }
}

fn config_key_is_sensitive(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized.split('.').any(|component| {
        let compact: String = component
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .collect();
        component
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(is_sensitive_key_part)
            || [
                "password",
                "passwd",
                "secret",
                "token",
                "credential",
                "credentials",
                "authorization",
                "apikey",
                "accesstoken",
                "refreshtoken",
                "clientsecret",
                "privatekey",
                "cookie",
                "signature",
            ]
            .iter()
            .any(|suffix| compact == *suffix || compact.ends_with(suffix))
    })
}

fn is_sensitive_key_part(part: &str) -> bool {
    matches!(
        part,
        "auth"
            | "password"
            | "passwd"
            | "secret"
            | "token"
            | "credential"
            | "credentials"
            | "authorization"
            | "apikey"
            | "accesstoken"
            | "refreshtoken"
            | "clientsecret"
            | "privatekey"
            | "cookie"
            | "signature"
    )
}

fn redact_url_credentials(value: String) -> String {
    if !value.contains("://") {
        return value;
    }
    let Ok(mut url) = reqwest::Url::parse(&value) else {
        return value;
    };
    let mut changed = false;
    if !url.username().is_empty() {
        let _ = url.set_username("REDACTED");
        changed = true;
    }
    if url.password().is_some() {
        let _ = url.set_password(Some("REDACTED"));
        changed = true;
    }
    if url.query().is_some() {
        let pairs: Vec<_> = url
            .query_pairs()
            .map(|(key, value)| {
                let value = if config_key_is_sensitive(&key) {
                    std::borrow::Cow::Borrowed("REDACTED")
                } else {
                    value
                };
                (key.into_owned(), value.into_owned())
            })
            .collect();
        if pairs.iter().any(|(_, value)| value == "REDACTED") {
            url.query_pairs_mut().clear().extend_pairs(pairs);
            changed = true;
        }
    }
    if changed { url.to_string() } else { value }
}

fn redact_command_arguments(mut values: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    let mut redact_next = false;
    for value in &mut values {
        let Some(argument) = value.as_str() else {
            redact_next = false;
            continue;
        };
        if redact_next {
            *value = serde_json::Value::String("[REDACTED]".to_string());
            redact_next = false;
            continue;
        }
        if let Some((flag, _)) = argument.split_once('=')
            && config_key_is_sensitive(flag)
        {
            *value = serde_json::Value::String(format!("{flag}=[REDACTED]"));
        } else if config_key_is_sensitive(argument.trim_start_matches('-')) {
            redact_next = true;
        } else if argument
            .split_once(':')
            .is_some_and(|(header, _)| config_key_is_sensitive(header))
        {
            *value = serde_json::Value::String(format!(
                "{}: [REDACTED]",
                argument.split_once(':').expect("header was present").0
            ));
        } else {
            let redacted = redact_url_credentials(argument.to_string());
            if redacted != argument {
                *value = serde_json::Value::String(redacted);
            }
        }
    }
    values
}

pub(super) fn config_value_at_path<'a>(
    config: &'a toml::map::Map<String, toml::Value>,
    key: &str,
) -> Option<&'a toml::Value> {
    let mut segments = key.split('.');
    let first = segments.next()?;
    if first.is_empty() {
        return None;
    }
    let mut value = config.get(first)?;
    for segment in segments {
        if segment.is_empty() {
            return None;
        }
        value = value.as_table()?.get(segment)?;
    }
    Some(value)
}

pub(super) fn remove_config_value_at_path(
    config: &mut toml::map::Map<String, toml::Value>,
    key: &str,
) -> bool {
    let mut segments = key.split('.').peekable();
    let mut table = config;
    while let Some(segment) = segments.next() {
        if segment.is_empty() {
            return false;
        }
        if segments.peek().is_none() {
            return table.remove(segment).is_some();
        }
        let Some(next) = table.get_mut(segment).and_then(toml::Value::as_table_mut) else {
            return false;
        };
        table = next;
    }
    false
}

pub(super) fn config_value_for_display(value: &toml::Value) -> String {
    match value {
        toml::Value::Boolean(value) => value.to_string(),
        toml::Value::Integer(value) => value.to_string(),
        toml::Value::Float(value) => value.to_string(),
        toml::Value::Datetime(value) => value.to_string(),
        _ => value.to_string(),
    }
}

pub(super) fn guard_generic_set_against_force_floor(
    config: &GlobalConfig,
    key: &str,
    value: &str,
) -> Result<(), LpmError> {
    let global = config;
    match key {
        "force-security-floor"
            if crate::security_floor::force_security_floor_enabled(global)
                && !matches!(value, "true" | "1" | "yes") =>
        {
            return Err(crate::security_floor::security_floor_write_error(
                "force-security-floor",
                value,
                "true",
            ));
        }
        SCRIPT_POLICY_KEY => {
            if let Ok(requested) = crate::script_policy_config::ScriptPolicy::parse(value) {
                crate::security_floor::reject_looser_script_policy_write(global, requested)?;
            }
        }
        RELEASE_AGE_KEY => {
            if let Some(requested_secs) = crate::release_age_config::parse_strict_u64_string(value)
            {
                crate::security_floor::reject_looser_release_age_write(global, requested_secs)?;
            }
        }
        RELEASE_AGE_POLICY_KEY => {
            if let Ok(requested) = crate::release_age_config::ReleaseAgePolicy::parse(key, value) {
                crate::security_floor::reject_looser_release_age_policy_write(global, requested)?;
            }
        }
        TYPOSQUAT_GUARD_KEY => {
            if let Some(requested) = TyposquatGuardSelection::parse(value) {
                reject_looser_typosquat_guard_write(global, requested)?;
            }
        }
        INSTALL_TIME_SOURCE_ANALYSIS_KEY
            if crate::security_floor::force_security_floor_enabled(global)
                && crate::source_analysis_config::read_install_time_source_analysis(global)?
                && matches!(parse_config_bool(value), Ok(false)) =>
        {
            return Err(crate::security_floor::security_floor_write_error(
                INSTALL_TIME_SOURCE_ANALYSIS_KEY,
                value,
                "true",
            ));
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn guard_generic_delete_against_force_floor(
    config: &GlobalConfig,
    key: &str,
) -> Result<(), LpmError> {
    let global = config;
    match key {
        RELEASE_AGE_KEY => crate::security_floor::reject_looser_release_age_write(
            global,
            crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS,
        )?,
        RELEASE_AGE_POLICY_KEY => crate::security_floor::reject_looser_release_age_policy_write(
            global,
            crate::release_age_config::ReleaseAgePolicy::Direct,
        )?,
        "sandbox" => crate::security_floor::reject_looser_sandbox_mode_write(
            global,
            ResolvedSandboxMode::Default,
        )?,
        TYPOSQUAT_GUARD_KEY => {
            reject_looser_typosquat_guard_write(global, TyposquatGuardSelection::Default)?
        }
        INSTALL_TIME_SOURCE_ANALYSIS_KEY => guard_generic_set_against_force_floor(
            global,
            key,
            if crate::source_analysis_config::DEFAULT_INSTALL_TIME_SOURCE_ANALYSIS {
                "true"
            } else {
                "false"
            },
        )?,
        "force-security-floor" if crate::security_floor::force_security_floor_enabled(global) => {
            return Err(crate::security_floor::security_floor_write_error(
                "force-security-floor",
                "unset",
                "true",
            ));
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_writer_rejects_serialized_output_above_the_read_cap() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "color = \"always\"\n").unwrap();
        let before = std::fs::read(&path).unwrap();
        let oversized = "x".repeat(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize);
        let mut table = toml::map::Map::new();
        table.insert("payload".to_string(), toml::Value::String(oversized));

        let err = write_config(
            &path,
            &toml::Value::Table(table),
            Some("color = \"always\"\n"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds"), "got: {err}");
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn config_reader_rejects_a_fifo_without_waiting_for_a_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let result = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        let started = std::time::Instant::now();
        let err = read_config(&path).unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(err.to_string().contains("regular file"), "got: {err}");
    }

    #[tokio::test]
    async fn config_lock_contention_has_a_bounded_wait() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".config.lock");
        let _held = lpm_common::acquire_exclusive_lock(&path).unwrap();

        let started = std::time::Instant::now();
        let error =
            match acquire_config_lock_with_timeout(&path, std::time::Duration::from_millis(75))
                .await
            {
                Ok(_) => panic!("contended config lock unexpectedly succeeded"),
                Err(error) => error,
            };

        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(error.to_string().contains("timed out"), "got: {error}");
    }

    #[test]
    fn redaction_covers_composite_secret_keys_urls_and_command_arguments() {
        assert_eq!(
            redact_config_json_value("registry.api_key", serde_json::json!("secret")),
            serde_json::json!("[REDACTED]")
        );
        assert_eq!(
            redact_config_json_value(
                "registry",
                serde_json::json!("https://user:pass@example.test/path?access_token=secret")
            ),
            serde_json::json!("https://REDACTED:REDACTED@example.test/path?access_token=REDACTED")
        );
        assert_eq!(
            redact_config_json_value(
                "policy.extensions.scan.command",
                serde_json::json!([
                    "scanner",
                    "--api-key",
                    "secret",
                    "https://user:pass@example.test/input"
                ])
            ),
            serde_json::json!([
                "scanner",
                "--api-key",
                "[REDACTED]",
                "https://REDACTED:REDACTED@example.test/input"
            ])
        );
    }
}
