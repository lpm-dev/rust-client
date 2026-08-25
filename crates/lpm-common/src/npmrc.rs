use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;

pub const NPMRC_INTERPOLATED_VALUE_CAP_BYTES: usize = 4 * 1024 * 1024;
pub const NPMRC_DIAGNOSTIC_LIMIT: usize = 100;

pub fn push_npmrc_diagnostic(
    diagnostics: &mut Vec<String>,
    source_label: &str,
    make_diagnostic: impl FnOnce() -> String,
) {
    match diagnostics.len() {
        0..NPMRC_DIAGNOSTIC_LIMIT => diagnostics.push(make_diagnostic()),
        NPMRC_DIAGNOSTIC_LIMIT => diagnostics.push(format!(
            "{source_label}: additional npm configuration diagnostics suppressed"
        )),
        _ => {}
    }
}

fn nonempty_env_os(name: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

pub fn npm_config_path(name: &str) -> Option<PathBuf> {
    npm_config_path_with_home(name, dirs::home_dir().as_deref())
}

pub fn npm_config_path_with_home(name: &str, home: Option<&Path>) -> Option<PathBuf> {
    let uppercase = format!("NPM_CONFIG_{}", name.to_ascii_uppercase());
    let lowercase = format!("npm_config_{name}");
    nonempty_env_os(&uppercase)
        .or_else(|| nonempty_env_os(&lowercase))
        .map(PathBuf::from)
        .map(|path| expand_home_path(path, home))
}

pub fn npm_user_config_path(home: Option<&Path>) -> Option<PathBuf> {
    npm_config_path_with_home("userconfig", home)
        .or_else(|| home.map(|directory| directory.join(".npmrc")))
}

pub fn npm_global_config_path(home: Option<&Path>) -> PathBuf {
    let user_config = npm_user_config_path(home).and_then(|path| {
        crate::read_text_regular_file_capped_with_metadata(&path, crate::NPMRC_FILE_SIZE_CAP_BYTES)
            .ok()
    });
    npm_global_config_path_from_user_config(
        home,
        user_config
            .as_ref()
            .map(|(content, metadata)| (content.as_str(), metadata)),
    )
}

pub fn npm_global_config_path_from_user_config(
    home: Option<&Path>,
    user_config: Option<(&str, &std::fs::Metadata)>,
) -> PathBuf {
    if let Some(path) = npm_config_path_with_home("globalconfig", home) {
        return path;
    }

    let prefix = npm_config_path_with_home("prefix", home)
        .or_else(|| {
            user_config
                .filter(|(_, metadata)| npmrc_can_influence_config_discovery(metadata))
                .and_then(|(content, _)| npm_user_config_prefix(content))
        })
        .or_else(|| nonempty_env_os("PREFIX").map(PathBuf::from))
        .map_or_else(node_install_prefix, |path| expand_home_path(path, home));
    absolutize_path(prefix).join("etc/npmrc")
}

#[inline]
pub fn npmrc_can_influence_config_discovery(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        metadata.permissions().mode() & 0o022 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn npm_user_config_prefix(content: &str) -> Option<PathBuf> {
    let mut warnings = Vec::new();
    parse_npmrc_ini_settings(
        crate::strip_utf8_bom_str(content),
        "user npm config",
        &mut warnings,
    )
    .into_iter()
    .find(|setting| setting.key.as_ref() == "prefix" && !setting.is_array)
    .and_then(|setting| {
        setting
            .values
            .last()
            .map(|value| value.value.trim().to_owned())
    })
    .filter(|value| !value.is_empty())
    .map(PathBuf::from)
}

fn expand_home_path(path: PathBuf, home: Option<&Path>) -> PathBuf {
    let Some(home) = home else {
        return path;
    };
    if path == Path::new("~") {
        return home.to_path_buf();
    }
    if let Ok(suffix) = path.strip_prefix("~")
        && suffix.components().next().is_some()
    {
        return home.join(suffix);
    }
    path
}

fn absolutize_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir().map_or(path.clone(), |cwd| cwd.join(path))
    }
}

fn node_install_prefix() -> PathBuf {
    let executable = nonempty_env_os("NODE")
        .map(PathBuf::from)
        .or_else(find_node_on_path)
        .and_then(|path| std::fs::canonicalize(&path).ok().or(Some(path)));
    if let Some(executable) = executable {
        #[cfg(windows)]
        if let Some(parent) = executable.parent() {
            return parent.to_path_buf();
        }
        #[cfg(not(windows))]
        if let Some(prefix) = executable.parent().and_then(Path::parent) {
            let prefix = prefix.to_path_buf();
            if let Some(destination) = nonempty_env_os("DESTDIR") {
                return PathBuf::from(destination)
                    .join(prefix.strip_prefix("/").unwrap_or(&prefix));
            }
            return prefix;
        }
    }
    #[cfg(windows)]
    {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("C:\\"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/usr/local")
    }
}

fn find_node_on_path() -> Option<PathBuf> {
    let path = nonempty_env_os("PATH")?;
    let executable_name = if cfg!(windows) { "node.exe" } else { "node" };
    std::env::split_paths(&path)
        .map(|directory| directory.join(executable_name))
        .find(|candidate| candidate.is_file())
}

#[derive(Debug)]
pub struct NpmrcIniValue<'a> {
    pub value: Cow<'a, str>,
    pub line: usize,
}

#[derive(Debug)]
pub struct NpmrcIniSetting<'a> {
    pub key: Arc<str>,
    pub values: smallvec::SmallVec<[NpmrcIniValue<'a>; 1]>,
    pub is_array: bool,
}

pub fn parse_npmrc_ini_settings<'a>(
    content: &'a str,
    source_label: &str,
    warnings: &mut Vec<String>,
) -> Vec<NpmrcIniSetting<'a>> {
    let mut settings = Vec::<NpmrcIniSetting>::new();
    let mut indices = HashMap::<Arc<str>, usize>::new();
    let mut in_section = false;

    let mut parse_line = |raw_line: &'a str, line_number: usize| {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            return;
        }
        if raw_line.starts_with('[')
            && raw_line
                .find(']')
                .is_some_and(|end| raw_line[end + 1..].trim().is_empty())
        {
            in_section = true;
            return;
        }
        if in_section {
            return;
        }

        let (raw_key, raw_value) = if let Some(eq_index) = raw_line.find('=') {
            (&raw_line[..eq_index], &raw_line[eq_index + 1..])
        } else {
            push_npmrc_diagnostic(warnings, source_label, || {
                format!(
                    "{source_label}:{line_number}: line has no '=' separator; interpreted as true"
                )
            });
            (raw_line, "true")
        };
        let decoded_key = decode_npmrc_ini_fragment(raw_key);
        let decoded_key = decoded_key.as_ref();
        let is_array = decoded_key.ends_with("[]") && decoded_key.len() > 2;
        let key = if is_array {
            &decoded_key[..decoded_key.len() - 2]
        } else {
            decoded_key
        };
        if key.is_empty() || key == "__proto__" {
            return;
        }
        let value = NpmrcIniValue {
            value: decode_npmrc_ini_fragment(raw_value),
            line: line_number,
        };

        if let Some(index) = indices.get(key).copied() {
            let setting = &mut settings[index];
            if is_array || setting.is_array {
                setting.is_array = true;
                setting.values.push(value);
            } else {
                setting.values.clear();
                setting.values.push(value);
            }
        } else {
            let key: Arc<str> = Arc::from(key);
            indices.insert(Arc::clone(&key), settings.len());
            settings.push(NpmrcIniSetting {
                key,
                values: smallvec::smallvec![value],
                is_array,
            });
        }
    };

    let bytes = content.as_bytes();
    let mut line_start = 0;
    let mut line_number = 1;
    let mut index = 0;
    loop {
        if index == bytes.len() {
            parse_line(&content[line_start..index], line_number);
            break;
        }
        if matches!(bytes[index], b'\r' | b'\n') {
            parse_line(&content[line_start..index], line_number);
            if bytes[index] == b'\r' && bytes.get(index + 1).is_some_and(|next| *next == b'\n') {
                index += 1;
            }
            index += 1;
            line_start = index;
            line_number += 1;
        } else {
            index += 1;
        }
    }

    settings
}

pub fn decode_npmrc_ini_fragment(value: &str) -> Cow<'_, str> {
    let value = value.trim();
    let quoted = value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')));
    if quoted {
        if value.starts_with('"') {
            return Cow::Owned(
                serde_json::from_str::<String>(value).unwrap_or_else(|_| value.to_string()),
            );
        }
        let inner = &value[1..value.len() - 1];
        return Cow::Owned(
            serde_json::from_str::<String>(inner).unwrap_or_else(|_| inner.to_string()),
        );
    }

    if !value
        .bytes()
        .any(|byte| matches!(byte, b'\\' | b';' | b'#'))
    {
        return Cow::Borrowed(value);
    }

    let mut decoded = String::with_capacity(value.len());
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            if matches!(ch, '\\' | ';' | '#') {
                decoded.push(ch);
            } else {
                decoded.push('\\');
                decoded.push(ch);
            }
            escaped = false;
        } else if matches!(ch, ';' | '#') {
            break;
        } else if ch == '\\' {
            escaped = true;
        } else {
            decoded.push(ch);
        }
    }
    if escaped {
        decoded.push('\\');
    }
    let trimmed = decoded.trim();
    let start = trimmed.as_ptr() as usize - decoded.as_ptr() as usize;
    let trimmed_len = trimmed.len();
    if start > 0 {
        decoded.drain(..start);
    }
    decoded.truncate(trimmed_len);
    Cow::Owned(decoded)
}

#[derive(Debug, Error)]
#[error("npm configuration environment expansion exceeds the {limit}-byte limit")]
pub struct NpmrcInterpolationError {
    limit: usize,
}

pub fn interpolate_npmrc_env<'a>(
    value: &'a str,
    env_lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<Cow<'a, str>, NpmrcInterpolationError> {
    if !value.contains("${") {
        return Ok(Cow::Borrowed(value));
    }
    if value.len() > NPMRC_INTERPOLATED_VALUE_CAP_BYTES {
        return Err(NpmrcInterpolationError {
            limit: NPMRC_INTERPOLATED_VALUE_CAP_BYTES,
        });
    }
    let mut environment = HashMap::<&str, Option<String>>::new();
    if !npmrc_interpolation_changes_value(value, env_lookup, &mut environment) {
        return Ok(Cow::Borrowed(value));
    }

    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let slash_start = index;
        while index < bytes.len() && bytes[index] == b'\\' {
            index += 1;
        }
        let slash_count = index - slash_start;

        if index + 1 < bytes.len() && bytes[index] == b'$' && bytes[index + 1] == b'{' {
            let mut cursor = index + 2;
            let mut optional = false;
            let mut end = None;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'}' => {
                        end = Some(cursor);
                        break;
                    }
                    b'?' if bytes.get(cursor + 1) == Some(&b'}') => {
                        optional = true;
                        end = Some(cursor + 1);
                        break;
                    }
                    b'$' | b'{' | b'?' => break,
                    _ => cursor += 1,
                }
            }
            if let Some(end) = end {
                let name_end = if optional { end - 1 } else { end };
                let name = &value[index + 2..name_end];
                if !name.is_empty() {
                    append_repeated(&mut out, '\\', slash_count / 2)?;
                    if slash_count % 2 == 1 {
                        append_capped(&mut out, &value[index..=end])?;
                    } else {
                        let replacement =
                            environment.entry(name).or_insert_with(|| env_lookup(name));
                        if let Some(replacement) = replacement {
                            append_capped(&mut out, replacement)?;
                        } else if !optional {
                            append_capped(&mut out, "${")?;
                            append_capped(&mut out, name)?;
                            append_capped(&mut out, "}")?;
                        }
                    }
                    index = end + 1;
                    continue;
                }
            }
        }

        append_repeated(&mut out, '\\', slash_count)?;
        if index >= bytes.len() {
            break;
        }
        let ch = value[index..]
            .chars()
            .next()
            .expect("index is within value");
        append_char_capped(&mut out, ch)?;
        index += ch.len_utf8();
    }
    Ok(Cow::Owned(out))
}

fn npmrc_interpolation_changes_value<'a>(
    value: &'a str,
    env_lookup: &dyn Fn(&str) -> Option<String>,
    environment: &mut HashMap<&'a str, Option<String>>,
) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        let slash_start = index;
        while index < bytes.len() && bytes[index] == b'\\' {
            index += 1;
        }
        let slash_count = index - slash_start;
        if index + 1 >= bytes.len() || bytes[index] != b'$' || bytes[index + 1] != b'{' {
            index = index.saturating_add(1);
            continue;
        }

        let mut cursor = index + 2;
        let mut optional = false;
        let mut end = None;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'}' => {
                    end = Some(cursor);
                    break;
                }
                b'?' if bytes.get(cursor + 1) == Some(&b'}') => {
                    optional = true;
                    end = Some(cursor + 1);
                    break;
                }
                b'$' | b'{' | b'?' => break,
                _ => cursor += 1,
            }
        }
        let Some(end) = end else {
            index += 2;
            continue;
        };
        let name_end = if optional { end - 1 } else { end };
        let name = &value[index + 2..name_end];
        if name.is_empty() {
            index = end + 1;
            continue;
        }
        if slash_count > 0 {
            return true;
        }
        let replacement = environment.entry(name).or_insert_with(|| env_lookup(name));
        match replacement {
            Some(replacement) if replacement != &value[index..=end] => return true,
            None if optional => return true,
            _ => {}
        }
        index = end + 1;
    }
    false
}

fn append_capped(out: &mut String, value: &str) -> Result<(), NpmrcInterpolationError> {
    if out.len().saturating_add(value.len()) > NPMRC_INTERPOLATED_VALUE_CAP_BYTES {
        return Err(NpmrcInterpolationError {
            limit: NPMRC_INTERPOLATED_VALUE_CAP_BYTES,
        });
    }
    out.push_str(value);
    Ok(())
}

fn append_char_capped(out: &mut String, value: char) -> Result<(), NpmrcInterpolationError> {
    if out.len().saturating_add(value.len_utf8()) > NPMRC_INTERPOLATED_VALUE_CAP_BYTES {
        return Err(NpmrcInterpolationError {
            limit: NPMRC_INTERPOLATED_VALUE_CAP_BYTES,
        });
    }
    out.push(value);
    Ok(())
}

fn append_repeated(
    out: &mut String,
    value: char,
    count: usize,
) -> Result<(), NpmrcInterpolationError> {
    let additional = value.len_utf8().saturating_mul(count);
    if out.len().saturating_add(additional) > NPMRC_INTERPOLATED_VALUE_CAP_BYTES {
        return Err(NpmrcInterpolationError {
            limit: NPMRC_INTERPOLATED_VALUE_CAP_BYTES,
        });
    }
    out.extend(std::iter::repeat_n(value, count));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        NPMRC_INTERPOLATED_VALUE_CAP_BYTES, interpolate_npmrc_env, npm_config_path,
        parse_npmrc_ini_settings,
    };
    use std::borrow::Cow;
    use std::cell::Cell;

    #[test]
    fn npmrc_interpolation_bounds_expanded_output_and_caches_environment_lookups() {
        let lookups = Cell::new(0);
        let repeated = "${TOKEN}".repeat(5_000);
        let error = interpolate_npmrc_env(&repeated, &|name| {
            assert_eq!(name, "TOKEN");
            lookups.set(lookups.get() + 1);
            Some("x".repeat(NPMRC_INTERPOLATED_VALUE_CAP_BYTES / 4))
        })
        .expect_err("expanded npm configuration must be bounded");

        assert!(error.to_string().contains("4194304"));
        assert_eq!(lookups.get(), 1, "one variable must be read only once");
    }

    #[test]
    fn malformed_npmrc_interpolation_is_scanned_once_and_preserved() {
        let value = "${".repeat(512 * 1024);

        let expanded =
            interpolate_npmrc_env(&value, &|_| None).expect("malformed input is literal");

        assert_eq!(expanded, value);
        assert!(matches!(expanded, Cow::Borrowed(_)));
    }

    #[test]
    fn missing_required_interpolation_preserves_borrowed_storage() {
        let value = "registry=${MISSING}";

        let expanded = interpolate_npmrc_env(value, &|_| None).unwrap();

        assert!(matches!(expanded, Cow::Borrowed(_)));
        assert_eq!(expanded, value);
    }

    #[test]
    fn npmrc_ini_bounds_malformed_line_diagnostics() {
        let content = "missing-separator\n".repeat(1_000);
        let mut warnings = Vec::new();

        let _ = parse_npmrc_ini_settings(&content, "test.npmrc", &mut warnings);

        assert!(warnings.len() <= 101, "diagnostics were not bounded");
        assert!(
            warnings
                .last()
                .is_some_and(|warning| warning.contains("suppressed")),
            "the bounded output must disclose suppression: {warnings:?}"
        );
    }

    #[test]
    fn npm_config_path_ignores_an_empty_uppercase_value_before_lowercase_fallback() {
        let upper = std::env::var_os("NPM_CONFIG_LPM_TEST_PATH");
        let lower = std::env::var_os("npm_config_lpm_test_path");
        unsafe {
            std::env::set_var("NPM_CONFIG_LPM_TEST_PATH", "");
            std::env::set_var("npm_config_lpm_test_path", "/lower/npmrc");
        }

        let resolved = npm_config_path("lpm_test_path");

        unsafe {
            match upper {
                Some(value) => std::env::set_var("NPM_CONFIG_LPM_TEST_PATH", value),
                None => std::env::remove_var("NPM_CONFIG_LPM_TEST_PATH"),
            }
            match lower {
                Some(value) => std::env::set_var("npm_config_lpm_test_path", value),
                None => std::env::remove_var("npm_config_lpm_test_path"),
            }
        }
        assert_eq!(
            resolved.as_deref(),
            Some(std::path::Path::new("/lower/npmrc"))
        );
    }

    #[test]
    fn npmrc_ini_sections_do_not_promote_nested_settings_to_the_top_level() {
        let mut warnings = Vec::new();
        let settings = parse_npmrc_ini_settings(
            "[nested]\nregistry=https://attacker.example/\n",
            "test.npmrc",
            &mut warnings,
        );

        assert!(
            settings
                .iter()
                .all(|setting| setting.key.as_ref() != "registry"),
            "npm 12 parses assignments after a section header as nested values"
        );
    }

    #[test]
    fn npmrc_ini_treats_a_standalone_carriage_return_as_a_line_separator() {
        let mut warnings = Vec::new();
        let settings = parse_npmrc_ini_settings(
            "registry=https://first.example/\rregistry=https://second.example/\r",
            "test.npmrc",
            &mut warnings,
        );

        let registry = settings
            .iter()
            .find(|setting| setting.key.as_ref() == "registry")
            .expect("registry setting");
        assert_eq!(registry.values.len(), 1);
        assert_eq!(registry.values[0].value, "https://second.example/");
        assert_eq!(registry.values[0].line, 2);
    }
}
