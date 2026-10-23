//! The names the CLI and the LPM Vault app accept for the env projects they
//! keep in the credential store.

/// Whether `id` can name a vault in protected storage and in fallback stores
/// that normalize paths their own way: 1 to 128 bytes, without a path
/// separator, colon, control character or `..`, not `.`, and not starting
/// with `~` or with `__`, which the store's own records use.
pub fn is_safe_vault_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.starts_with("__")
        && !id.starts_with('~')
        && id != "."
        && !id.contains("..")
        && !id
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
}

/// Whether `name` can name a stored environment: 1 to 64 ASCII letters,
/// digits, `-`, `_` or `.`, without `..`, and not `__index__`.
pub fn is_valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "__index__"
        && !name.contains("..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Whether `name` can name a stored variable: an ASCII letter or `_`, then
/// ASCII letters, digits or `_`.
pub fn is_valid_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Whether `slug` can name an organization in stored associations: 1 to 120
/// ASCII letters, digits, `-` or `_`, starting with a letter or digit.
pub fn is_valid_org_slug(slug: &str) -> bool {
    let mut bytes = slug.bytes();
    slug.len() <= 120
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Whether `value` is a registry URL as stored sync bindings hold it: an
/// `http` or `https` URL with a host and no credentials, query or fragment,
/// written as its origin and its path without trailing slashes.
pub fn is_canonical_registry_url(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let canonical_path = url.path().trim_end_matches('/');
    format!("{}{canonical_path}", url.origin().ascii_serialization()) == value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_ids_accept_uuids_and_slugs_and_refuse_reserved_and_path_forms() {
        for id in [
            "550e8400-e29b-41d4-a716-446655440000",
            "my-vault",
            "a.b",
            "x_1",
        ] {
            assert!(is_safe_vault_id(id), "{id}");
        }
        let long = "a".repeat(129);
        for id in [
            "",
            ".",
            "..",
            "a..b",
            "__index__",
            "~home",
            "a/b",
            "a\\b",
            "a:b",
            "a\0b",
            "a\nb",
            "a\u{85}b",
            &long,
        ] {
            assert!(!is_safe_vault_id(id), "{id:?}");
        }
        assert!(is_safe_vault_id(&"a".repeat(128)));
    }

    #[test]
    fn environment_names_accept_the_portable_set_and_refuse_the_index_and_dot_dot() {
        for name in ["default", "staging", "preview.eu-1", "a_b", &"e".repeat(64)] {
            assert!(is_valid_environment_name(name), "{name}");
        }
        for name in ["", "__index__", "a..b", "a b", "a/b", "é", &"e".repeat(65)] {
            assert!(!is_valid_environment_name(name), "{name:?}");
        }
    }

    #[test]
    fn registry_urls_must_be_written_canonically() {
        for url in [
            "https://lpm.dev",
            "http://localhost:3000",
            "http://localhost:3000/registry",
            "https://[::1]:8443",
        ] {
            assert!(is_canonical_registry_url(url), "{url}");
        }
        for url in [
            "",
            "lpm.dev",
            "ftp://lpm.dev",
            "https://:",
            "https://[",
            "https://lpm.dev:bad",
            "https://LPM.dev",
            "https://lpm.dev:443",
            "https://lpm.dev/",
            "https://lpm.dev/a/",
            "https://user@lpm.dev",
            "https://lpm.dev?x",
            "https://lpm.dev#x",
            "https://lpm.dev/a b",
        ] {
            assert!(!is_canonical_registry_url(url), "{url:?}");
        }
    }

    #[test]
    fn variable_names_start_with_a_letter_or_underscore() {
        for name in ["A", "_", "DATABASE_URL", "_x9", "lower"] {
            assert!(is_valid_variable_name(name), "{name}");
        }
        for name in ["", "1A", "A-B", "A.B", "A B", "É"] {
            assert!(!is_valid_variable_name(name), "{name:?}");
        }
    }
}
