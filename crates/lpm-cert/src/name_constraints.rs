//! Name-constraint configuration validation.
//!
//! Owns the validation rules for the `cert.extra_permitted_dns` config entries in
//! `lpm.json`. The validator runs at config-parse time so a malformed or attack-shaped
//! entry is rejected before it ever reaches a CA-generation code path.
//!
//! No consumer of these subtrees ships in this build — project-scoped CA generation is
//! a follow-up. The validator is in place now so future code that *does* attach these
//! to a CA cannot be smuggled past by an attacker editing config to broaden the
//! permitted set (e.g. `"*.com"`).

use lpm_common::LpmError;

/// Bare-name TLD suffixes that are "obviously local" and never need
/// `cert.allowPublicDns`. Match is case-insensitive on a trailing `.<tld>`.
const LOCAL_TLD_ALLOWLIST: &[&str] = &["local", "test", "localhost", "internal", "home.arpa"];

/// Suffixes already covered by the built-in permitted_subtrees in `ca::permitted_subtrees`.
///
/// Each entry is the bare suffix without the leading dot. An entry whose `host` ends in
/// any of these is redundant on a CA that already carries the built-in subtree.
const BUILTIN_DNS_SUFFIXES: &[&str] = &["localhost", "local", "test", "lpm.test"];

/// One accepted entry from `cert.extra_permitted_dns`.
///
/// The validator emits both an exact match and a leading-dot suffix match per accepted
/// bare-name entry (RFC 5280 §4.2.1.10 has no wildcard token; "any subdomain of X"
/// is expressed via the leading-dot subtree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedDnsEntry {
    /// The bare hostname as written in config (lowercased, trimmed).
    pub host: String,
    /// `host` itself — matches the exact name.
    pub exact_subtree: String,
    /// `.{host}` — matches any subdomain.
    pub suffix_subtree: String,
}

/// Convert accepted config entries into the DNS subtree strings rcgen expects
/// for a NameConstraints extension.
pub fn dns_subtrees_from_entries(entries: &[AcceptedDnsEntry]) -> Vec<String> {
    let mut subtrees = Vec::with_capacity(entries.len() * 2);
    for entry in entries {
        push_unique(&mut subtrees, entry.exact_subtree.clone());
        push_unique(&mut subtrees, entry.suffix_subtree.clone());
    }
    subtrees
}

/// Validate a list of `cert.extra_permitted_dns` entries.
///
/// On success, returns one `AcceptedDnsEntry` per input entry, deduplicated and in input
/// order. On the first invalid entry, returns `LpmError::Cert` with a message that names
/// the offending entry and a hint at how to fix it.
///
/// `allow_public_dns` is wired from the `cert.allowPublicDns` field in
/// `lpm.json`. When `false` (the default), any entry whose TLD is not in
/// `LOCAL_TLD_ALLOWLIST` is rejected.
pub fn validate_extra_permitted_dns(
    entries: &[String],
    allow_public_dns: bool,
) -> Result<Vec<AcceptedDnsEntry>, LpmError> {
    let mut accepted: Vec<AcceptedDnsEntry> = Vec::with_capacity(entries.len());

    for entry in entries {
        let trimmed = entry.trim();
        let normalized = trimmed.to_ascii_lowercase();

        if normalized.is_empty() {
            return Err(LpmError::Cert(
                "cert.extra_permitted_dns entry is empty".into(),
            ));
        }
        if normalized.contains('*') {
            return Err(LpmError::Cert(format!(
                "cert.extra_permitted_dns entry {entry:?} contains '*': use the bare \
                 name instead (e.g. \"myapp.local\" covers both myapp.local and \
                 *.myapp.local via the NameConstraints suffix encoding)"
            )));
        }
        if normalized.starts_with('.') {
            return Err(LpmError::Cert(format!(
                "cert.extra_permitted_dns entry {entry:?} starts with '.': the \
                 leading-dot form is an output encoding, not input syntax. Use the \
                 bare name (e.g. \"myapp.local\")."
            )));
        }
        if !normalized.contains('.') {
            return Err(LpmError::Cert(format!(
                "cert.extra_permitted_dns entry {entry:?} has no dot: bare TLDs are not \
                 allowed. Use a multi-label hostname (e.g. \"myapp.local\")."
            )));
        }
        if normalized.contains(char::is_whitespace) {
            return Err(LpmError::Cert(format!(
                "cert.extra_permitted_dns entry {entry:?} contains whitespace"
            )));
        }
        for byte in normalized.bytes() {
            let ok = byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-';
            if !ok {
                return Err(LpmError::Cert(format!(
                    "cert.extra_permitted_dns entry {entry:?} contains invalid character \
                     {ch:?}: only [a-z0-9.-] are allowed",
                    ch = byte as char
                )));
            }
        }
        if normalized.ends_with('.')
            || normalized.contains("..")
            || normalized.len() > 253
            || normalized.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
            })
        {
            return Err(LpmError::Cert(format!(
                "cert.extra_permitted_dns entry {entry:?} is not a valid DNS label \
                 sequence"
            )));
        }

        if !allow_public_dns && !has_local_tld(&normalized) {
            return Err(LpmError::Cert(format!(
                "cert.extraPermittedDns entry {entry:?} ends in a non-local TLD; \
                 set `cert.allowPublicDns: true` in lpm.json to permit broadening \
                 the CA to public hostnames"
            )));
        }

        if is_already_covered_by_builtins(&normalized) {
            return Err(LpmError::Cert(format!(
                "cert.extra_permitted_dns entry {entry:?} is already covered by the \
                 built-in permitted subtrees ({}); remove it from config",
                BUILTIN_DNS_SUFFIXES.join(", ")
            )));
        }

        if accepted.iter().any(|e| e.host == normalized) {
            continue;
        }

        accepted.push(AcceptedDnsEntry {
            host: normalized.clone(),
            exact_subtree: normalized.clone(),
            suffix_subtree: format!(".{normalized}"),
        });
    }

    Ok(accepted)
}

fn has_local_tld(host: &str) -> bool {
    LOCAL_TLD_ALLOWLIST
        .iter()
        .any(|tld| host == *tld || host.ends_with(&format!(".{tld}")))
}

fn is_already_covered_by_builtins(host: &str) -> bool {
    BUILTIN_DNS_SUFFIXES.contains(&host)
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_well_formed_local_name_and_emits_exact_and_suffix() {
        let accepted = validate_extra_permitted_dns(&["myapp.local".into()], false).unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].host, "myapp.local");
        assert_eq!(accepted[0].exact_subtree, "myapp.local");
        assert_eq!(accepted[0].suffix_subtree, ".myapp.local");
    }

    #[test]
    fn rejects_wildcard_entry_with_rewrite_hint() {
        let err = validate_extra_permitted_dns(&["*.myapp.local".into()], false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("'*'"), "expected '*' in message, got {msg}");
        assert!(
            msg.contains("myapp.local"),
            "expected rewrite hint, got {msg}"
        );
    }

    #[test]
    fn rejects_leading_dot_entry() {
        let err = validate_extra_permitted_dns(&[".myapp.local".into()], false).unwrap_err();
        assert!(err.to_string().contains("starts with '.'"));
    }

    #[test]
    fn rejects_bare_label_with_no_dot() {
        let err = validate_extra_permitted_dns(&["myapp".into()], false).unwrap_err();
        assert!(err.to_string().contains("no dot"));
    }

    #[test]
    fn rejects_public_tld_without_allow_flag() {
        let err = validate_extra_permitted_dns(&["evil.example".into()], false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("non-local TLD"), "got {msg}");
        assert!(
            msg.contains("cert.allowPublicDns"),
            "hint must point at the actual lpm.json field, got {msg}"
        );
    }

    #[test]
    fn permits_public_tld_when_allow_flag_set() {
        let accepted = validate_extra_permitted_dns(&["staging.example.com".into()], true).unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].host, "staging.example.com");
    }

    #[test]
    fn accepts_all_local_tlds_in_allowlist() {
        let inputs: Vec<String> = vec![
            "a.local".into(),
            "b.test".into(),
            "c.internal".into(),
            "d.home.arpa".into(),
        ];
        let accepted = validate_extra_permitted_dns(&inputs, false).unwrap();
        assert_eq!(accepted.len(), 4);
    }

    #[test]
    fn accepts_subdomain_under_builtin_suffix_so_project_ca_can_restrict_further() {
        let accepted = validate_extra_permitted_dns(&["api.localhost".into()], false).unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].host, "api.localhost");
    }

    #[test]
    fn rejects_entry_that_is_an_exact_builtin_suffix() {
        let err = validate_extra_permitted_dns(&["lpm.test".into()], false).unwrap_err();
        assert!(err.to_string().contains("already covered"));
    }

    #[test]
    fn deduplicates_repeated_entries() {
        let accepted = validate_extra_permitted_dns(
            &[
                "myapp.local".into(),
                "MyApp.local".into(),
                "myapp.local".into(),
            ],
            false,
        )
        .unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].host, "myapp.local");
    }

    #[test]
    fn dns_subtrees_from_entries_emits_exact_and_suffix_without_duplicates() {
        let accepted =
            validate_extra_permitted_dns(&["myapp.local".into(), "MyApp.local".into()], false)
                .unwrap();

        assert_eq!(
            dns_subtrees_from_entries(&accepted),
            vec!["myapp.local".to_string(), ".myapp.local".to_string()]
        );
    }

    #[test]
    fn rejects_empty_entry() {
        let err = validate_extra_permitted_dns(&["".into()], false).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn rejects_whitespace_in_entry() {
        let err = validate_extra_permitted_dns(&["a b.local".into()], false).unwrap_err();
        assert!(err.to_string().contains("whitespace"));
    }

    #[test]
    fn rejects_invalid_dns_characters() {
        for bad in ["a/b.local", "a_b.local", "a@b.local", "a:b.local"] {
            let err = validate_extra_permitted_dns(&[bad.into()], false).unwrap_err();
            assert!(
                err.to_string().contains("invalid character"),
                "expected invalid-character rejection for {bad:?}, got {err}"
            );
        }
    }

    #[test]
    fn rejects_label_starting_or_ending_with_hyphen() {
        for bad in [
            "-myapp.local",
            "myapp.local-",
            "api.-bad.local",
            "api.bad-.local",
        ] {
            let err = validate_extra_permitted_dns(&[bad.into()], false).unwrap_err();
            assert!(err.to_string().contains("not a valid DNS"));
        }
    }

    #[test]
    fn rejects_double_dot() {
        let err = validate_extra_permitted_dns(&["a..local".into()], false).unwrap_err();
        assert!(err.to_string().contains("not a valid DNS"));
    }

    #[test]
    fn rejects_dns_names_over_the_label_or_total_length_limits() {
        let long_label = format!("{}.local", "a".repeat(64));
        let long_name = format!(
            "{}.{}.{}.{}.local",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );

        for bad in [long_label, long_name] {
            let error = validate_extra_permitted_dns(&[bad], false).unwrap_err();
            assert!(error.to_string().contains("not a valid DNS"));
        }
    }

    #[test]
    fn accepts_subdomain_under_user_local_tld() {
        let accepted =
            validate_extra_permitted_dns(&["api.myapp.example.local".into()], false).unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].host, "api.myapp.example.local");
        assert_eq!(accepted[0].suffix_subtree, ".api.myapp.example.local");
    }
}
