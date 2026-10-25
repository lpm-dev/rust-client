//! Account names of companion storage, shared with the LPM Vault app.
//!
//! ```text
//! __vault_features_v1__:<b64url(vault id)>                     feature marker
//! __vault_companion_v1__:<kind>:<b64url(vault id)>[:<part>]    companion record
//! __vault_staged_v1__:<kind>:<b64url(vault id)>[:<part>]       record a restore staged
//! ```
//!
//! Every name has exactly one spelling: the vault ID's encoding is canonical
//! URL-safe base64 without padding, and a part is three lowercase hex digits.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lpm_common::stored_env::is_safe_vault_id;

pub const MARKER_PREFIX: &str = "__vault_features_v1__:";
pub const RECORD_PREFIX: &str = "__vault_companion_v1__:";
pub const STAGED_PREFIX: &str = "__vault_staged_v1__:";
pub const MAX_ACCOUNT_BYTES: usize = 512;
const MAX_IDENTIFIER_BYTES: usize = 32;
const MAX_PART: u16 = 0xfff;

/// A feature or kind name: `[a-z][a-z0-9-]{0,31}`.
pub fn is_valid_identifier(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_IDENTIFIER_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// A record kind: an identifier other than `features`, which names the
/// marker's entry in the file store.
pub fn is_valid_kind(kind: &str) -> bool {
    kind != "features" && is_valid_identifier(kind)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CompanionAccount {
    Marker {
        vault_id: String,
    },
    Record {
        kind: String,
        vault_id: String,
        part: Option<u16>,
    },
    Staged {
        kind: String,
        vault_id: String,
        part: Option<u16>,
    },
}

impl CompanionAccount {
    /// The account's meaning, when `account` is spelled exactly as this
    /// namespace spells it.
    pub fn parse(account: &str) -> Option<Self> {
        if account.len() > MAX_ACCOUNT_BYTES {
            return None;
        }
        if let Some(encoded) = account.strip_prefix(MARKER_PREFIX) {
            return Some(Self::Marker {
                vault_id: decode_vault_id(encoded)?,
            });
        }
        if let Some(rest) = account.strip_prefix(RECORD_PREFIX) {
            let (kind, vault_id, part) = parse_record_suffix(rest)?;
            return Some(Self::Record {
                kind,
                vault_id,
                part,
            });
        }
        let rest = account.strip_prefix(STAGED_PREFIX)?;
        let (kind, vault_id, part) = parse_record_suffix(rest)?;
        Some(Self::Staged {
            kind,
            vault_id,
            part,
        })
    }

    pub fn vault_id(&self) -> &str {
        match self {
            Self::Marker { vault_id }
            | Self::Record { vault_id, .. }
            | Self::Staged { vault_id, .. } => vault_id,
        }
    }

    /// The record's kind, or `None` for the marker.
    pub fn kind(&self) -> Option<&str> {
        match self {
            Self::Marker { .. } => None,
            Self::Record { kind, .. } | Self::Staged { kind, .. } => Some(kind),
        }
    }

    pub fn part(&self) -> Option<u16> {
        match self {
            Self::Marker { .. } => None,
            Self::Record { part, .. } | Self::Staged { part, .. } => *part,
        }
    }

    pub fn name(&self) -> String {
        match self {
            Self::Marker { vault_id } => marker_account(vault_id),
            Self::Record {
                kind,
                vault_id,
                part,
            } => record_account(kind, vault_id, *part),
            Self::Staged {
                kind,
                vault_id,
                part,
            } => staged_account(kind, vault_id, *part),
        }
    }

    /// The live record a staged record becomes when a restore activates.
    pub fn activated(&self) -> Option<Self> {
        match self {
            Self::Staged {
                kind,
                vault_id,
                part,
            } => Some(Self::Record {
                kind: kind.clone(),
                vault_id: vault_id.clone(),
                part: *part,
            }),
            Self::Marker { .. } | Self::Record { .. } => None,
        }
    }
}

/// Whether `account` is in the companion namespace, valid or not.
pub fn is_in_companion_namespace(account: &str) -> bool {
    account.starts_with(MARKER_PREFIX)
        || account.starts_with(RECORD_PREFIX)
        || account.starts_with(STAGED_PREFIX)
}

pub fn encode_vault_id(vault_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(vault_id.as_bytes())
}

pub fn marker_account(vault_id: &str) -> String {
    let encoded = encode_vault_id(vault_id);
    let mut account = String::with_capacity(MARKER_PREFIX.len() + encoded.len());
    account.push_str(MARKER_PREFIX);
    account.push_str(&encoded);
    account
}

pub fn record_account(kind: &str, vault_id: &str, part: Option<u16>) -> String {
    prefixed_record_account(RECORD_PREFIX, kind, vault_id, part)
}

pub fn staged_account(kind: &str, vault_id: &str, part: Option<u16>) -> String {
    prefixed_record_account(STAGED_PREFIX, kind, vault_id, part)
}

fn prefixed_record_account(prefix: &str, kind: &str, vault_id: &str, part: Option<u16>) -> String {
    let encoded = encode_vault_id(vault_id);
    let mut account = String::with_capacity(prefix.len() + kind.len() + encoded.len() + 5);
    account.push_str(prefix);
    account.push_str(kind);
    account.push(':');
    account.push_str(&encoded);
    if let Some(part) = part {
        use std::fmt::Write as _;
        let _ = write!(account, ":{part:03x}");
    }
    account
}

fn parse_record_suffix(rest: &str) -> Option<(String, String, Option<u16>)> {
    let (kind, rest) = rest.split_once(':')?;
    if !is_valid_kind(kind) {
        return None;
    }
    let (encoded, part) = match rest.split_once(':') {
        Some((encoded, part)) => (encoded, Some(parse_part(part)?)),
        None => (rest, None),
    };
    Some((kind.to_owned(), decode_vault_id(encoded)?, part))
}

fn parse_part(part: &str) -> Option<u16> {
    if part.len() != 3
        || !part
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    u16::from_str_radix(part, 16)
        .ok()
        .filter(|part| *part <= MAX_PART)
}

fn decode_vault_id(encoded: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let vault_id = String::from_utf8(bytes).ok()?;
    (is_safe_vault_id(&vault_id) && encode_vault_id(&vault_id) == encoded).then_some(vault_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_account_round_trips_through_its_one_spelling() {
        let accounts = [
            CompanionAccount::Marker {
                vault_id: "proj-1".to_owned(),
            },
            CompanionAccount::Record {
                kind: "overrides".to_owned(),
                vault_id: "proj-1".to_owned(),
                part: None,
            },
            CompanionAccount::Record {
                kind: "history".to_owned(),
                vault_id: "proj-1".to_owned(),
                part: Some(0x00f),
            },
            CompanionAccount::Staged {
                kind: "key".to_owned(),
                vault_id: "proj-1".to_owned(),
                part: None,
            },
        ];
        for account in accounts {
            let name = account.name();
            assert_eq!(CompanionAccount::parse(&name), Some(account), "{name}");
        }
        assert_eq!(
            record_account("history", "proj-1", Some(15)),
            "__vault_companion_v1__:history:cHJvai0x:00f"
        );
    }

    #[test]
    fn non_canonical_spellings_are_not_companion_accounts() {
        for account in [
            "__vault_features_v1__:cHJvai0x=",
            "__vault_features_v1__:cHJvai1",
            "__vault_companion_v1__:Overrides:cHJvai0x",
            "__vault_companion_v1__:features:cHJvai0x",
            "__vault_companion_v1__:history:cHJvai0x:0F",
            "__vault_companion_v1__:history:cHJvai0x:0f",
            "__vault_companion_v1__:history:cHJvai0x:1000",
            "__vault_companion_v1__:history:cHJvai0x:001:002",
            "__vault_companion_v1__:-history:cHJvai0x",
            "__vault_companion_v1__:history",
            "__vault_staged_v1__::cHJvai0x",
            "__vault_features_v1__:X192YXVsdF9wcm9qZWN0X2luZGV4X21hcmtlcl9f",
        ] {
            assert_eq!(CompanionAccount::parse(account), None, "{account}");
        }
        let too_long = format!("{RECORD_PREFIX}{}:{}", "a".repeat(32), "b".repeat(500));
        assert_eq!(CompanionAccount::parse(&too_long), None);
    }

    #[test]
    fn identifiers_follow_the_shared_grammar() {
        assert!(is_valid_identifier("overrides"));
        assert!(is_valid_identifier("a"));
        assert!(is_valid_identifier(&format!("a{}", "-".repeat(31))));
        assert!(!is_valid_identifier(&format!("a{}", "b".repeat(32))));
        for invalid in ["", "1abc", "Abc", "a_b", "a.b", "a\u{1b}[0m", "é", "a b"] {
            assert!(!is_valid_identifier(invalid), "{invalid:?}");
        }
        assert!(is_valid_identifier("features"));
        assert!(!is_valid_kind("features"));
    }

    #[test]
    fn staged_records_activate_into_the_record_of_the_same_kind_and_part() {
        let staged = CompanionAccount::Staged {
            kind: "history".to_owned(),
            vault_id: "proj".to_owned(),
            part: Some(2),
        };
        assert_eq!(
            staged.activated(),
            Some(CompanionAccount::Record {
                kind: "history".to_owned(),
                vault_id: "proj".to_owned(),
                part: Some(2),
            })
        );
    }
}
