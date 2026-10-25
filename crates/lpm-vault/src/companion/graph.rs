//! What code owns about companion records: each known feature's records and
//! minimum policy, the access class of every kind, and which versions this
//! client supports.

use super::marker::Level;

/// The kind every key-dependent feature shares.
pub(crate) const SHARED_KEY_KIND: &str = "key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KnownFeature {
    pub(crate) name: &'static str,
    /// Every kind the feature lists, in the order its marker entry lists them.
    pub(crate) kinds: &'static [&'static str],
    /// Kinds that must exist while the feature is active.
    pub(crate) required: &'static [&'static str],
    pub(crate) minimum: Level,
    pub(crate) supported_versions: &'static [u16],
}

pub(crate) const OVERRIDES: KnownFeature = KnownFeature {
    name: "overrides",
    kinds: &["overrides"],
    required: &["overrides"],
    minimum: Level::Refuse,
    supported_versions: &[1],
};

const HISTORY: KnownFeature = KnownFeature {
    name: "history",
    kinds: &["history-head", "history", SHARED_KEY_KIND],
    required: &["history-head", SHARED_KEY_KIND],
    minimum: Level::Ignore,
    supported_versions: &[],
};

const RELEASES: KnownFeature = KnownFeature {
    name: "releases",
    kinds: &["releases-head", "releases", SHARED_KEY_KIND],
    required: &["releases-head", SHARED_KEY_KIND],
    minimum: Level::Ignore,
    supported_versions: &[],
};

const DETAILS: KnownFeature = KnownFeature {
    name: "details",
    kinds: &["meta", "notes"],
    required: &[],
    minimum: Level::Ignore,
    supported_versions: &[],
};

const KNOWN_FEATURES: [KnownFeature; 4] = [OVERRIDES, HISTORY, RELEASES, DETAILS];

pub(crate) fn known_feature(name: &str) -> Option<&'static KnownFeature> {
    KNOWN_FEATURES.iter().find(|feature| feature.name == name)
}

/// The known feature that alone may list `kind`, or `None` for `key`, which
/// any feature may list, and for kinds no known feature owns.
pub(crate) fn reserved_owner(kind: &str) -> Option<&'static str> {
    if kind == SHARED_KEY_KIND {
        return None;
    }
    KNOWN_FEATURES
        .iter()
        .find(|feature| feature.kinds.contains(&kind))
        .map(|feature| feature.name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessClass {
    /// Readable without CLI approval: the marker and ciphertext parts.
    Open,
    /// The same CLI approval as the project's values item.
    FollowsValues,
}

/// A record's access class. Every kind follows values, unknown kinds
/// included, except the parts of `history` and `releases`, which are
/// ciphertext under `key`.
pub(crate) fn record_access_class(kind: &str, part: Option<u16>) -> AccessClass {
    if part.is_some() && matches!(kind, "history" | "releases") {
        AccessClass::Open
    } else {
        AccessClass::FollowsValues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_kinds_are_reserved_to_their_feature_and_key_is_shared() {
        assert_eq!(reserved_owner("overrides"), Some("overrides"));
        assert_eq!(reserved_owner("history-head"), Some("history"));
        assert_eq!(reserved_owner("releases"), Some("releases"));
        assert_eq!(reserved_owner("notes"), Some("details"));
        assert_eq!(reserved_owner("key"), None);
        assert_eq!(reserved_owner("future-kind"), None);
    }

    #[test]
    fn only_history_and_release_parts_are_open() {
        assert_eq!(record_access_class("history", Some(0)), AccessClass::Open);
        assert_eq!(record_access_class("releases", Some(7)), AccessClass::Open);
        for (kind, part) in [
            ("history-head", None),
            ("key", None),
            ("overrides", None),
            ("meta", None),
            ("future", Some(1)),
            ("history", None),
        ] {
            assert_eq!(
                record_access_class(kind, part),
                AccessClass::FollowsValues,
                "{kind} {part:?}"
            );
        }
    }

    #[test]
    fn this_client_supports_only_overrides_version_one() {
        for feature in KNOWN_FEATURES {
            let expected: &[u16] = if feature.name == "overrides" {
                &[1]
            } else {
                &[]
            };
            assert_eq!(feature.supported_versions, expected, "{}", feature.name);
        }
    }
}
