/// Store layout version selector.
///
/// Threaded through the install pipeline so a single env-var probe at
/// the top of `lpm install` decides whether the run materializes to
/// v1 (`<HOME>/.lpm/store/v1/...` + `<project>/.lpm/wrappers/...`) or
/// v2/v3 (`<HOME>/.lpm/store/v{2,3}/{objects,links}/...` with project
/// `node_modules/<dep>` symlinks pointing into `links/<graph-key>/`).
///
/// **v2 is the default.** v3 stays available as an explicit experimental
/// mode and v1 remains the downgrade path via `LPM_STORE_VERSION`.
///
/// Read once per install via [`StoreVersion::from_env`] so a single
/// invocation is internally consistent — flipping the env mid-install
/// would otherwise produce a half-v1/half-v2 layout.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum StoreVersion {
    /// Legacy layout — wrappers under `<project>/.lpm/wrappers/`,
    /// canonical bytes at `<HOME>/.lpm/store/v1/<pkg>/<version>/`.
    /// Selected only via explicit `LPM_STORE_VERSION=v1`
    /// (downgrade-rollback path).
    V1,
    /// Default virtual-store layout — canonical bytes at
    /// `<HOME>/.lpm/store/v2/objects/<sri>/`, per-context wrappers at
    /// `<HOME>/.lpm/store/v2/links/<graph-key>/`. Project
    /// `node_modules/<dep>` is a symlink into the link entry.
    #[default]
    V2,
    /// Experimental file-CAS virtual-store layout rooted at
    /// `<HOME>/.lpm/store/v3/`.
    /// Package link trees retain independent writable inodes while object
    /// files share immutable content-and-mode blobs.
    V3,
}

impl StoreVersion {
    /// Env var name. Defined as a constant so callers that want to
    /// log "the user set X" can reference it without re-string-typing.
    pub const ENV_VAR: &'static str = "LPM_STORE_VERSION";

    /// Read the active store version from `LPM_STORE_VERSION`. Returns
    /// `V2` (the default) when the var is unset.
    ///
    /// Recognized values:
    /// - Unset, empty, or `v2`/`2` → `V2` (default).
    /// - `v3`/`3` selects the experimental file-CAS layout.
    /// - `v1`/`1` selects the downgrade path.
    /// - Anything else → `V2` + a warning trace, so a typo doesn't
    ///   silently activate an experimental or legacy layout.
    ///
    /// Trimmed and lowercased for ergonomics.
    pub fn from_env() -> Self {
        Self::parse(std::env::var(Self::ENV_VAR).ok().as_deref())
    }

    /// Pure parser for the env-var value. Extracted from
    /// [`Self::from_env`] so unit tests can exercise the recognized /
    /// rejected / fallback branches without manipulating process
    /// environment (which would race other parallel tests).
    pub fn parse(raw: Option<&str>) -> Self {
        let Some(raw) = raw else {
            return Self::V2;
        };
        let normalized = raw.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "" | "v2" | "2" => Self::V2,
            "v3" | "3" => Self::V3,
            "v1" | "1" => Self::V1,
            other => {
                tracing::warn!(
                    "{}={other:?} not recognized; falling back to v2 (valid: v1, v2, v3)",
                    Self::ENV_VAR
                );
                Self::V2
            }
        }
    }

    /// `true` iff this is [`StoreVersion::V2`].
    pub fn is_v2(self) -> bool {
        matches!(self, Self::V2)
    }

    /// Whether this version uses the graph-keyed virtual-store pipeline.
    pub fn uses_virtual_store(self) -> bool {
        matches!(self, Self::V2 | Self::V3)
    }
}

impl std::fmt::Display for StoreVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => f.write_str("v1"),
            Self::V2 => f.write_str("v2"),
            Self::V3 => f.write_str("v3"),
        }
    }
}

/// Store version for the directory layout.
pub(crate) const STORE_VERSION: &str = "v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_version_default_is_v2() {
        assert_eq!(StoreVersion::default(), StoreVersion::V2);
    }

    #[test]
    fn store_version_parse_unset_is_v2() {
        assert_eq!(StoreVersion::parse(None), StoreVersion::V2);
    }

    #[test]
    fn store_version_parse_recognizes_v3_aliases() {
        for s in ["v3", "V3", "3", "  V3  ", "v3\n"] {
            assert_eq!(
                StoreVersion::parse(Some(s)),
                StoreVersion::V3,
                "input {s:?} should resolve to v3"
            );
        }
    }

    #[test]
    fn store_version_parse_recognizes_v2_default_aliases() {
        for s in ["", "v2", "V2", "2", "  v2  "] {
            assert_eq!(StoreVersion::parse(Some(s)), StoreVersion::V2);
        }
    }

    #[test]
    fn store_version_parse_recognizes_v1_downgrade_aliases() {
        for s in ["v1", "V1", "1", "  v1  "] {
            assert_eq!(
                StoreVersion::parse(Some(s)),
                StoreVersion::V1,
                "input {s:?} should resolve to v1 (explicit downgrade)"
            );
        }
    }

    #[test]
    fn store_version_parse_unknown_falls_back_to_v2() {
        for s in ["v4", "v3x", "true", "yes", "on", "junk"] {
            assert_eq!(
                StoreVersion::parse(Some(s)),
                StoreVersion::V2,
                "input {s:?} should fall back to v2"
            );
        }
    }

    #[test]
    fn store_version_is_v2_predicate() {
        assert!(StoreVersion::V2.is_v2());
        assert!(!StoreVersion::V1.is_v2());
        assert!(!StoreVersion::V3.is_v2());
        assert!(StoreVersion::V2.uses_virtual_store());
        assert!(StoreVersion::V3.uses_virtual_store());
        assert!(!StoreVersion::V1.uses_virtual_store());
    }

    #[test]
    fn store_version_display_round_trips_through_parse() {
        for v in [StoreVersion::V1, StoreVersion::V2, StoreVersion::V3] {
            let rendered = format!("{v}");
            assert_eq!(StoreVersion::parse(Some(&rendered)), v);
        }
    }
}
