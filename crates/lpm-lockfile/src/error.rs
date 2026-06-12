#[derive(Debug, thiserror::Error)]
pub enum LockfileError {
    #[error("failed to serialize lockfile: {0}")]
    Serialize(String),

    #[error("failed to parse lockfile: {0}")]
    Deserialize(String),

    #[error("unsupported lockfile version {found} (max supported: {max_supported})")]
    UnsupportedVersion { found: u32, max_supported: u32 },

    #[error("IO error: {0}")]
    Io(String),

    /// A non-Registry source kind is paired with a `tarball`
    /// field-hint. The `tarball` field is a dist-URL cache valid only
    /// for Registry sources; for `Source::Tarball`, `Source::Git`,
    /// etc. the URL is part of source identity (lives inside the
    /// `source` variant). The two slots must stay disjoint —
    /// conflation would let `lpm update` silently swap a tarball-URL
    /// dep for a registry package with the same dist URL.
    ///
    /// Detected by [`LockedPackage::tarball_field_hint_is_consistent`]
    /// at `from_toml` time — invalid lockfile shapes hard-reject at
    /// the load boundary (manifest-as-truth: invalid shapes should
    /// never propagate).
    #[error(
        "package {package:?} has a `tarball` field-hint paired with a non-Registry source — \
         the hint is valid only for Registry sources"
    )]
    InvalidTarballHint { package: String },

    /// `@lpm.dev/*` package whose registry source URL is not on the
    /// LPM origin. Rejected at load time so a tampered lockfile can't
    /// redirect an LPM-scoped package to an attacker-controlled
    /// registry, even if the SRI in the same file matches the
    /// malicious tarball.
    #[error(
        "package {package:?} is in the @lpm.dev scope but its source URL {url:?} \
         is not on the lpm.dev origin — refusing to use an off-origin URL for an \
         LPM-scoped package"
    )]
    InvalidScopeOrigin { package: String, url: String },
}
