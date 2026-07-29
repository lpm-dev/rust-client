/// Controls whether store writes and cache hits perform behavioral source analysis.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SecurityAnalysisPolicy {
    /// Analyze source during extraction and repair missing or stale caches.
    #[default]
    Enabled,
    /// Skip source analysis without removing any existing cache.
    Disabled,
}

impl SecurityAnalysisPolicy {
    /// Return whether install-time source analysis is enabled.
    #[inline]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Return the stable on-disk representation used by install state.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}
