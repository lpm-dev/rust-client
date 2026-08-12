use serde::{Deserialize, Serialize};

/// One resolved peer edge from a consumer's manifest-local name to an exact
/// provider identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PeerEdge {
    /// Key used in the consumer's `peerDependencies` map and policy rules.
    pub local_name: String,
    /// Canonical package name used to locate the provider.
    pub target_name: String,
    /// Exact resolved provider version.
    pub target_version: String,
    /// Source identity for non-registry providers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_wrapper_id: Option<String>,
}

impl PeerEdge {
    #[inline]
    pub fn registry(
        local_name: impl Into<String>,
        target_name: impl Into<String>,
        target_version: impl Into<String>,
    ) -> Self {
        Self {
            local_name: local_name.into(),
            target_name: target_name.into(),
            target_version: target_version.into(),
            target_wrapper_id: None,
        }
    }
}
