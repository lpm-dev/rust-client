use crate::provider::{CachedPackageInfo, parse_metadata_to_cache_info};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SpeculativePackageMetadata {
    pub dist_tags: HashMap<String, String>,
    pub info: Arc<CachedPackageInfo>,
}

impl SpeculativePackageMetadata {
    pub fn from_dist_tags_and_info(
        dist_tags: HashMap<String, String>,
        info: Arc<CachedPackageInfo>,
    ) -> Self {
        Self { dist_tags, info }
    }
}

impl From<lpm_registry::PackageMetadata> for SpeculativePackageMetadata {
    fn from(meta: lpm_registry::PackageMetadata) -> Self {
        let info = Arc::new(parse_metadata_to_cache_info(&meta));
        Self::from_dist_tags_and_info(meta.dist_tags, info)
    }
}

impl From<&lpm_registry::PackageMetadata> for SpeculativePackageMetadata {
    fn from(meta: &lpm_registry::PackageMetadata) -> Self {
        let info = Arc::new(parse_metadata_to_cache_info(meta));
        Self::from_dist_tags_and_info(meta.dist_tags.clone(), info)
    }
}
