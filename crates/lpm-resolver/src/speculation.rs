use crate::provider::{
    CachedPackageInfo, merge_cached_package_info, parse_metadata_to_cache_info,
    parse_owned_metadata_to_cache_info,
};
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

    /// Retains known versions when a partial metadata snapshot arrives.
    pub fn merge_snapshot(&mut self, incoming: Self) {
        self.dist_tags.extend(incoming.dist_tags);
        if Arc::ptr_eq(&self.info, &incoming.info) {
            return;
        }
        if incoming.info.versions_complete {
            self.info = incoming.info;
        } else if !self.info.versions_complete
            || incoming
                .info
                .versions
                .iter()
                .any(|version| !self.info.versions.contains(version))
        {
            self.info = Arc::new(merge_cached_package_info(&self.info, &incoming.info));
        }
    }
}

impl From<lpm_registry::PackageMetadata> for SpeculativePackageMetadata {
    fn from(meta: lpm_registry::PackageMetadata) -> Self {
        let dist_tags = meta.dist_tags.clone();
        let info = Arc::new(parse_owned_metadata_to_cache_info(meta));
        Self::from_dist_tags_and_info(dist_tags, info)
    }
}

impl From<&lpm_registry::PackageMetadata> for SpeculativePackageMetadata {
    fn from(meta: &lpm_registry::PackageMetadata) -> Self {
        let info = Arc::new(parse_metadata_to_cache_info(meta));
        Self::from_dist_tags_and_info(meta.dist_tags.clone(), info)
    }
}
