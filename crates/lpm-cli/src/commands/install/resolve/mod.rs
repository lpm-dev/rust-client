pub(super) mod metadata;
pub(super) mod metrics;
pub(super) mod parity;

pub(super) use metadata::{
    MetadataCaches, MetadataRequestContext, MetadataStats, metadata_for_package,
};
pub(super) use metrics::{InstallerSpikeStageTimings, InstallerSpikeStats};
pub(super) use parity::{
    InstallerSpikeParity, InstallerSpikeParityMode, compare_package_parity_with_baseline,
};

pub(super) type PackageIdentity = (String, String);

#[derive(Debug, Clone)]
pub(super) struct ResolveRequest {
    pub(super) local_name: String,
    pub(super) target_name: String,
    pub(super) range: String,
    pub(super) parent: Option<PackageIdentity>,
    pub(super) root_ancestor: String,
    pub(super) depth: u16,
    pub(super) optional: bool,
    pub(super) root: bool,
    pub(super) direct: bool,
}
