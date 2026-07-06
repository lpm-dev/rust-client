#[derive(Debug, Default)]
pub(in crate::commands::install) struct InstallerSpikeStats {
    pub(in crate::commands::install) metadata_requests: u64,
    pub(in crate::commands::install) metadata_cache_hits: u64,
    pub(in crate::commands::install) root_requests: u64,
    pub(in crate::commands::install) dependency_requests_enqueued: u64,
    pub(in crate::commands::install) peer_requests_enqueued: u64,
    pub(in crate::commands::install) selected_nodes: u64,
    pub(in crate::commands::install) inserted_nodes: u64,
    pub(in crate::commands::install) duplicate_nodes: u64,
    pub(in crate::commands::install) reused_existing_versions: u64,
    pub(in crate::commands::install) inline_reused_edges: u64,
    pub(in crate::commands::install) inline_reuse_deferred_promotions: u64,
    pub(in crate::commands::install) skipped_optional: u64,
    pub(in crate::commands::install) platform_pre_skipped: u64,
    pub(in crate::commands::install) fetch_dispatched: u64,
}

#[derive(Debug, Default)]
pub(in crate::commands::install) struct InstallerSpikeStageTimings {
    pub(in crate::commands::install) resolve_worklist_ms: u128,
    pub(in crate::commands::install) peer_drain_ms: u128,
    pub(in crate::commands::install) package_graph_ms: u128,
    pub(in crate::commands::install) parity_ms: u128,
    pub(in crate::commands::install) link_targets_ms: u128,
    pub(in crate::commands::install) v2_targets_ms: u128,
    pub(in crate::commands::install) v2_prepare_ms: u128,
    pub(in crate::commands::install) v2_index_ms: u128,
    pub(in crate::commands::install) pre_fetch_overlap_ms: u128,
    pub(in crate::commands::install) fetch_join_ms: u128,
    pub(in crate::commands::install) link_task_await_ms: u128,
    pub(in crate::commands::install) link_finalize_ms: u128,
}

impl InstallerSpikeStageTimings {
    pub(in crate::commands::install) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "resolve_worklist_ms": self.resolve_worklist_ms,
            "peer_drain_ms": self.peer_drain_ms,
            "package_graph_ms": self.package_graph_ms,
            "parity_ms": self.parity_ms,
            "link_targets_ms": self.link_targets_ms,
            "v2_targets_ms": self.v2_targets_ms,
            "v2_prepare_ms": self.v2_prepare_ms,
            "v2_index_ms": self.v2_index_ms,
            "pre_fetch_overlap_ms": self.pre_fetch_overlap_ms,
            "fetch_join_ms": self.fetch_join_ms,
            "link_task_await_ms": self.link_task_await_ms,
            "link_finalize_ms": self.link_finalize_ms,
        })
    }
}
