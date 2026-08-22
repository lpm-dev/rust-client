mod npm_artifact;
mod orchestrator;
mod output;
mod prepare;
mod provenance;
mod quality_gate;
mod secret_scan;
mod skills;
mod swift;
mod target;
mod types;
mod upload_lpm;
mod version_data;
mod wait;

pub(crate) use npm_artifact::prepare_npm_target_artifact;
pub use orchestrator::run;
pub(crate) use orchestrator::{
    PreparedPublish, PublishExecutionReport, PublishIntent, PublishTargetPreflight,
    ReleasePublishClients, execute_prepared_for_release, plan_publish_intent_from_source,
    prepare_intent_with_workspace_lock_held, validate_intent_with_workspace_lock_held,
};
pub(crate) use prepare::{
    PublishManifest, PublishSource, prepare_publish_project, read_publish_manifest_from_source,
    validate_publish_tarball_size,
};
pub(crate) use provenance::{
    ProvenanceRequest, materialize_provenance_request,
    resolve_provenance_request_from_project_source,
};
pub(crate) use quality_gate::run_publish_quality_gate;
pub(crate) use secret_scan::run_publish_secret_scan;
#[allow(unused_imports)]
pub use target::resolve_targets;
#[allow(unused_imports)]
pub(crate) use types::{
    NpmTargetArtifactInput, ProvenanceContext, PublishProject, PublishQualityGateInput,
    PublishResult, PublishTarget, ResolvedProvenance,
};
pub(crate) use version_data::build_publish_version_data;

#[cfg(test)]
mod tests;
