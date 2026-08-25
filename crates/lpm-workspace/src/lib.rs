//! Monorepo/workspace discovery and filtering for LPM.
//!
//! Detects workspace configurations from:
//! - `package.json` `"workspaces"` field (npm/yarn)
//! - `pnpm-workspace.yaml`
//!
//! Discovers member packages and reads their package.json for dependencies.
//!
//! Protocols: `workspace:*`, `catalog:`, and `catalog:{name}`.
//! `--filter` and workspace-aware `run` are supported.

mod catalog;
mod compat;
mod discovery;
mod error;
mod package_json;
mod protocols;
mod trust;

pub use catalog::{
    CatalogReferences, collect_catalog_references, prune_unused_package_json_catalogs,
    prune_unused_pnpm_workspace_catalogs,
};
pub use compat::{
    ENGINES_BUN_IGNORED_META, ENGINES_NPM_IGNORED_META, ENGINES_PNPM_IGNORED_META,
    ENGINES_YARN_IGNORED_META, MANIFEST_COMPAT_CATALOG, ManifestCompatCatalogEntry,
    ManifestCompatIssue, ManifestCompatSeverity, PNPM_OVERRIDES_DRIFT_META,
    PNPM_PATCHES_DRIFT_META, PNPM_PEER_RULES_DRIFT_META, UNSUPPORTED_OVERRIDE_VALUES_META,
};
pub use discovery::{
    OpenWorkspaceRoot, PublishProjectionContext, PublishWorkspaceGeneration, Workspace,
    WorkspaceMember, capture_publish_workspace_generation_from_open_root, collect_all_dependencies,
    discover_workspace, discover_workspace_from_open_root, find_project_root, find_workspace_root,
    find_workspace_root_from_open_project, read_publish_projection_from_open_root,
    read_workspace_root_package,
};
pub use error::WorkspaceError;
pub use package_json::{
    BinConfig, CatalogMode, LpmConfig, PackageJson, PatchedDependencyEntry, PeerDependencyMeta,
    PeerDependencyRules, PeerDepsResult, PnpmRaw, WorkspacesConfig, package_json_from_value,
    parse_bin_field, parse_peer_dependencies, read_package_json, read_peer_dependencies,
};
pub use protocols::{
    CatalogProtocolError, CatalogProtocolResolution, resolve_catalog_protocol,
    resolve_workspace_protocol, validate_workspace_protocol_version,
};
pub use trust::{
    ApprovalMetadata, ProvenanceSnapshot, ProvenanceStatus, TrustMatch, TrustedDependencies,
    TrustedDependencyBinding,
};
