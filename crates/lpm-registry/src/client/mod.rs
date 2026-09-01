//! Registry HTTP client.
//!
//! Handles communication with the LPM registry at `lpm.dev`.
//! Publish, token, and OIDC operations are implemented in publish.rs, npmrc.rs, oidc.rs.
//! Uses ETag conditional requests and MessagePack binary cache.

#[cfg(test)]
use crate::npmrc::TaggedPath;
use crate::npmrc::{OriginKey, OriginTlsOverrides, TaggedRoot, TlsOverrides};
use crate::tls_identity::{
    EnvThenTtyPassphrase, LoadedIdentity, PassphraseProvider, load_identity,
    load_identity_with_material_and_reservation,
};
use crate::types::*;
use lpm_auth::{RefreshPolicy, SessionManager};
use lpm_common::{DEFAULT_REGISTRY_URL, LpmError, LpmRoot, NPM_REGISTRY_URL, PackageName};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

mod api;
mod auth;
mod body;
mod cache;
mod config;
mod firewall;
mod http;
mod install_accounting;
mod metadata;
mod state;
mod tarball;
#[cfg(test)]
mod tests;
mod transport;
mod url_gate;

pub use self::auth::AuthPosture;
pub use self::body::parse_capped_api_json;
pub use self::firewall::{
    NpmFirewallAction, NpmFirewallBatchPackage, NpmFirewallBatchResponse, NpmFirewallClientTiming,
    NpmFirewallDecision, NpmFirewallDecisionAuthority, NpmFirewallDecisionDisplay,
    NpmFirewallDecisionPolicy, NpmFirewallDiagnostics, NpmFirewallFlaggedPackageIndexDiagnostics,
    NpmFirewallLookupDuration, NpmFirewallMatchSources, NpmFirewallPolicyAction,
    NpmFirewallPolicyProfile, NpmFirewallSummary,
};
pub use self::install_accounting::{
    MANAGED_INSTALL_ACCOUNTING_HEADER, MANAGED_INSTALL_ACCOUNTING_VERSION,
    MAX_MANAGED_POOL_INSTALL_ROOTS, ManagedInstallAccounting, ManagedInstallRoot,
};
pub use self::metadata::BatchMetadataEntryStream;
pub use self::state::{
    CompressedTarballSpoolReservation, DownloadedTarball, FanOutStats, HttpClients,
    PackageMetadataFetchTimings, RegistryClient, TimedPackageMetadata, TimedReleaseTimeMetadata,
};
pub use self::tarball::{
    MAX_COMPRESSED_TARBALL_SIZE, MAX_COMPRESSED_TARBALL_SPOOL_BYTES,
    reserve_compressed_tarball_spool,
};
pub use self::url_gate::{
    GateDecision, evaluate_cached_url, is_http_url, is_https_url, is_localhost_url,
};

use self::auth::{
    RequestDestination, apply_npmrc_auth, apply_npmrc_auth_to_destination,
    bearer_principal_fingerprint, cert_pem_fingerprint, principal_fingerprint,
};
use self::body::{
    MAX_METADATA_BYTES, MAX_VERSION_METADATA_BYTES, elapsed_millis, forbidden_error_from_body,
    parse_capped_api_json_with_timing, parse_capped_metadata, parse_capped_metadata_with_timing,
    parse_capped_metadata_with_timing_limit, read_capped_error_text,
};
use self::cache::MetadataCacheDirective;
use self::http::{CONNECT_TIMEOUT, READ_TIMEOUT, build_per_origin_http_client};
#[cfg(test)]
use self::state::CacheContent;
use self::state::{
    CacheValidator, CachedClient, MetadataCacheEntry, MetadataCacheMutation,
    MetadataCommandCachePolicy, MetadataMemoryEntry, TlsMaterialBudget,
};
use self::state::{LazyIdentityCert, LazyIdentityMaterial, MAX_NPMRC_TLS_CLIENT_SETS};
use self::transport::PublishSafeResponse;
use self::url_gate::validate_pem_root;

#[cfg(test)]
use self::body::MAX_API_RESPONSE_BYTES;
#[cfg(test)]
use self::cache::{METADATA_CACHE_FILE_CAP, METADATA_CACHE_MAGIC, METADATA_CACHE_TTL};
#[cfg(test)]
use self::tarball::{flush_tarball_file, write_tarball_chunk};
#[cfg(test)]
use self::transport::{MAX_RETRIES, RETRY_MAX_DELAY, backoff_delay};
