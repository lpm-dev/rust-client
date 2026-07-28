//! HTTP client for the LPM package registry.
//!
//! Handles all communication between the Rust client and the LPM registry
//! at `lpm.dev`, as well as the upstream npm registry for non-LPM packages.

pub mod client;
pub mod npmrc;
pub mod route;
pub mod timing;
pub mod tls_identity;
pub mod types;

pub use client::{
    BatchMetadataEntryStream, DownloadedTarball, FanOutStats, GateDecision,
    MANAGED_INSTALL_ACCOUNTING_HEADER, MANAGED_INSTALL_ACCOUNTING_VERSION,
    MAX_COMPRESSED_TARBALL_SIZE, ManagedInstallAccounting, PackageMetadataFetchTimings,
    PoolInstallRoot, RegistryClient, TimedPackageMetadata, TimedReleaseTimeMetadata,
    evaluate_cached_url, is_https_url, is_localhost_url, parse_capped_api_json,
};
pub use npmrc::{
    NpmrcConfig, OriginKey, OriginTlsOverrides, RegistryAuth, RegistryKind, RegistryTarget,
    TaggedBool, TaggedPath, TaggedRoot, TlsOverrides,
};
pub use route::{NpmrcLoadErrors, RouteMode, RouteTable, UpstreamRoute};
pub use tls_identity::{
    EnvThenTtyPassphrase, KEY_PASSPHRASE_ENV, LoadedIdentity, PassphraseCache, PassphraseProvider,
    load_identity,
};
pub use types::*;
