pub mod error;
pub mod integrity;
pub mod package_name;

pub use error::LpmError;
pub use integrity::Integrity;
pub use package_name::PackageName;

/// The LPM scope prefix. All LPM packages live under this scope.
pub const LPM_SCOPE: &str = "@lpm.dev";

/// Default LPM registry URL.
pub const DEFAULT_REGISTRY_URL: &str = "https://lpm.dev";

/// Default npm upstream registry URL.
pub const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";
