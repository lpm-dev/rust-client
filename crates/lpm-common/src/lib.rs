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

/// Format bytes into a human-readable string (e.g., "1.2 KB", "3.4 MB").
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
