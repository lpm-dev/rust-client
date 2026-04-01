//! Security policies for LPM package installation.
//!
//! Key policies (following pnpm v10 and Bun best practices):
//!
//! 1. **Lifecycle scripts blocked by default** — `preinstall`, `install`, `postinstall`
//!    scripts are NOT executed unless the package is in `trustedDependencies`.
//!    This prevents supply chain attacks via malicious postinstall scripts.
//!
//! 2. **Trusted dependencies allowlist** — packages in `"lpm": { "trustedDependencies": [...] }`
//!    in package.json are allowed to run lifecycle scripts.
//!
//! 3. **Minimum release age** (future) — block packages published less than 24h ago.
//!
//! Supply chain security: SLSA, Sigstore, typosquatting, OSV audit, release age.
//! See phase-19-todo.md.

pub mod behavioral;
pub mod query;
pub mod skill_security;
pub mod typosquatting;

use std::collections::HashSet;
use std::path::Path;
use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;

/// Lifecycle script names that are blocked by default.
const BLOCKED_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
    "prepare",
    "prepublishOnly",
];

/// Warning returned when a package release is too new.
#[derive(Debug, Clone)]
pub struct ReleaseAgeWarning {
    /// How old the release actually is (seconds).
    pub age_secs: u64,
    /// The minimum age required by policy (seconds).
    pub minimum: u64,
}

/// Parse an ISO 8601 timestamp into a Unix epoch (seconds).
///
/// Uses the `time` crate for correct parsing (leap years, etc.).
fn parse_timestamp(ts: &str) -> Option<u64> {
    let dt = OffsetDateTime::parse(ts, &Iso8601::DEFAULT).ok()?;
    Some(dt.unix_timestamp() as u64)
}

/// Get the current time as Unix epoch seconds.
fn current_epoch_secs() -> u64 {
    OffsetDateTime::now_utc().unix_timestamp() as u64
}

/// Security policy for a project, derived from package.json's `"lpm"` config.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Packages explicitly trusted to run lifecycle scripts.
    pub trusted_dependencies: HashSet<String>,
    /// Minimum age in seconds before a release is installable (default: 86400 = 24h).
    /// Set to 0 to disable. Protects against compromised publish tokens being used
    /// to push malicious versions that get installed before detection.
    pub minimum_release_age_secs: u64,
}

impl SecurityPolicy {
    /// Default minimum release age: 24 hours (matches pnpm v10 default).
    const DEFAULT_MIN_RELEASE_AGE: u64 = 86400;

    /// Create a default policy (nothing trusted — all scripts blocked, 24h release age).
    pub fn default_policy() -> Self {
        SecurityPolicy {
            trusted_dependencies: HashSet::new(),
            minimum_release_age_secs: Self::DEFAULT_MIN_RELEASE_AGE,
        }
    }

    /// Load policy from a project's package.json.
    ///
    /// Reads `"lpm": { "trustedDependencies": ["esbuild", "sharp"] }`.
    /// Uses the typed `PackageJson` struct (single source of truth, no raw JSON parsing).
    pub fn from_package_json(pkg_json_path: &Path) -> Self {
        let pkg = match lpm_workspace::read_package_json(pkg_json_path) {
            Ok(p) => p,
            Err(_) => return Self::default_policy(),
        };

        let lpm_config = match pkg.lpm {
            Some(c) => c,
            None => return Self::default_policy(),
        };

        let trusted: HashSet<String> = lpm_config.trusted_dependencies.into_iter().collect();
        let min_age = lpm_config
            .minimum_release_age
            .unwrap_or(Self::DEFAULT_MIN_RELEASE_AGE);

        SecurityPolicy {
            trusted_dependencies: trusted,
            minimum_release_age_secs: min_age,
        }
    }

    /// Check if a package is allowed to run lifecycle scripts.
    pub fn can_run_scripts(&self, package_name: &str) -> bool {
        self.trusted_dependencies.contains(package_name)
    }

    /// Check if a package was published too recently.
    ///
    /// # Trust Model
    /// The `published_at` timestamp comes from the LPM registry metadata.
    /// This check protects against:
    /// - Stolen publish tokens used against the legitimate registry
    /// - Rapid malicious publish -> install -> damage scenarios
    ///
    /// This check does NOT protect against:
    /// - A compromised registry (attacker controls timestamps)
    /// - MITM attacks (mitigated by HTTPS + cert pinning in lpm-tunnel)
    ///
    /// The timestamp is trusted because the registry is the source of truth
    /// for package metadata. For stronger guarantees, use SLSA provenance
    /// verification (when available).
    ///
    /// # Fail-closed behavior
    /// If the timestamp cannot be parsed, this returns a warning (treats the
    /// package as just-published). This is intentional: a garbage timestamp
    /// should NOT silently bypass the age check.
    ///
    /// `published_at` should be an ISO 8601 timestamp string, or `None` if unknown.
    /// Returns `Some(ReleaseAgeWarning)` if the release is too new, `None` if it's ok.
    pub fn check_release_age(&self, published_at: Option<&str>) -> Option<ReleaseAgeWarning> {
        if self.minimum_release_age_secs == 0 {
            return None;
        }

        let Some(ts_str) = published_at else {
            return None; // No timestamp available -> can't check
        };

        let now = current_epoch_secs();

        let published_epoch = match parse_timestamp(ts_str) {
            Some(t) => t,
            None => {
                // Parse failure -> fail closed: treat as just published
                tracing::warn!(
                    "failed to parse publish timestamp '{}' — treating as new package",
                    ts_str
                );
                now // current time = age 0 = triggers warning
            }
        };

        let age_secs = now.saturating_sub(published_epoch);
        if age_secs < self.minimum_release_age_secs {
            Some(ReleaseAgeWarning {
                age_secs,
                minimum: self.minimum_release_age_secs,
            })
        } else {
            None
        }
    }

    /// Check if a script name is a lifecycle script that should be blocked.
    pub fn is_blocked_script(script_name: &str) -> bool {
        BLOCKED_SCRIPTS.contains(&script_name)
    }

    /// Scan a package's `package.json` for lifecycle scripts.
    /// Returns the names of scripts that would be blocked.
    /// Uses the typed `PackageJson` struct (single source of truth).
    pub fn detect_lifecycle_scripts(pkg_json_path: &Path) -> Vec<String> {
        let pkg = match lpm_workspace::read_package_json(pkg_json_path) {
            Ok(p) => p,
            Err(_) => return vec![],
        };

        pkg.scripts
            .keys()
            .filter(|name| Self::is_blocked_script(name))
            .cloned()
            .collect()
    }
}

/// Result of scanning all installed packages for lifecycle scripts.
#[derive(Debug)]
pub struct ScriptAuditResult {
    /// Packages with blocked lifecycle scripts.
    pub blocked: Vec<BlockedPackage>,
    /// Packages trusted to run scripts.
    pub trusted: Vec<String>,
}

/// A package that has lifecycle scripts but is not trusted.
#[derive(Debug)]
pub struct BlockedPackage {
    pub name: String,
    pub scripts: Vec<String>,
}

/// Scan all installed packages in node_modules/.lpm/ for lifecycle scripts.
///
/// Returns an audit result showing which packages have scripts and whether
/// they're trusted or blocked.
pub fn audit_lifecycle_scripts(project_dir: &Path, policy: &SecurityPolicy) -> ScriptAuditResult {
    let lpm_dir = project_dir.join("node_modules").join(".lpm");
    let mut blocked = Vec::new();
    let mut trusted = Vec::new();

    if !lpm_dir.exists() {
        return ScriptAuditResult { blocked, trusted };
    }

    let entries = match std::fs::read_dir(&lpm_dir) {
        Ok(e) => e,
        Err(_) => return ScriptAuditResult { blocked, trusted },
    };

    for entry in entries.flatten() {
        let pkg_dir = entry.path().join("node_modules");
        if !pkg_dir.exists() {
            continue;
        }

        // Each dir inside is the actual package
        let inner_entries = match std::fs::read_dir(&pkg_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for inner in inner_entries.flatten() {
            let pkg_json = inner.path().join("package.json");
            if !pkg_json.exists() {
                continue;
            }

            let scripts = SecurityPolicy::detect_lifecycle_scripts(&pkg_json);
            if scripts.is_empty() {
                continue;
            }

            let pkg_name = inner.file_name().to_string_lossy().to_string();

            if policy.can_run_scripts(&pkg_name) {
                trusted.push(pkg_name);
            } else {
                blocked.push(BlockedPackage {
                    name: pkg_name,
                    scripts,
                });
            }
        }
    }

    ScriptAuditResult { blocked, trusted }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_blocks_all() {
        let policy = SecurityPolicy::default_policy();
        assert!(!policy.can_run_scripts("esbuild"));
        assert!(!policy.can_run_scripts("sharp"));
    }

    #[test]
    fn trusted_deps_can_run_scripts() {
        let mut policy = SecurityPolicy::default_policy();
        policy.trusted_dependencies.insert("esbuild".to_string());

        assert!(policy.can_run_scripts("esbuild"));
        assert!(!policy.can_run_scripts("sharp"));
    }

    #[test]
    fn blocked_script_detection() {
        assert!(SecurityPolicy::is_blocked_script("postinstall"));
        assert!(SecurityPolicy::is_blocked_script("preinstall"));
        assert!(SecurityPolicy::is_blocked_script("install"));
        assert!(SecurityPolicy::is_blocked_script("prepare"));
        assert!(SecurityPolicy::is_blocked_script("prepublishOnly"));
        assert!(!SecurityPolicy::is_blocked_script("build"));
        assert!(!SecurityPolicy::is_blocked_script("test"));
        assert!(!SecurityPolicy::is_blocked_script("start"));
    }

    #[test]
    fn detect_scripts_from_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"scripts":{"postinstall":"node setup.js","build":"tsc","preinstall":"echo hi"}}"#,
        )
        .unwrap();

        let scripts = SecurityPolicy::detect_lifecycle_scripts(&pkg_json);
        assert!(scripts.contains(&"postinstall".to_string()));
        assert!(scripts.contains(&"preinstall".to_string()));
        assert!(!scripts.contains(&"build".to_string()));
    }

    #[test]
    fn detect_prepare_script() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"scripts":{"prepare":"node build.js","build":"tsc"}}"#,
        )
        .unwrap();

        let scripts = SecurityPolicy::detect_lifecycle_scripts(&pkg_json);
        assert!(scripts.contains(&"prepare".to_string()));
        assert!(!scripts.contains(&"build".to_string()));
    }

    #[test]
    fn detect_prepublish_only_script() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"scripts":{"prepublishOnly":"npm run build"}}"#,
        )
        .unwrap();

        let scripts = SecurityPolicy::detect_lifecycle_scripts(&pkg_json);
        assert!(scripts.contains(&"prepublishOnly".to_string()));
    }

    #[test]
    fn release_age_old_package_no_warning() {
        let policy = SecurityPolicy {
            trusted_dependencies: HashSet::new(),
            minimum_release_age_secs: 86400, // 24h
        };
        // A date far in the past should pass (return None = no warning)
        assert!(
            policy
                .check_release_age(Some("2020-01-01T00:00:00Z"))
                .is_none()
        );
    }

    #[test]
    fn release_age_recent_package_warns() {
        let policy = SecurityPolicy {
            trusted_dependencies: HashSet::new(),
            minimum_release_age_secs: 86400, // 24h
        };
        // Use current time as "just published" — must warn
        let now = OffsetDateTime::now_utc();
        let ts = now.format(&Iso8601::DEFAULT).unwrap();
        let warning = policy.check_release_age(Some(&ts));
        assert!(
            warning.is_some(),
            "just-published package should trigger warning"
        );
        let w = warning.unwrap();
        assert!(w.age_secs < 5, "age should be near zero");
        assert_eq!(w.minimum, 86400);
    }

    #[test]
    fn release_age_leap_year() {
        let policy = SecurityPolicy {
            trusted_dependencies: HashSet::new(),
            minimum_release_age_secs: 86400,
        };
        // Feb 29, 2024 is a valid leap year date — should parse correctly and not warn
        assert!(
            policy
                .check_release_age(Some("2024-02-29T12:00:00Z"))
                .is_none()
        );
    }

    #[test]
    fn release_age_garbage_fails_closed() {
        let policy = SecurityPolicy {
            trusted_dependencies: HashSet::new(),
            minimum_release_age_secs: 86400,
        };
        // Garbage input — must fail closed (return Some = warning)
        assert!(
            policy.check_release_age(Some("not-a-date")).is_some(),
            "garbage timestamp must trigger warning (fail closed)"
        );
        assert!(
            policy.check_release_age(Some("")).is_some(),
            "empty string must trigger warning (fail closed)"
        );
    }

    #[test]
    fn release_age_none_timestamp_no_check() {
        let policy = SecurityPolicy {
            trusted_dependencies: HashSet::new(),
            minimum_release_age_secs: 86400,
        };
        // No timestamp at all — can't check, return None
        assert!(policy.check_release_age(None).is_none());
    }

    #[test]
    fn release_age_disabled_policy() {
        let policy = SecurityPolicy {
            trusted_dependencies: HashSet::new(),
            minimum_release_age_secs: 0, // disabled
        };
        let now = OffsetDateTime::now_utc();
        let ts = now.format(&Iso8601::DEFAULT).unwrap();
        assert!(policy.check_release_age(Some(&ts)).is_none());
    }

    #[test]
    fn parse_timestamp_valid() {
        let epoch = parse_timestamp("2024-02-29T12:00:00Z");
        assert!(epoch.is_some());
        // Feb 29 2024 12:00 UTC = 1709208000
        assert_eq!(epoch.unwrap(), 1709208000);
    }

    #[test]
    fn parse_timestamp_invalid() {
        assert!(parse_timestamp("not-a-date").is_none());
        assert!(parse_timestamp("").is_none());
    }

    #[test]
    fn load_policy_from_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"name":"test","lpm":{"trustedDependencies":["esbuild","sharp"]}}"#,
        )
        .unwrap();

        let policy = SecurityPolicy::from_package_json(&pkg_json);
        assert!(policy.can_run_scripts("esbuild"));
        assert!(policy.can_run_scripts("sharp"));
        assert!(!policy.can_run_scripts("malware"));
    }
}
