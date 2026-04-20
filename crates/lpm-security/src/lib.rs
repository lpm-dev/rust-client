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
pub mod script_hash;
pub mod skill_security;
pub mod triage;
pub mod typosquatting;

use std::path::Path;
use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;

// Re-export Phase 4 trust types so callers in lpm-cli can import them
// from lpm-security alongside `SecurityPolicy`. The types are owned by
// `lpm-workspace` (the schema crate) but used most heavily here.
pub use lpm_workspace::{TrustMatch, TrustedDependencies, TrustedDependencyBinding};

/// Lifecycle script names that are blocked by default.
///
/// This is the BROAD set — every phase that LPM refuses to execute by
/// default at install time. It is a strict superset of
/// [`EXECUTED_INSTALL_PHASES`] (which is the narrow set the build pipeline
/// actually runs) so that detection in source manifests catches every
/// dangerous phase even if some are inert in the current pipeline.
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

/// Lifecycle script phases that the install-time `lpm build` pipeline
/// **actually runs**, in execution order.
///
/// **Phase 32 Phase 4** (F3 in the Phase 4 status doc): the script_hash
/// approval binding covers EXACTLY these phases. Editing a non-executed
/// phase like `prepare` does NOT invalidate approvals because that script
/// never runs at install time. Conversely, any change to one of these
/// three phases DOES invalidate approvals because that's bytes the user
/// previously trusted to execute.
///
/// This const is the SINGLE source of truth — `lpm-cli/src/commands/build.rs`
/// imports it instead of defining its own `SCRIPT_PHASES` list, and
/// [`script_hash::compute_script_hash`] iterates it in fixed order.
///
/// **Invariant** (asserted by `script_hash::tests::executed_install_phases_const_is_subset_of_blocked_scripts`):
/// every entry here MUST also appear in [`BLOCKED_SCRIPTS`]. You can't run
/// a script that isn't blocked by default.
pub const EXECUTED_INSTALL_PHASES: &[&str] = &["preinstall", "install", "postinstall"];

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
    ///
    /// **Phase 32 Phase 4** (M2): the type changed from `HashSet<String>`
    /// to [`TrustedDependencies`] so the strict gate
    /// ([`Self::can_run_scripts_strict`]) can bind to
    /// `{name, version, integrity, script_hash}`. The legacy
    /// [`Self::can_run_scripts`] method is preserved as a name-only
    /// fallback for the existing `lpm build` code path.
    pub trusted_dependencies: TrustedDependencies,
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
            trusted_dependencies: TrustedDependencies::default(),
            minimum_release_age_secs: Self::DEFAULT_MIN_RELEASE_AGE,
        }
    }

    /// Load policy from a project's package.json.
    ///
    /// Reads `"lpm": { "trustedDependencies": ... }`. Accepts BOTH the
    /// legacy array form and the Phase 4 rich-map form (per
    /// [`TrustedDependencies`]).
    pub fn from_package_json(pkg_json_path: &Path) -> Self {
        let pkg = match lpm_workspace::read_package_json(pkg_json_path) {
            Ok(p) => p,
            Err(_) => return Self::default_policy(),
        };

        let lpm_config = match pkg.lpm {
            Some(c) => c,
            None => return Self::default_policy(),
        };

        let min_age = lpm_config
            .minimum_release_age
            .unwrap_or(Self::DEFAULT_MIN_RELEASE_AGE);

        SecurityPolicy {
            trusted_dependencies: lpm_config.trusted_dependencies,
            minimum_release_age_secs: min_age,
        }
    }

    /// Lenient name-only check: returns true if the package name appears
    /// in `trustedDependencies` regardless of version, integrity, or
    /// script hash. Used by the existing `lpm build` code path before
    /// M5 swaps to [`Self::can_run_scripts_strict`].
    ///
    /// **Phase 4 deprecation note:** in the long term, callers should
    /// migrate to [`Self::can_run_scripts_strict`] which binds to the
    /// full `{name, version, integrity, script_hash}` tuple. The lenient
    /// check is kept ONLY for backwards compatibility with manifests
    /// that still have the legacy `Vec<String>` form.
    pub fn can_run_scripts(&self, package_name: &str) -> bool {
        self.trusted_dependencies
            .contains_name_lenient(package_name)
    }

    /// **Phase 32 Phase 4 strict gate.** Returns the full
    /// [`TrustMatch`] result for a package against the project's
    /// trustedDependencies, considering name + version + integrity +
    /// script hash.
    ///
    /// `lpm build` should branch on the result:
    /// - [`TrustMatch::Strict`] → run the script
    /// - [`TrustMatch::LegacyNameOnly`] → run the script + emit a deprecation warning
    /// - [`TrustMatch::BindingDrift`] → SKIP the script + warn the user to re-review
    /// - [`TrustMatch::NotTrusted`] → SKIP the script
    pub fn can_run_scripts_strict(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> TrustMatch {
        self.trusted_dependencies
            .matches_strict(name, version, integrity, script_hash)
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
        // Phase 4 M2: trusted_dependencies is now a TrustedDependencies enum.
        // Construct a Legacy variant directly to preserve the original test
        // semantic (name-only trust), which can_run_scripts honors via
        // contains_name_lenient.
        let mut policy = SecurityPolicy::default_policy();
        policy.trusted_dependencies = TrustedDependencies::Legacy(vec!["esbuild".to_string()]);

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
            trusted_dependencies: TrustedDependencies::default(),
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
            trusted_dependencies: TrustedDependencies::default(),
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
            trusted_dependencies: TrustedDependencies::default(),
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
            trusted_dependencies: TrustedDependencies::default(),
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
            trusted_dependencies: TrustedDependencies::default(),
            minimum_release_age_secs: 86400,
        };
        // No timestamp at all — can't check, return None
        assert!(policy.check_release_age(None).is_none());
    }

    #[test]
    fn release_age_disabled_policy() {
        let policy = SecurityPolicy {
            trusted_dependencies: TrustedDependencies::default(),
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

    #[test]
    fn release_age_boundary_exact_threshold() {
        // Package published exactly at the threshold boundary should pass (age == minimum).
        let policy = SecurityPolicy {
            trusted_dependencies: TrustedDependencies::default(),
            minimum_release_age_secs: 3600, // 1 hour
        };
        let now = OffsetDateTime::now_utc();
        // Published exactly 1 hour ago
        let published = now - time::Duration::seconds(3600);
        let ts = published.format(&Iso8601::DEFAULT).unwrap();
        assert!(
            policy.check_release_age(Some(&ts)).is_none(),
            "package at exact threshold should pass"
        );
    }

    #[test]
    fn release_age_just_under_threshold() {
        // Package published 1 second less than the threshold should be blocked.
        let policy = SecurityPolicy {
            trusted_dependencies: TrustedDependencies::default(),
            minimum_release_age_secs: 3600,
        };
        let now = OffsetDateTime::now_utc();
        // Published 3599 seconds ago (1 second short of 1 hour)
        let published = now - time::Duration::seconds(3599);
        let ts = published.format(&Iso8601::DEFAULT).unwrap();
        assert!(
            policy.check_release_age(Some(&ts)).is_some(),
            "package just under threshold must be blocked"
        );
    }

    #[test]
    fn custom_release_age_from_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"name":"test","lpm":{"trustedDependencies":[],"minimumReleaseAge":7200}}"#,
        )
        .unwrap();

        let policy = SecurityPolicy::from_package_json(&pkg_json);
        assert_eq!(policy.minimum_release_age_secs, 7200);
    }
}
