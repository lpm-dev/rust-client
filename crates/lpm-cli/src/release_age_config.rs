//! release-age cooldown config loader.
//!
//! Resolves the effective release-age config for a project install.
//! The cooldown seconds walk this precedence chain, highest first:
//!
//! 1. **CLI flag**: `lpm install --min-release-age=<dur>`. Parsed via
//!    [`parse_duration`] — accepts `m` / `h` / `d` suffixes and plain seconds.
//! 2. **Per-project**: `package.json > lpm > minimumReleaseAge`. Read
//!    via [`lpm_workspace::read_package_json`]; tolerant of missing /
//!    malformed manifest (matches [`lpm_security::SecurityPolicy::from_package_json`]).
//! 3. **Global**: the configured LPM root's `config.toml` key
//!    `minimum-release-age-secs`.
//!    Read with a path-aware fallible loader; malformed TOML or a
//!    garbage value surfaces a file-pathed error rather than being
//!    silently ignored as [`crate::commands::config::GlobalConfig::load`]
//!    would do).
//! 4. **Default**: 86400 (24h).
//!
//! `minimumReleaseAgePolicy` follows the same project/global/default
//! tiers, using `direct` by default and `strict` for opt-in transitive
//! enforcement.
//!
//! `./lpm.toml` is deliberately NOT in this chain: the project-local
//! TOML is scoped to save-policy keys, while release-age policy lives in
//! package.json, global config, or per-invocation flags.
//!
//! Package, exact-version, and scoped-wildcard excludes are merged from the CLI
//! `--min-release-age-exclude <selector>` list, `package.json > lpm >
//! minimumReleaseAgeExclude`, and `~/.lpm/config.toml >
//! minimum-release-age-exclude` when those layers are consulted. Excludes
//! affect only release-age selection and the install halt; lifecycle
//! script cooldown hardening still receives publish-age data.
//!
//! The resolver returns `Result<ReleaseAgeConfig, LpmError>`. The global
//! TOML layer can raise file read, parse, or value-shape errors. The CLI
//! duration input is validated upstream by the clap parser hook; the
//! package.json layer is deliberately tolerant of missing or malformed
//! manifests, preserving the default cooldown behaviour for ordinary
//! installs.
//!
//! The effective seconds value is then passed to
//! [`lpm_security::SecurityPolicy::with_resolved_min_age`], which couples
//! it with the `trustedDependencies` read from the same manifest.
//!
//! The install-time call site for the resolver lives in
//! [`crate::commands::install::run_with_options`] just before the
//! `minimumReleaseAge` gate; the clap layer parses `--min-release-age`
//! via [`parse_duration`] and fans the resulting `Option<u64>` through
//! the install entry points alongside `allow_new`.

use lpm_common::{LpmError, LpmRoot};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Default cooldown window when nothing else is configured (matches
/// [`lpm_security::SecurityPolicy::DEFAULT_MIN_RELEASE_AGE`]; copied
/// here to keep this module self-contained and to avoid poking at
/// lpm-security's private constant).
pub(crate) const DEFAULT_MIN_RELEASE_AGE_SECS: u64 = 86400;

/// TOML key in `~/.lpm/config.toml` holding the global override.
const GLOBAL_KEY: &str = "minimum-release-age-secs";
const GLOBAL_EXCLUDE_KEY: &str = "minimum-release-age-exclude";
pub(crate) const GLOBAL_POLICY_KEY: &str = "release-age-policy";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseAgeConfig {
    pub minimum_release_age_secs: u64,
    pub minimum_release_age_exclude: Vec<String>,
    pub minimum_release_age_policy: ReleaseAgePolicy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ReleaseAgePolicy {
    #[default]
    Direct,
    Strict,
}

impl ReleaseAgePolicy {
    pub(crate) fn parse(source: &str, raw: &str) -> Result<Self, LpmError> {
        match raw {
            "direct" | "default" => Ok(Self::Direct),
            "strict" => Ok(Self::Strict),
            _ => Err(LpmError::Registry(format!(
                "{source} must be one of: direct | strict"
            ))),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Strict => "strict",
        }
    }

    pub(crate) const fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }

    pub(crate) const fn loosens(self, floor: Self) -> bool {
        self.rank() < floor.rank()
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Direct => 0,
            Self::Strict => 1,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct GlobalReleaseAgeConfig {
    minimum_release_age_secs: Option<u64>,
    minimum_release_age_exclude: Vec<String>,
    minimum_release_age_policy: Option<ReleaseAgePolicy>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PackageReleaseAgeConfig {
    minimum_release_age_secs: Option<u64>,
    minimum_release_age_exclude: Vec<String>,
    minimum_release_age_policy: Option<ReleaseAgePolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseAgePolicySource {
    Project,
    Global,
    Default,
}

/// Parse the `--min-release-age=<dur>` CLI argument into a seconds count.
///
/// Accepted forms:
/// - `<N>m` — minutes (e.g. `10m` → 600)
/// - `<N>h` — hours (e.g. `72h` → 259_200)
/// - `<N>d` — days (e.g. `3d` → 259_200)
/// - `<N>` — plain seconds (e.g. `86400`)
///
/// Rejected:
/// - Empty string
/// - Surrounding whitespace (`" 72h "`)
/// - Bare suffix without a number (`h`, `d`)
/// - Unsupported suffixes (`1w`, `1y`)
/// - Negative values (`-5h`, `-1`)
/// - Non-integer scalars (`0.5h`, `1.5d`)
/// - Overflow when multiplying hours/days into seconds
///
/// Errors are descriptive and include the offending input verbatim so
/// clap surfaces them directly to the user.
pub fn parse_duration(input: &str) -> Result<u64, LpmError> {
    if input.is_empty() {
        return Err(LpmError::Registry(
            "release-age duration must not be empty (expected `<N>m`, `<N>h`, `<N>d`, or `<N>` seconds)"
                .into(),
        ));
    }
    if input.trim() != input {
        return Err(LpmError::Registry(format!(
            "release-age duration `{input}` must not contain surrounding whitespace"
        )));
    }

    if let Some(minutes_str) = input.strip_suffix('m') {
        let minutes = parse_scalar(minutes_str, input)?;
        minutes
            .checked_mul(60)
            .ok_or_else(|| overflow_err(input, "minutes"))
    } else if let Some(hours_str) = input.strip_suffix('h') {
        let hours = parse_scalar(hours_str, input)?;
        hours
            .checked_mul(3600)
            .ok_or_else(|| overflow_err(input, "hours"))
    } else if let Some(days_str) = input.strip_suffix('d') {
        let days = parse_scalar(days_str, input)?;
        days.checked_mul(86400)
            .ok_or_else(|| overflow_err(input, "days"))
    } else if input
        .chars()
        .last()
        .is_some_and(|c| c.is_ascii_alphabetic())
    {
        Err(LpmError::Registry(format!(
            "release-age duration `{input}` has an unsupported unit (expected `m`, `h`, `d`, or plain seconds)"
        )))
    } else {
        parse_scalar(input, input)
    }
}

fn parse_scalar(scalar: &str, original: &str) -> Result<u64, LpmError> {
    if scalar.is_empty() {
        return Err(LpmError::Registry(format!(
            "release-age duration `{original}` has no numeric value (expected `<N>m`, `<N>h`, `<N>d`, or `<N>` seconds)"
        )));
    }
    if scalar.starts_with('-') {
        return Err(LpmError::Registry(format!(
            "release-age duration `{original}` must be non-negative"
        )));
    }
    // `u64::from_str` silently accepts a leading `+` (e.g. `"+5".parse::<u64>()`
    // returns `Ok(5)`). Reject it explicitly so `+5h` doesn't quietly mean `5h`.
    if scalar.starts_with('+') {
        return Err(LpmError::Registry(format!(
            "release-age duration `{original}` is not a valid non-negative integer (expected `<N>h`, `<N>d`, or `<N>` seconds)"
        )));
    }
    scalar.parse::<u64>().map_err(|_| {
        LpmError::Registry(format!(
            "release-age duration `{original}` is not a valid non-negative integer (expected `<N>h`, `<N>d`, or `<N>` seconds)"
        ))
    })
}

fn overflow_err(input: &str, unit: &str) -> LpmError {
    LpmError::Registry(format!(
        "release-age duration `{input}` overflows when converting {unit} to seconds"
    ))
}

/// Parse a string as a non-negative `u64`, rejecting explicit sign
/// prefixes (`+` or `-`).
///
/// `u64::from_str` silently accepts a leading `+` (`"+5".parse::<u64>()`
/// returns `Ok(5)`), which would let values like `"+259200"` slip
/// through the string-coercion paths in the global config reader and
/// [`crate::commands::config::GlobalConfig::get_u64`]. Since the CLI
/// parser rejects `+5h` by contract, every string-coercion site that
/// interprets a value as seconds MUST apply the same rule — otherwise
/// the persistent config surface silently accepts inputs the CLI
/// rejects, breaking the least-surprise property across the precedence
/// chain.
///
/// This helper is the single source of truth for string-to-seconds
/// coercion. Callers render error messages as appropriate for their
/// context (file-pathed for the global loader, `Option<u64>` for the
/// `GlobalConfig` convenience reader).
pub(crate) fn parse_strict_u64_string(s: &str) -> Option<u64> {
    if s.starts_with('-') || s.starts_with('+') {
        return None;
    }
    s.parse::<u64>().ok()
}

/// Resolve the effective `minimumReleaseAge` for a project install.
///
/// See module docs for the precedence chain. The caller is responsible
/// for validating `cli_override` upstream (typically by routing
/// `--min-release-age=<dur>` through [`parse_duration`] in the clap
/// layer). This function treats `cli_override` as already-validated.
pub struct ReleaseAgeResolver;

impl ReleaseAgeResolver {
    /// Walk the precedence chain and return the effective seconds value.
    ///
    /// Returns an error only if the global `~/.lpm/config.toml` exists
    /// and is unreadable / malformed / has a garbage
    /// `minimum-release-age-secs` value. A missing global file is fine
    /// (falls through to default).
    #[cfg(test)]
    pub fn resolve(
        project_dir: &Path,
        cli_override: Option<u64>,
        json_output: bool,
    ) -> Result<u64, LpmError> {
        Ok(
            Self::resolve_config(project_dir, cli_override, &[], json_output)?
                .minimum_release_age_secs,
        )
    }

    pub fn resolve_config(
        project_dir: &Path,
        cli_override: Option<u64>,
        cli_exclude: &[String],
        json_output: bool,
    ) -> Result<ReleaseAgeConfig, LpmError> {
        let global = crate::commands::config::GlobalConfig::load();
        let effective_authorized = crate::security_approval::load_effective_authorized_posture()?;
        let authorized_floor = effective_authorized.posture.minimum_release_age_secs();
        let authorized_policy = effective_authorized.posture.release_age_policy();
        let force_security_floor = crate::security_floor::force_security_floor_enabled(&global);
        let floor = crate::security_floor::current_release_age_floor_secs(&global);
        let policy_floor = crate::security_floor::current_release_age_policy_floor(&global);
        let mut minimum_release_age_exclude =
            validate_release_age_excludes("--min-release-age-exclude", cli_exclude)?;

        let package_config =
            read_package_json_release_age_config(&project_dir.join("package.json"))?
                .unwrap_or_default();
        extend_unique_excludes(
            &mut minimum_release_age_exclude,
            package_config.minimum_release_age_exclude,
        );
        let global_release_age_config = match global_config_path() {
            Some(path) => match read_global_release_age_config_from_file(&path) {
                Ok(mut config) => {
                    ensure_global_release_age_excludes_authorized(
                        &effective_authorized,
                        project_dir,
                        json_output,
                        &config.minimum_release_age_exclude,
                    )?;
                    extend_unique_excludes(
                        &mut minimum_release_age_exclude,
                        std::mem::take(&mut config.minimum_release_age_exclude),
                    );
                    Ok(Some(config))
                }
                Err(err) => Err(err),
            },
            None => Ok(None),
        };
        let global_policy = global_release_age_config
            .as_ref()
            .ok()
            .and_then(|config| config.as_ref())
            .and_then(|config| config.minimum_release_age_policy);
        let (requested_policy, policy_source) =
            if let Some(policy) = package_config.minimum_release_age_policy {
                (policy, ReleaseAgePolicySource::Project)
            } else if let Some(policy) = global_policy {
                (policy, ReleaseAgePolicySource::Global)
            } else {
                (ReleaseAgePolicy::default(), ReleaseAgePolicySource::Default)
            };
        let effective_policy = enforce_release_age_policy_posture(
            project_dir,
            json_output,
            force_security_floor,
            requested_policy,
            policy_source,
            authorized_policy,
            policy_floor,
        )?;

        if let Some(secs) = cli_override {
            if secs < authorized_floor {
                crate::security_approval::ensure_project_unlock(
                    crate::security_approval::ApprovalScope::CooldownBypass,
                    project_dir,
                    json_output,
                    crate::security_approval::ApprovalSource::CliFlag,
                    &format!(
                        "This install request lowers minimum release age to {secs}s for this project."
                    ),
                    Some(secs),
                    &[],
                )?;
                return Ok(ReleaseAgeConfig {
                    minimum_release_age_secs: secs,
                    minimum_release_age_exclude,
                    minimum_release_age_policy: effective_policy,
                });
            }
            if force_security_floor && secs < floor {
                crate::security_floor::record_suppression(
                    crate::security_floor::SuppressionRecord::new(
                        crate::security_floor::GuardedControl::CooldownWindow,
                        crate::security_floor::SuppressionSource::Cli,
                        secs.to_string(),
                        floor.to_string(),
                    ),
                    json_output,
                );
                return Ok(ReleaseAgeConfig {
                    minimum_release_age_secs: floor,
                    minimum_release_age_exclude,
                    minimum_release_age_policy: effective_policy,
                });
            }
            return Ok(ReleaseAgeConfig {
                minimum_release_age_secs: secs,
                minimum_release_age_exclude,
                minimum_release_age_policy: effective_policy,
            });
        }
        if let Some(secs) = package_config.minimum_release_age_secs {
            if secs < authorized_floor {
                crate::security_approval::ensure_project_unlock(
                    crate::security_approval::ApprovalScope::CooldownBypass,
                    project_dir,
                    json_output,
                    crate::security_approval::ApprovalSource::ProjectConfig,
                    "package.json requests a lower minimum release age than this machine has approved.",
                    Some(secs),
                    &[],
                )?;
                return Ok(ReleaseAgeConfig {
                    minimum_release_age_secs: secs,
                    minimum_release_age_exclude,
                    minimum_release_age_policy: effective_policy,
                });
            }
            if force_security_floor && secs < floor {
                crate::security_floor::record_suppression(
                    crate::security_floor::SuppressionRecord::new(
                        crate::security_floor::GuardedControl::CooldownWindow,
                        crate::security_floor::SuppressionSource::Project,
                        secs.to_string(),
                        floor.to_string(),
                    ),
                    json_output,
                );
                return Ok(ReleaseAgeConfig {
                    minimum_release_age_secs: floor,
                    minimum_release_age_exclude,
                    minimum_release_age_policy: effective_policy,
                });
            }
            return Ok(ReleaseAgeConfig {
                minimum_release_age_secs: secs,
                minimum_release_age_exclude,
                minimum_release_age_policy: effective_policy,
            });
        }
        if let Some(global_config) = global_release_age_config?
            && let Some(secs) = global_config.minimum_release_age_secs
        {
            if secs < authorized_floor {
                return Err(crate::security_approval::approval_required_error(
                    "the persisted global minimum-release-age-secs value is weaker than this machine has approved",
                    vec![
                        crate::security_approval::ApprovalScope::CooldownBypass
                            .as_str()
                            .to_string(),
                    ],
                    None,
                    Some(format!("lpm config set {GLOBAL_KEY} {secs}")),
                ));
            }
            return Ok(ReleaseAgeConfig {
                minimum_release_age_secs: secs,
                minimum_release_age_exclude,
                minimum_release_age_policy: effective_policy,
            });
        }
        Ok(ReleaseAgeConfig {
            minimum_release_age_secs: DEFAULT_MIN_RELEASE_AGE_SECS,
            minimum_release_age_exclude,
            minimum_release_age_policy: effective_policy,
        })
    }
}

fn ensure_global_release_age_excludes_authorized(
    effective: &crate::security_approval::EffectiveAuthorizedPosture,
    project_dir: &Path,
    json_output: bool,
    exclusions: &[String],
) -> Result<(), LpmError> {
    if exclusions.is_empty() {
        return Ok(());
    }
    let managed_cooldown = matches!(
        effective.sources.minimum_release_age_secs,
        crate::security_approval::PostureSourceKind::ManagedPolicy
    ) || matches!(
        effective.sources.release_age_policy,
        crate::security_approval::PostureSourceKind::ManagedPolicy
    );
    let unauthorized: Vec<_> = exclusions
        .iter()
        .filter(|selector| {
            managed_cooldown
                || !effective
                    .posture
                    .minimum_release_age_exclude
                    .contains(selector)
        })
        .cloned()
        .collect();
    if unauthorized.is_empty() {
        return Ok(());
    }
    crate::security_approval::ensure_project_unlock(
        crate::security_approval::ApprovalScope::CooldownBypass,
        project_dir,
        json_output,
        crate::security_approval::ApprovalSource::GlobalConfig,
        "The persisted global release-age exclusion list bypasses the approved cooldown for matching packages.",
        None,
        &unauthorized,
    )
}

fn enforce_release_age_policy_posture(
    project_dir: &Path,
    json_output: bool,
    force_security_floor: bool,
    requested: ReleaseAgePolicy,
    source: ReleaseAgePolicySource,
    authorized_floor: ReleaseAgePolicy,
    force_floor: ReleaseAgePolicy,
) -> Result<ReleaseAgePolicy, LpmError> {
    if requested.loosens(authorized_floor) {
        match source {
            ReleaseAgePolicySource::Project => {
                crate::security_approval::ensure_project_unlock(
                    crate::security_approval::ApprovalScope::CooldownWindow,
                    project_dir,
                    json_output,
                    crate::security_approval::ApprovalSource::ProjectConfig,
                    "package.json requests a looser minimum release age policy than this machine has approved.",
                    None,
                    &[],
                )?;
            }
            ReleaseAgePolicySource::Global => {
                return Err(crate::security_approval::approval_required_error(
                    "the persisted global release-age-policy value is weaker than this machine has approved",
                    vec![
                        crate::security_approval::ApprovalScope::CooldownWindow
                            .as_str()
                            .to_string(),
                    ],
                    None,
                    Some(format!(
                        "lpm config set {GLOBAL_POLICY_KEY} {}",
                        requested.as_str()
                    )),
                ));
            }
            ReleaseAgePolicySource::Default => {}
        }
    }
    if force_security_floor && requested.loosens(force_floor) {
        if matches!(source, ReleaseAgePolicySource::Project) {
            crate::security_floor::record_suppression(
                crate::security_floor::SuppressionRecord::new(
                    crate::security_floor::GuardedControl::CooldownWindow,
                    crate::security_floor::SuppressionSource::Project,
                    requested.as_str(),
                    force_floor.as_str(),
                ),
                json_output,
            );
        }
        return Ok(force_floor);
    }
    Ok(requested)
}

/// Locate the configured LPM root's `config.toml`. Returns `None` only when the root is
/// unset — in that case the global layer is silently skipped
/// (matches [`crate::commands::config::GlobalConfig::load`]).
fn global_config_path() -> Option<PathBuf> {
    LpmRoot::from_env()
        .ok()
        .map(|root| root.root().join("config.toml"))
}

fn read_package_json_release_age_config(
    pkg_json_path: &Path,
) -> Result<Option<PackageReleaseAgeConfig>, LpmError> {
    let Ok(pkg) = lpm_workspace::read_package_json(pkg_json_path) else {
        return Ok(None);
    };
    let Some(lpm) = pkg.lpm else {
        return Ok(None);
    };
    Ok(Some(PackageReleaseAgeConfig {
        minimum_release_age_secs: lpm.minimum_release_age,
        minimum_release_age_exclude: validate_release_age_excludes(
            "package.json lpm.minimumReleaseAgeExclude",
            &lpm.minimum_release_age_exclude,
        )?,
        minimum_release_age_policy: lpm
            .minimum_release_age_policy
            .as_deref()
            .map(|raw| ReleaseAgePolicy::parse("package.json lpm.minimumReleaseAgePolicy", raw))
            .transpose()?,
    }))
}

/// Read `minimum-release-age-secs` from a `~/.lpm/config.toml` at `path`.
///
/// Missing file → `Ok(None)`. Malformed TOML, non-table top level, or a
/// `minimum-release-age-secs` value that isn't a non-negative integer
/// (native or string-coerced) → `Err` with the file path baked in,
/// mirroring the save-config loader error style.
///
/// String coercion accepts values like `"86400"` because the generic
/// `lpm config set <key> <value>` command writes every value as a TOML
/// string; the documented
/// persistent-config path must actually work.
#[cfg(test)]
fn read_global_min_age_from_file(path: &Path) -> Result<Option<u64>, LpmError> {
    Ok(read_global_release_age_config_from_file(path)?.minimum_release_age_secs)
}

fn read_global_release_age_config_from_file(
    path: &Path,
) -> Result<GlobalReleaseAgeConfig, LpmError> {
    let raw = match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
    {
        Ok(raw) => raw,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return Ok(GlobalReleaseAgeConfig::default());
        }
        Err(error) => return Err(LpmError::Registry(error.to_string())),
    };
    let parsed: toml::Value = toml::from_str(&raw)
        .map_err(|e| LpmError::Registry(format!("failed to parse {}: {e}", path.display())))?;
    let table = match parsed {
        toml::Value::Table(t) => t,
        _ => {
            return Err(LpmError::Registry(format!(
                "{} must be a TOML table at the top level",
                path.display()
            )));
        }
    };
    let minimum_release_age_secs = match table.get(GLOBAL_KEY) {
        Some(value) => Some(parse_global_min_age_value(path, value)?),
        None => None,
    };
    let minimum_release_age_exclude = match table.get(GLOBAL_EXCLUDE_KEY) {
        Some(value) => parse_global_release_age_exclude_value(path, value)?,
        None => Vec::new(),
    };
    let minimum_release_age_policy = match table.get(GLOBAL_POLICY_KEY) {
        Some(value) => Some(parse_global_release_age_policy_value(path, value)?),
        None => None,
    };
    Ok(GlobalReleaseAgeConfig {
        minimum_release_age_secs,
        minimum_release_age_exclude,
        minimum_release_age_policy,
    })
}

fn parse_global_min_age_value(path: &Path, value: &toml::Value) -> Result<u64, LpmError> {
    match value {
        toml::Value::Integer(i) => u64::try_from(*i).map_err(|_| {
            LpmError::Registry(format!(
                "{}: `{GLOBAL_KEY}` must be a non-negative integer (seconds), got {i}",
                path.display()
            ))
        }),
        toml::Value::String(s) => parse_strict_u64_string(s).ok_or_else(|| {
            LpmError::Registry(format!(
                "{}: `{GLOBAL_KEY}` must be a non-negative integer (seconds) or a string \
                 parseable as one (e.g. \"86400\"), got \"{s}\"",
                path.display()
            ))
        }),
        other => Err(LpmError::Registry(format!(
            "{}: `{GLOBAL_KEY}` must be a non-negative integer (seconds), got {other}",
            path.display()
        ))),
    }
}

fn parse_global_release_age_exclude_value(
    path: &Path,
    value: &toml::Value,
) -> Result<Vec<String>, LpmError> {
    let Some(entries) = value.as_array() else {
        return Err(LpmError::Registry(format!(
            "{}: `{GLOBAL_EXCLUDE_KEY}` must be an array of exact package names",
            path.display()
        )));
    };
    let raw: Result<Vec<_>, _> = entries
        .iter()
        .map(|entry| {
            entry.as_str().map(str::to_string).ok_or_else(|| {
                LpmError::Registry(format!(
                    "{}: `{GLOBAL_EXCLUDE_KEY}` entries must be strings",
                    path.display()
                ))
            })
        })
        .collect();
    validate_release_age_excludes(GLOBAL_EXCLUDE_KEY, &raw?)
}

fn parse_global_release_age_policy_value(
    path: &Path,
    value: &toml::Value,
) -> Result<ReleaseAgePolicy, LpmError> {
    let Some(raw) = value.as_str() else {
        return Err(LpmError::Registry(format!(
            "{}: `{GLOBAL_POLICY_KEY}` must be a string (`direct` or `strict`)",
            path.display()
        )));
    };
    ReleaseAgePolicy::parse(GLOBAL_POLICY_KEY, raw)
        .map_err(|err| LpmError::Registry(format!("{}: {}", path.display(), err)))
}

pub(crate) fn validate_release_age_excludes(
    source: &str,
    excludes: &[String],
) -> Result<Vec<String>, LpmError> {
    let mut seen = HashSet::with_capacity(excludes.len());
    let mut normalized = Vec::with_capacity(excludes.len());
    for raw in excludes {
        let exclude = parse_release_age_exclude(source, raw)?;
        let normalized_exclude = exclude.to_string();
        if seen.insert(normalized_exclude.clone()) {
            normalized.push(normalized_exclude);
        }
    }
    Ok(normalized)
}

pub(crate) fn parse_release_age_exclusions(
    source: &str,
    excludes: &[String],
) -> Result<Vec<lpm_resolver::ReleaseAgeExclusion>, LpmError> {
    excludes
        .iter()
        .map(|raw| parse_release_age_exclude(source, raw))
        .collect()
}

fn parse_release_age_exclude(
    source: &str,
    raw: &str,
) -> Result<lpm_resolver::ReleaseAgeExclusion, LpmError> {
    raw.parse().map_err(|detail| {
        LpmError::Registry(format!(
            "{source} entry `{raw}` is invalid: {detail}; expected a package name, exact package version, or `@scope/*`"
        ))
    })
}

fn extend_unique_excludes(target: &mut Vec<String>, source: Vec<String>) {
    if source.is_empty() {
        return;
    }
    let mut seen: HashSet<String> = target.iter().cloned().collect();
    target.reserve(source.len());
    for package in source {
        if seen.insert(package.clone()) {
            target.push(package);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ── parse_duration ───────────────────────────────────────────

    #[test]
    fn parse_hours_suffix() {
        assert_eq!(parse_duration("72h").unwrap(), 72 * 3600);
    }

    #[test]
    fn parse_one_hour() {
        assert_eq!(parse_duration("1h").unwrap(), 3600);
    }

    #[test]
    fn parse_zero_hours() {
        assert_eq!(parse_duration("0h").unwrap(), 0);
    }

    #[test]
    fn parse_minutes_suffix() {
        assert_eq!(parse_duration("10m").unwrap(), 600);
    }

    #[test]
    fn parse_zero_minutes() {
        assert_eq!(parse_duration("0m").unwrap(), 0);
    }

    #[test]
    fn parse_days_suffix() {
        assert_eq!(parse_duration("3d").unwrap(), 3 * 86400);
    }

    #[test]
    fn parse_zero_days() {
        assert_eq!(parse_duration("0d").unwrap(), 0);
    }

    #[test]
    fn parse_plain_seconds() {
        assert_eq!(parse_duration("86400").unwrap(), 86400);
    }

    #[test]
    fn parse_zero_plain() {
        assert_eq!(parse_duration("0").unwrap(), 0);
    }

    #[test]
    fn parse_leading_zeros_allowed() {
        // `u64::from_str` accepts leading zeros; no need to be fussier.
        assert_eq!(parse_duration("01h").unwrap(), 3600);
    }

    #[test]
    fn reject_empty() {
        let err = parse_duration("").unwrap_err().to_string();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn reject_leading_whitespace() {
        let err = parse_duration(" 72h").unwrap_err().to_string();
        assert!(err.contains("whitespace"), "got: {err}");
    }

    #[test]
    fn reject_trailing_whitespace() {
        let err = parse_duration("72h ").unwrap_err().to_string();
        assert!(err.contains("whitespace"), "got: {err}");
    }

    #[test]
    fn reject_lone_hours_suffix() {
        let err = parse_duration("h").unwrap_err().to_string();
        assert!(err.contains("no numeric value"), "got: {err}");
    }

    #[test]
    fn reject_lone_days_suffix() {
        let err = parse_duration("d").unwrap_err().to_string();
        assert!(err.contains("no numeric value"), "got: {err}");
    }

    #[test]
    fn reject_weeks_suffix() {
        let err = parse_duration("1w").unwrap_err().to_string();
        assert!(err.contains("unsupported unit"), "got: {err}");
    }

    #[test]
    fn reject_negative_hours() {
        let err = parse_duration("-5h").unwrap_err().to_string();
        assert!(err.contains("non-negative"), "got: {err}");
    }

    #[test]
    fn reject_negative_plain() {
        let err = parse_duration("-5").unwrap_err().to_string();
        // The plain-seconds path hits `parse_scalar` which catches the
        // leading `-` first.
        assert!(err.contains("non-negative"), "got: {err}");
    }

    #[test]
    fn reject_garbage() {
        let err = parse_duration("abc").unwrap_err().to_string();
        // `abc` ends in `c` (alphabetic) → the unsupported-unit branch fires.
        assert!(err.contains("unsupported unit"), "got: {err}");
    }

    #[test]
    fn reject_fractional_hours() {
        let err = parse_duration("0.5h").unwrap_err().to_string();
        assert!(
            err.contains("not a valid non-negative integer"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_plus_sign() {
        // `u64::from_str` rejects `+5` — the hours path surfaces the
        // "not a valid integer" branch (not the `-` branch).
        let err = parse_duration("+5h").unwrap_err().to_string();
        assert!(
            err.contains("not a valid non-negative integer"),
            "got: {err}"
        );
    }

    #[test]
    fn reject_hours_overflow() {
        // u64::MAX / 3600 = ~5.1e15. Anything bigger overflows.
        let input = format!("{}h", u64::MAX);
        let err = parse_duration(&input).unwrap_err().to_string();
        assert!(err.contains("overflows"), "got: {err}");
        assert!(err.contains("hours"), "got: {err}");
    }

    #[test]
    fn reject_days_overflow() {
        let input = format!("{}d", u64::MAX);
        let err = parse_duration(&input).unwrap_err().to_string();
        assert!(err.contains("overflows"), "got: {err}");
        assert!(err.contains("days"), "got: {err}");
    }

    // ── read_global_min_age_from_file ────────────────────────────

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn global_file_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_global_min_age_from_file(&dir.path().join("config.toml")).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn global_file_empty_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "");
        let result = read_global_min_age_from_file(&path).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn global_file_key_absent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "some-other-key = 42\n");
        let result = read_global_min_age_from_file(&path).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn global_file_integer_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "minimum-release-age-secs = 259200\n");
        let result = read_global_min_age_from_file(&path).unwrap();
        assert_eq!(result, Some(259200));
    }

    /// `lpm config set minimum-release-age-secs 259200` writes a TOML
    /// string. The loader MUST accept that form or the
    /// documented persistent-config path is unusable.
    #[test]
    fn global_file_string_value_for_config_set_compat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-secs = "259200""#);
        let result = read_global_min_age_from_file(&path).unwrap();
        assert_eq!(result, Some(259200));
    }

    #[test]
    fn global_file_minimum_release_age_exclude_array_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(
            &path,
            r#"minimum-release-age-exclude = ["react", "@scope/pkg"]"#,
        );
        let result = read_global_release_age_config_from_file(&path).unwrap();
        assert_eq!(result.minimum_release_age_secs, None);
        assert_eq!(
            result.minimum_release_age_exclude,
            vec!["react".to_string(), "@scope/pkg".to_string()]
        );
    }

    #[test]
    fn global_file_minimum_release_age_exclude_accepts_scoped_wildcard_selector() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-exclude = ["@scope/*"]"#);
        let result = read_global_release_age_config_from_file(&path).unwrap();

        assert_eq!(result.minimum_release_age_exclude, vec!["@scope/*"]);
    }

    #[test]
    fn global_file_minimum_release_age_exclude_accepts_exact_version_selector() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-exclude = ["react@19.0.0"]"#);
        let result = read_global_release_age_config_from_file(&path).unwrap();

        assert_eq!(result.minimum_release_age_exclude, vec!["react@19.0.0"]);
    }

    #[test]
    fn global_file_minimum_release_age_exclude_wrong_type_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-exclude = "react""#);
        let err = read_global_release_age_config_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("minimum-release-age-exclude"), "got: {err}");
        assert!(err.contains("array"), "got: {err}");
    }

    #[test]
    fn global_file_release_age_policy_string_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"release-age-policy = "strict""#);
        let result = read_global_release_age_config_from_file(&path).unwrap();
        assert_eq!(
            result.minimum_release_age_policy,
            Some(ReleaseAgePolicy::Strict)
        );
    }

    #[test]
    fn global_file_release_age_policy_rejects_unknown_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"release-age-policy = "transitive""#);
        let err = read_global_release_age_config_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("release-age-policy"), "got: {err}");
        assert!(err.contains("direct | strict"), "got: {err}");
    }

    #[test]
    fn minimum_release_age_exclude_rejects_protocol_specifier() {
        let err =
            validate_release_age_excludes("--min-release-age-exclude", &["npm:react".to_string()])
                .unwrap_err()
                .to_string();

        assert!(err.contains("protocol"), "got: {err}");
    }

    #[test]
    fn minimum_release_age_exclude_rejects_malformed_scoped_name() {
        let err =
            validate_release_age_excludes("--min-release-age-exclude", &["@scope".to_string()])
                .unwrap_err()
                .to_string();

        assert!(err.contains("invalid package name"), "got: {err}");
    }

    #[test]
    fn minimum_release_age_exclude_rejects_root_pseudo_package() {
        let err =
            validate_release_age_excludes("--min-release-age-exclude", &["<root>".to_string()])
                .unwrap_err()
                .to_string();

        assert!(err.contains("resolver root"), "got: {err}");
    }

    #[test]
    fn global_file_negative_integer_rejected_with_path_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "minimum-release-age-secs = -1\n");
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name the file: {err}");
        assert!(
            err.contains("minimum-release-age-secs"),
            "must name the key: {err}"
        );
    }

    /// `u64::from_str("+5")` returns `Ok(5)`, so without an explicit
    /// sign-prefix rejection the global-TOML
    /// string path would silently accept `"+259200"` even though the
    /// CLI flag rejects `+5h`. Both string-coercion sites now route
    /// through [`parse_strict_u64_string`] for uniform behaviour; this
    /// test is the regression guard against drift.
    #[test]
    fn global_file_plus_prefixed_string_rejected_with_path_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-secs = "+259200""#);
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name the file: {err}");
        assert!(
            err.contains("minimum-release-age-secs"),
            "must name the key: {err}"
        );
    }

    /// Symmetric regression: the `-` prefix must also surface a
    /// file-pathed error, not silently parse. `u64::from_str("-5")`
    /// already returns `Err`, so the string path's behaviour here
    /// matches the CLI parser's "must be non-negative" branch —
    /// [`parse_strict_u64_string`] makes that guarantee explicit rather
    /// than implicit.
    #[test]
    fn global_file_minus_prefixed_string_rejected_with_path_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-secs = "-1""#);
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name the file: {err}");
        assert!(
            err.contains("minimum-release-age-secs"),
            "must name the key: {err}"
        );
    }

    #[test]
    fn global_file_garbage_string_rejected_with_path_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, r#"minimum-release-age-secs = "forever""#);
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name the file: {err}");
        assert!(
            err.contains("minimum-release-age-secs"),
            "must name the key: {err}"
        );
    }

    #[test]
    fn global_file_wrong_type_rejected() {
        // A TOML array isn't coercible. Must surface a clear error,
        // not silently ignore.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "minimum-release-age-secs = [1, 2, 3]\n");
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("minimum-release-age-secs"), "got: {err}");
    }

    #[test]
    fn global_file_malformed_toml_rejected_with_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_file(&path, "not valid toml === [[[");
        let err = read_global_min_age_from_file(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name the file: {err}");
    }

    // ── ReleaseAgeResolver::resolve ──────────────────────────────

    /// Redirect HOME and LPM_HOME so the default LPM root points at a
    /// per-test temp directory — otherwise the resolver would pick up the
    /// developer's actual global config. Mirrors the `scoped_home_dir`
    /// helper in [`crate::save_config`].
    fn scoped_home_dir() -> ScopedHomeDir {
        let dir = tempfile::tempdir().unwrap();
        let env = crate::test_env::ScopedEnv::set([
            ("HOME", dir.path().as_os_str().to_owned()),
            ("LPM_HOME", dir.path().join(".lpm").as_os_str().to_owned()),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                std::ffi::OsString::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
            ),
        ]);
        ScopedHomeDir { dir, _env: env }
    }

    struct ScopedHomeDir {
        dir: tempfile::TempDir,
        _env: crate::test_env::ScopedEnv,
    }

    impl ScopedHomeDir {
        fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    fn write_package_json_with_min_age_and_excludes(
        project: &Path,
        secs: Option<u64>,
        excludes: &[&str],
    ) {
        let mut lpm = serde_json::Map::new();
        if let Some(secs) = secs {
            lpm.insert(
                "minimumReleaseAge".to_string(),
                serde_json::Value::Number(secs.into()),
            );
        }
        if !excludes.is_empty() {
            lpm.insert(
                "minimumReleaseAgeExclude".to_string(),
                serde_json::json!(excludes),
            );
        }

        let mut body = serde_json::json!({ "name": "p", "version": "0.0.0" });
        if !lpm.is_empty() {
            body["lpm"] = serde_json::Value::Object(lpm);
        }
        write_file(
            &project.join("package.json"),
            &serde_json::to_string(&body).unwrap(),
        );
    }

    fn write_package_json_with_min_age_and_policy(
        project: &Path,
        secs: Option<u64>,
        policy: Option<&str>,
    ) {
        let mut lpm = serde_json::Map::new();
        if let Some(secs) = secs {
            lpm.insert(
                "minimumReleaseAge".to_string(),
                serde_json::Value::Number(secs.into()),
            );
        }
        if let Some(policy) = policy {
            lpm.insert(
                "minimumReleaseAgePolicy".to_string(),
                serde_json::Value::String(policy.to_string()),
            );
        }

        let mut body = serde_json::json!({ "name": "p", "version": "0.0.0" });
        if !lpm.is_empty() {
            body["lpm"] = serde_json::Value::Object(lpm);
        }
        write_file(
            &project.join("package.json"),
            &serde_json::to_string(&body).unwrap(),
        );
    }

    fn write_package_json_with_min_age(project: &Path, secs: Option<u64>) {
        write_package_json_with_min_age_and_excludes(project, secs, &[]);
    }

    fn write_package_json_with_excludes(project: &Path, excludes: &[&str]) {
        write_package_json_with_min_age_and_excludes(project, None, excludes);
    }

    fn write_global_config(home: &Path, contents: &str) {
        write_file(&home.join(".lpm").join("config.toml"), contents);
    }

    fn write_authorized_min_age(secs: u64) {
        write_authorized_min_age_with_excludes(secs, &[]);
    }

    fn write_authorized_min_age_with_excludes(secs: u64, excludes: &[&str]) {
        let posture = crate::security_approval::AuthorizedPosture {
            minimum_release_age_secs: secs,
            minimum_release_age_exclude: excludes
                .iter()
                .map(|exclude| (*exclude).to_string())
                .collect(),
            ..crate::security_approval::AuthorizedPosture::default()
        };
        crate::security_approval::persist_authorized_posture(&posture).unwrap();
    }

    fn write_authorized_release_age_policy(policy: ReleaseAgePolicy) {
        let posture = crate::security_approval::AuthorizedPosture {
            minimum_release_age_secs: 0,
            release_age_policy: policy.as_str().to_string(),
            ..crate::security_approval::AuthorizedPosture::default()
        };
        crate::security_approval::persist_authorized_posture(&posture).unwrap();
    }

    #[test]
    fn resolve_cli_override_wins_over_everything() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), Some(1000));
        write_global_config(home.path(), "minimum-release-age-secs = 2000\n");

        let result = ReleaseAgeResolver::resolve(project.path(), Some(500), true).unwrap();
        assert_eq!(result, 500, "CLI override must beat package.json + global");
    }

    #[test]
    fn resolve_cli_override_zero_is_honored() {
        // `--min-release-age=0` disables cooldown for this invocation,
        // even when package.json / global set a non-zero value.
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), Some(1000));
        write_global_config(home.path(), "minimum-release-age-secs = 2000\n");

        let result = ReleaseAgeResolver::resolve(project.path(), Some(0), true).unwrap();
        assert_eq!(result, 0, "CLI --min-release-age=0 must force zero");
    }

    #[test]
    fn resolve_package_json_beats_global() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), Some(1000));
        write_global_config(home.path(), "minimum-release-age-secs = 2000\n");

        let result = ReleaseAgeResolver::resolve(project.path(), None, true).unwrap();
        assert_eq!(result, 1000, "package.json must beat global config");
    }

    #[test]
    fn resolve_global_beats_default_when_package_json_silent() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), None);
        write_global_config(home.path(), "minimum-release-age-secs = 2000\n");

        let result = ReleaseAgeResolver::resolve(project.path(), None, true).unwrap();
        assert_eq!(result, 2000, "global config must override 24h default");
    }

    #[test]
    fn resolve_global_config_reads_lpm_home_when_set() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let lpm_home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("HOME", home.path().as_os_str().to_owned()),
            ("LPM_HOME", lpm_home.path().as_os_str().to_owned()),
            (
                "LPM_TEST_SECURITY_SECRET_HEX",
                std::ffi::OsString::from(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
            ),
        ]);
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), None);
        write_file(
            &lpm_home.path().join("config.toml"),
            "minimum-release-age-secs = 2000\n",
        );

        let result = ReleaseAgeResolver::resolve(project.path(), None, true).unwrap();

        assert_eq!(
            result, 2000,
            "global release-age config must be read from LPM_HOME/config.toml when LPM_HOME is set",
        );
    }

    #[test]
    fn resolve_default_when_nothing_set() {
        let project = tempfile::tempdir().unwrap();
        let _home = scoped_home_dir();
        write_package_json_with_min_age(project.path(), None);

        let result = ReleaseAgeResolver::resolve(project.path(), None, true).unwrap();
        assert_eq!(result, DEFAULT_MIN_RELEASE_AGE_SECS);
    }

    #[test]
    fn resolve_default_when_package_json_missing() {
        let project = tempfile::tempdir().unwrap();
        let _home = scoped_home_dir();
        // No package.json written.
        let result = ReleaseAgeResolver::resolve(project.path(), None, true).unwrap();
        assert_eq!(result, DEFAULT_MIN_RELEASE_AGE_SECS);
    }

    #[test]
    fn resolve_default_when_package_json_malformed() {
        // Tolerant: malformed manifest doesn't error, falls through.
        let project = tempfile::tempdir().unwrap();
        let _home = scoped_home_dir();
        write_file(&project.path().join("package.json"), "{ not json ===");
        let result = ReleaseAgeResolver::resolve(project.path(), None, true).unwrap();
        assert_eq!(result, DEFAULT_MIN_RELEASE_AGE_SECS);
    }

    #[test]
    fn resolve_config_includes_package_json_excludes_with_default_release_age() {
        let project = tempfile::tempdir().unwrap();
        let _home = scoped_home_dir();
        write_package_json_with_excludes(project.path(), &["react", "@scope/pkg"]);

        let result = ReleaseAgeResolver::resolve_config(project.path(), None, &[], true).unwrap();

        assert_eq!(
            result.minimum_release_age_secs,
            DEFAULT_MIN_RELEASE_AGE_SECS
        );
        assert_eq!(
            result.minimum_release_age_exclude,
            vec!["react".to_string(), "@scope/pkg".to_string()]
        );
    }

    #[test]
    fn resolve_config_uses_global_release_age_policy_when_project_is_silent() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), None);
        write_global_config(home.path(), r#"release-age-policy = "strict""#);

        let result = ReleaseAgeResolver::resolve_config(project.path(), None, &[], true).unwrap();

        assert_eq!(result.minimum_release_age_policy, ReleaseAgePolicy::Strict);
    }

    #[test]
    fn resolve_config_package_release_age_policy_beats_global_policy() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age_and_policy(project.path(), None, Some("direct"));
        write_global_config(home.path(), r#"release-age-policy = "strict""#);

        let result = ReleaseAgeResolver::resolve_config(project.path(), None, &[], true).unwrap();

        assert_eq!(result.minimum_release_age_policy, ReleaseAgePolicy::Direct);
    }

    #[test]
    fn resolve_config_project_release_age_policy_direct_requires_unlock_after_approved_strict() {
        let project = tempfile::tempdir().unwrap();
        let _home = scoped_home_dir();
        write_authorized_release_age_policy(ReleaseAgePolicy::Strict);
        write_package_json_with_min_age_and_policy(project.path(), None, Some("direct"));

        let err = ReleaseAgeResolver::resolve_config(project.path(), None, &[], true)
            .unwrap_err()
            .to_string();

        assert!(err.contains("cooldown-window"), "got: {err}");
    }

    #[test]
    fn resolve_config_force_floor_suppresses_project_release_age_policy_direct() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age_and_policy(project.path(), None, Some("direct"));
        write_global_config(
            home.path(),
            "force-security-floor = true\nrelease-age-policy = \"strict\"\n",
        );
        crate::security_floor::clear_recorded_suppressions_for_tests();

        let result = ReleaseAgeResolver::resolve_config(project.path(), None, &[], true).unwrap();

        assert_eq!(result.minimum_release_age_policy, ReleaseAgePolicy::Strict);
        let suppressions = crate::security_floor::recorded_suppressions();
        assert_eq!(suppressions.len(), 1);
        assert_eq!(
            suppressions[0].source,
            crate::security_floor::SuppressionSource::Project
        );
        assert_eq!(
            suppressions[0].control,
            crate::security_floor::GuardedControl::CooldownWindow
        );
        crate::security_floor::clear_recorded_suppressions_for_tests();
    }

    #[test]
    fn resolve_config_rejects_invalid_package_release_age_policy() {
        let project = tempfile::tempdir().unwrap();
        let _home = scoped_home_dir();
        write_package_json_with_min_age_and_policy(project.path(), None, Some("transitive"));

        let err = ReleaseAgeResolver::resolve_config(project.path(), None, &[], true)
            .unwrap_err()
            .to_string();

        assert!(err.contains("minimumReleaseAgePolicy"), "got: {err}");
        assert!(err.contains("direct | strict"), "got: {err}");
    }

    #[test]
    fn resolve_config_merges_cli_project_and_global_excludes_when_global_sets_age() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age_with_excludes(0, &["global-pkg", "shared-pkg"]);
        write_package_json_with_excludes(project.path(), &["project-pkg", "shared-pkg"]);
        write_global_config(
            home.path(),
            r#"minimum-release-age-secs = 2000
minimum-release-age-exclude = ["global-pkg", "shared-pkg"]
"#,
        );
        let cli_excludes = vec!["cli-pkg".to_string()];

        let result =
            ReleaseAgeResolver::resolve_config(project.path(), None, &cli_excludes, true).unwrap();

        assert_eq!(result.minimum_release_age_secs, 2000);
        assert_eq!(
            result.minimum_release_age_exclude,
            vec![
                "cli-pkg".to_string(),
                "project-pkg".to_string(),
                "shared-pkg".to_string(),
                "global-pkg".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_config_merges_global_excludes_when_cli_override_sets_age() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age_with_excludes(0, &["global-pkg"]);
        write_package_json_with_excludes(project.path(), &["project-pkg"]);
        write_global_config(
            home.path(),
            r#"minimum-release-age-secs = 2000
minimum-release-age-exclude = ["global-pkg"]
"#,
        );
        let cli_excludes = vec!["cli-pkg".to_string()];

        let result =
            ReleaseAgeResolver::resolve_config(project.path(), Some(500), &cli_excludes, true)
                .unwrap();

        assert_eq!(result.minimum_release_age_secs, 500);
        assert_eq!(
            result.minimum_release_age_exclude,
            vec![
                "cli-pkg".to_string(),
                "project-pkg".to_string(),
                "global-pkg".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_config_merges_global_excludes_when_package_json_sets_age() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age_with_excludes(0, &["global-pkg"]);
        write_package_json_with_min_age_and_excludes(project.path(), Some(1000), &["project-pkg"]);
        write_global_config(
            home.path(),
            r#"minimum-release-age-secs = 2000
minimum-release-age-exclude = ["global-pkg"]
"#,
        );

        let result = ReleaseAgeResolver::resolve_config(project.path(), None, &[], true).unwrap();

        assert_eq!(result.minimum_release_age_secs, 1000);
        assert_eq!(
            result.minimum_release_age_exclude,
            vec!["project-pkg".to_string(), "global-pkg".to_string()]
        );
    }

    #[test]
    fn hand_edited_global_exclusion_requires_a_project_unlock() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), None);
        write_global_config(
            home.path(),
            r#"minimum-release-age-secs = 2000
minimum-release-age-exclude = ["global-pkg"]
"#,
        );

        let error =
            ReleaseAgeResolver::resolve_config(project.path(), None, &[], true).unwrap_err();

        assert_eq!(error.error_code(), "security_approval_required");
        assert!(
            error.to_string().contains("cooldown-bypass"),
            "got: {error}"
        );
    }

    #[test]
    fn resolve_surfaces_global_config_error() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_package_json_with_min_age(project.path(), None);
        write_global_config(home.path(), r#"minimum-release-age-secs = "garbage""#);

        let err = ReleaseAgeResolver::resolve(project.path(), None, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config.toml"), "must name global file: {err}");
        assert!(
            err.contains("minimum-release-age-secs"),
            "must name key: {err}"
        );
    }

    #[test]
    fn resolve_cli_override_skips_global_errors() {
        // When the user explicitly passes --min-release-age=<n>, a
        // broken global config must not block the install. The CLI
        // flag short-circuits the chain.
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), None);
        write_global_config(home.path(), "not valid toml === [[[");

        let result = ReleaseAgeResolver::resolve(project.path(), Some(0), true).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn resolve_package_json_skips_global_errors() {
        // Similarly, an explicit `"lpm": { "minimumReleaseAge": N }`
        // in package.json short-circuits the global layer.
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), Some(500));
        write_global_config(home.path(), "not valid toml === [[[");

        let result = ReleaseAgeResolver::resolve(project.path(), None, true).unwrap();
        assert_eq!(result, 500);
    }

    #[test]
    fn resolve_force_floor_suppresses_lower_cli_override() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), Some(1000));
        write_global_config(
            home.path(),
            "force-security-floor = true\nminimum-release-age-secs = \"259200\"\n",
        );
        crate::security_floor::clear_recorded_suppressions_for_tests();

        let result = ReleaseAgeResolver::resolve(project.path(), Some(0), true).unwrap();

        assert_eq!(result, 259200);
        let suppressions = crate::security_floor::recorded_suppressions();
        assert_eq!(suppressions.len(), 1);
        assert_eq!(
            suppressions[0].control,
            crate::security_floor::GuardedControl::CooldownWindow
        );
        crate::security_floor::clear_recorded_suppressions_for_tests();
    }

    #[test]
    fn resolve_force_floor_suppresses_lower_project_value() {
        let project = tempfile::tempdir().unwrap();
        let home = scoped_home_dir();
        write_authorized_min_age(0);
        write_package_json_with_min_age(project.path(), Some(1000));
        write_global_config(
            home.path(),
            "force-security-floor = true\nminimum-release-age-secs = \"259200\"\n",
        );
        crate::security_floor::clear_recorded_suppressions_for_tests();

        let result = ReleaseAgeResolver::resolve(project.path(), None, true).unwrap();

        assert_eq!(result, 259200);
        let suppressions = crate::security_floor::recorded_suppressions();
        assert_eq!(suppressions.len(), 1);
        assert_eq!(
            suppressions[0].source,
            crate::security_floor::SuppressionSource::Project
        );
        crate::security_floor::clear_recorded_suppressions_for_tests();
    }

    // ── GlobalConfig::get_u64 (spot-check in this module) ────────

    /// Minimal sanity check for the new `GlobalConfig::get_u64` helper.
    /// The deep coverage for the global-TOML layer lives in the path-
    /// aware tests above; this confirms the convenience accessor works
    /// for callers that don't need file-pathed errors.
    #[test]
    fn global_config_get_u64_accepts_integer_and_string() {
        let home = scoped_home_dir();
        write_global_config(
            home.path(),
            "native-int = 123\nstring-form = \"456\"\nnegative = -1\nboolean = true\n",
        );
        let cfg = crate::commands::config::GlobalConfig::load();
        assert_eq!(cfg.get_u64("native-int"), Some(123));
        assert_eq!(cfg.get_u64("string-form"), Some(456));
        assert_eq!(cfg.get_u64("negative"), None);
        assert_eq!(cfg.get_u64("boolean"), None);
        assert_eq!(cfg.get_u64("absent"), None);
    }

    /// The convenience reader must reject sign-prefixed strings too,
    /// not just the path-aware loader.
    /// Without this, a user who runs
    /// `lpm config set some-key +5` would have `GlobalConfig::get_u64`
    /// silently return `Some(5)` while `--some-flag=+5` would be
    /// rejected by any CLI parser routed through
    /// [`parse_strict_u64_string`].
    #[test]
    fn global_config_get_u64_rejects_sign_prefixed_strings() {
        let home = scoped_home_dir();
        write_global_config(
            home.path(),
            "plus-prefixed = \"+5\"\nminus-prefixed = \"-5\"\n",
        );
        let cfg = crate::commands::config::GlobalConfig::load();
        assert_eq!(cfg.get_u64("plus-prefixed"), None);
        assert_eq!(cfg.get_u64("minus-prefixed"), None);
    }

    // ── parse_strict_u64_string (shared helper) ──────────────────

    #[test]
    fn strict_u64_accepts_plain_digits() {
        assert_eq!(parse_strict_u64_string("0"), Some(0));
        assert_eq!(parse_strict_u64_string("86400"), Some(86400));
    }

    #[test]
    fn strict_u64_rejects_plus_prefix() {
        assert_eq!(parse_strict_u64_string("+5"), None);
    }

    #[test]
    fn strict_u64_rejects_minus_prefix() {
        assert_eq!(parse_strict_u64_string("-5"), None);
    }

    #[test]
    fn strict_u64_rejects_whitespace() {
        assert_eq!(parse_strict_u64_string(" 5"), None);
        assert_eq!(parse_strict_u64_string("5 "), None);
    }

    #[test]
    fn strict_u64_rejects_non_digit() {
        assert_eq!(parse_strict_u64_string("abc"), None);
        assert_eq!(parse_strict_u64_string("0x10"), None);
    }
}
