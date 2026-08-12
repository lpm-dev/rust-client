use super::super::*;
use std::collections::BTreeMap;

const ENV_INSTALLER_SPIKE_PARITY: &str = "LPM_INSTALLER_SPIKE_PARITY";
const PARITY_SAMPLE_LIMIT: usize = 25;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::commands::install) enum ExperimentalResolverParityMode {
    Disabled,
    FreshResolve { deny: bool },
    Lockfile { deny: bool },
}

impl ExperimentalResolverParityMode {
    pub(in crate::commands::install) fn from_env() -> Self {
        Self::from_value(std::env::var(ENV_INSTALLER_SPIKE_PARITY).ok().as_deref())
    }

    pub(in crate::commands::install) fn from_value(value: Option<&str>) -> Self {
        match value {
            Some("1" | "true" | "warn") => Self::FreshResolve { deny: false },
            Some("deny") => Self::FreshResolve { deny: true },
            Some("lock" | "lockfile" | "seed-lock") => Self::Lockfile { deny: false },
            Some("lock-deny" | "lockfile-deny" | "seed-lock-deny") => Self::Lockfile { deny: true },
            Some(_) | None => Self::Disabled,
        }
    }

    pub(in crate::commands::install) fn enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub(in crate::commands::install) fn deny(self) -> bool {
        matches!(
            self,
            Self::FreshResolve { deny: true } | Self::Lockfile { deny: true }
        )
    }

    pub(in crate::commands::install) fn baseline(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FreshResolve { .. } => "fresh-greedy",
            Self::Lockfile { .. } => "lockfile",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(in crate::commands::install) struct PackageFingerprint {
    pub(in crate::commands::install) dependencies: Vec<(String, String)>,
    pub(in crate::commands::install) aliases: Vec<(String, String)>,
    pub(in crate::commands::install) peers: Vec<lpm_common::PeerEdge>,
    pub(in crate::commands::install) root_link_names: Vec<String>,
    pub(in crate::commands::install) is_direct: bool,
    pub(in crate::commands::install) optional: bool,
}

#[derive(Debug, Clone)]
pub(in crate::commands::install) struct PackageFingerprintMismatch {
    pub(in crate::commands::install) package: String,
    pub(in crate::commands::install) candidate: PackageFingerprint,
    pub(in crate::commands::install) baseline: PackageFingerprint,
}

#[derive(Debug, Clone)]
pub(in crate::commands::install) struct ExperimentalResolverParity {
    pub(in crate::commands::install) enabled: bool,
    pub(in crate::commands::install) matches: bool,
    pub(in crate::commands::install) baseline: &'static str,
    pub(in crate::commands::install) candidate_count: usize,
    pub(in crate::commands::install) baseline_count: usize,
    pub(in crate::commands::install) count_delta: isize,
    pub(in crate::commands::install) extra_count: usize,
    pub(in crate::commands::install) missing_count: usize,
    pub(in crate::commands::install) fingerprint_mismatch_count: usize,
    pub(in crate::commands::install) extra: Vec<String>,
    pub(in crate::commands::install) missing: Vec<String>,
    pub(in crate::commands::install) fingerprint_mismatches: Vec<PackageFingerprintMismatch>,
}

impl ExperimentalResolverParity {
    pub(in crate::commands::install) fn disabled() -> Self {
        Self {
            enabled: false,
            matches: true,
            baseline: "disabled",
            candidate_count: 0,
            baseline_count: 0,
            count_delta: 0,
            extra_count: 0,
            missing_count: 0,
            fingerprint_mismatch_count: 0,
            extra: Vec::new(),
            missing: Vec::new(),
            fingerprint_mismatches: Vec::new(),
        }
    }

    pub(in crate::commands::install) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "matches": self.matches,
            "baseline": self.baseline,
            "candidate_count": self.candidate_count,
            "baseline_count": self.baseline_count,
            "count_delta": self.count_delta,
            "extra_count": self.extra_count,
            "missing_count": self.missing_count,
            "fingerprint_mismatch_count": self.fingerprint_mismatch_count,
            "extra": &self.extra,
            "missing": &self.missing,
            "fingerprint_mismatches": self.fingerprint_mismatches.iter().map(|mismatch| {
                serde_json::json!({
                    "package": &mismatch.package,
                    "candidate": package_fingerprint_json(&mismatch.candidate),
                    "baseline": package_fingerprint_json(&mismatch.baseline),
                })
            }).collect::<Vec<_>>(),
        })
    }
}

pub(in crate::commands::install) fn compare_package_parity_with_baseline(
    candidate_packages: &[InstallPackage],
    baseline_packages: &[InstallPackage],
    baseline_name: &'static str,
) -> ExperimentalResolverParity {
    let candidate = package_parity_index(candidate_packages);
    let baseline = package_parity_index(baseline_packages);

    let mut extra = Vec::new();
    for (key, (display, _)) in &candidate {
        if !baseline.contains_key(key) {
            extra.push(display.clone());
        }
    }

    let mut missing = Vec::new();
    for (key, (display, _)) in &baseline {
        if !candidate.contains_key(key) {
            missing.push(display.clone());
        }
    }

    let mut fingerprint_mismatches = Vec::new();
    for (key, (display, candidate_fp)) in &candidate {
        let Some((_, baseline_fp)) = baseline.get(key) else {
            continue;
        };
        if candidate_fp != baseline_fp {
            fingerprint_mismatches.push(PackageFingerprintMismatch {
                package: display.clone(),
                candidate: candidate_fp.clone(),
                baseline: baseline_fp.clone(),
            });
        }
    }

    let extra_count = extra.len();
    let missing_count = missing.len();
    let fingerprint_mismatch_count = fingerprint_mismatches.len();
    extra.truncate(PARITY_SAMPLE_LIMIT);
    missing.truncate(PARITY_SAMPLE_LIMIT);
    fingerprint_mismatches.truncate(PARITY_SAMPLE_LIMIT);
    let matches = extra_count == 0 && missing_count == 0 && fingerprint_mismatch_count == 0;

    ExperimentalResolverParity {
        enabled: true,
        matches,
        baseline: baseline_name,
        candidate_count: candidate_packages.len(),
        baseline_count: baseline_packages.len(),
        count_delta: candidate_packages.len() as isize - baseline_packages.len() as isize,
        extra_count,
        missing_count,
        fingerprint_mismatch_count,
        extra,
        missing,
        fingerprint_mismatches,
    }
}

fn package_parity_index(
    packages: &[InstallPackage],
) -> BTreeMap<String, (String, PackageFingerprint)> {
    packages
        .iter()
        .map(|package| {
            (
                install_pkg_key(package),
                (
                    format!("{}@{} {}", package.name, package.version, package.source),
                    package_fingerprint(package),
                ),
            )
        })
        .collect()
}

fn package_fingerprint(package: &InstallPackage) -> PackageFingerprint {
    let mut dependencies = package.dependencies.clone();
    dependencies.sort();
    let mut aliases: Vec<_> = package
        .aliases
        .iter()
        .map(|(alias, target)| (alias.clone(), target.clone()))
        .collect();
    aliases.sort();
    let mut peers = package.peers.clone();
    peers.sort();
    let mut root_link_names = package.root_link_names.clone().unwrap_or_default();
    root_link_names.sort();
    PackageFingerprint {
        dependencies,
        aliases,
        peers,
        root_link_names,
        is_direct: package.is_direct,
        optional: package.optional,
    }
}

fn package_fingerprint_json(fingerprint: &PackageFingerprint) -> serde_json::Value {
    serde_json::json!({
        "dependencies": &fingerprint.dependencies,
        "aliases": &fingerprint.aliases,
        "peers": &fingerprint.peers,
        "root_link_names": &fingerprint.root_link_names,
        "direct": fingerprint.is_direct,
        "optional": fingerprint.optional,
    })
}
