use std::path::{Component, Path};

use crate::provider::is_valid_dep_name;
use crate::ranges::NpmRange;
use crate::{NpmVersion, Specifier};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerProviderSource {
    Registry,
    File(String),
    Link(String),
    Tarball(String),
    Git {
        url: String,
        refspec: Option<String>,
    },
}

impl PeerProviderSource {
    pub fn from_install_source(source: &str) -> Option<Self> {
        if source.starts_with("registry+") {
            return Some(Self::Registry);
        }
        if let Some(path) = source.strip_prefix("directory+") {
            return Some(Self::File(normalize_source_path(path)));
        }
        if let Some(path) = source.strip_prefix("link+") {
            return Some(Self::Link(normalize_source_path(path)));
        }
        if let Some(value) = source.strip_prefix("tarball+") {
            if let Some(path) = value.strip_prefix("file:") {
                return Some(Self::File(normalize_source_path(path)));
            }
            return Some(Self::Tarball(value.to_string()));
        }
        None
    }

    fn scheme(&self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::File(_) => "file",
            Self::Link(_) => "link",
            Self::Tarball(_) => "url",
            Self::Git { .. } => "git",
        }
    }
}

#[derive(Debug, Clone)]
pub enum PeerConstraint {
    Version(NpmRange),
    Source(PeerProviderSource),
}

impl PeerConstraint {
    #[inline]
    pub fn version_range(&self) -> Option<&NpmRange> {
        match self {
            Self::Version(range) => Some(range),
            Self::Source(_) => None,
        }
    }

    #[inline]
    pub fn matches(&self, version: &NpmVersion, source: &PeerProviderSource) -> bool {
        match self {
            Self::Version(range) => range.satisfies(version),
            Self::Source(required) => required == source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerInstallSource {
    Registry,
    UnsupportedOriginal { scheme: String, specifier: String },
}

impl PeerInstallSource {
    #[inline]
    pub fn is_registry(&self) -> bool {
        matches!(self, Self::Registry)
    }

    pub fn unsupported_details(&self) -> Option<(&str, &str)> {
        match self {
            Self::Registry => None,
            Self::UnsupportedOriginal { scheme, specifier } => Some((scheme, specifier)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerSpecifier {
    raw: String,
    target: String,
    constraint: PeerConstraint,
    install_source: PeerInstallSource,
}

#[derive(Debug, Clone)]
pub struct PeerDependencySpec {
    raw: String,
    parsed: Result<PeerSpecifier, PeerSpecifierError>,
}

impl PeerDependencySpec {
    pub fn new(peer_name: &str, raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let parsed = PeerSpecifier::parse(peer_name, &raw);
        Self { raw, parsed }
    }

    #[inline]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    #[inline]
    pub fn parsed(&self) -> Result<&PeerSpecifier, &PeerSpecifierError> {
        self.parsed.as_ref()
    }
}

impl PeerSpecifier {
    pub fn parse(peer_name: &str, raw: &str) -> Result<Self, PeerSpecifierError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Self::version(peer_name, raw, "*", PeerInstallSource::Registry);
        }

        if NpmRange::parse(raw).is_ok() {
            return Self::version(peer_name, raw, raw, PeerInstallSource::Registry);
        }

        if raw.starts_with("npm:") {
            return parse_npm_alias(peer_name, raw);
        }

        if let Some(body) = raw.strip_prefix("workspace:") {
            let comparable = match body.trim() {
                "" | "*" | "^" | "~" => "*",
                range => range,
            };
            return Self::version(peer_name, raw, comparable, PeerInstallSource::Registry);
        }

        if raw.contains("||") {
            return parse_named_registry_union(peer_name, raw);
        }

        match Specifier::parse(raw) {
            Ok(Specifier::File { path }) => Ok(Self::source(
                peer_name,
                raw,
                PeerProviderSource::File(normalize_source_path(&path)),
            )),
            Ok(Specifier::Link { path }) => Ok(Self::source(
                peer_name,
                raw,
                PeerProviderSource::Link(normalize_source_path(&path)),
            )),
            Ok(Specifier::Tarball { url, .. }) => Ok(Self::source(
                peer_name,
                raw,
                PeerProviderSource::Tarball(url),
            )),
            Ok(Specifier::Git { url, refspec }) => Ok(Self::source(
                peer_name,
                raw,
                PeerProviderSource::Git { url, refspec },
            )),
            Ok(Specifier::SemverRange(_)) => parse_named_registry(peer_name, raw),
            Ok(Specifier::NpmAlias { .. } | Specifier::Workspace(_)) => {
                Err(PeerSpecifierError::Invalid {
                    specifier: raw.to_string(),
                    detail: "unsupported nested peer dependency specifier".to_string(),
                })
            }
            Err(error) => {
                if split_named_registry(raw).is_some() {
                    parse_named_registry(peer_name, raw)
                } else {
                    Err(PeerSpecifierError::Invalid {
                        specifier: raw.to_string(),
                        detail: error.to_string(),
                    })
                }
            }
        }
    }

    fn version(
        target: &str,
        raw: &str,
        range: &str,
        install_source: PeerInstallSource,
    ) -> Result<Self, PeerSpecifierError> {
        let comparable_range =
            NpmRange::parse(range).map_err(|detail| PeerSpecifierError::Invalid {
                specifier: raw.to_string(),
                detail,
            })?;
        Ok(Self {
            raw: raw.to_string(),
            target: target.to_string(),
            constraint: PeerConstraint::Version(comparable_range),
            install_source,
        })
    }

    fn source(target: &str, raw: &str, source: PeerProviderSource) -> Self {
        Self {
            raw: raw.to_string(),
            target: target.to_string(),
            install_source: PeerInstallSource::UnsupportedOriginal {
                scheme: source.scheme().to_string(),
                specifier: raw.to_string(),
            },
            constraint: PeerConstraint::Source(source),
        }
    }

    #[inline]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    #[inline]
    pub fn target(&self) -> &str {
        &self.target
    }

    #[inline]
    pub fn constraint(&self) -> &PeerConstraint {
        &self.constraint
    }

    #[inline]
    pub fn comparable_range(&self) -> Option<&NpmRange> {
        self.constraint.version_range()
    }

    #[inline]
    pub fn matches_registry_version(&self, version: &NpmVersion) -> bool {
        self.constraint
            .matches(version, &PeerProviderSource::Registry)
    }

    #[inline]
    pub fn matches_provider(&self, version: &NpmVersion, source: &PeerProviderSource) -> bool {
        self.constraint.matches(version, source)
    }

    pub fn into_parts(self) -> (String, PeerConstraint, PeerInstallSource) {
        (self.target, self.constraint, self.install_source)
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum PeerSpecifierError {
    #[error("invalid peer dependency specifier {specifier:?}: {detail}")]
    Invalid { specifier: String, detail: String },
    #[error(
        "invalid peer dependency specifier union {specifier:?}: alternatives target both {first:?} and {second:?}"
    )]
    ConflictingTargets {
        specifier: String,
        first: String,
        second: String,
    },
}

fn parse_npm_alias(peer_name: &str, raw: &str) -> Result<PeerSpecifier, PeerSpecifierError> {
    let parts: Vec<&str> = raw.split("||").map(str::trim).collect();
    if parts.len() > 1 && parts.iter().all(|part| part.starts_with("npm:")) {
        let mut target: Option<String> = None;
        let mut ranges = Vec::with_capacity(parts.len());
        for part in parts {
            let alias = crate::ranges::parse_npm_alias(part).ok_or_else(|| {
                PeerSpecifierError::Invalid {
                    specifier: raw.to_string(),
                    detail: "npm alias is missing a target".to_string(),
                }
            })?;
            validate_alias_target(raw, &alias.target)?;
            if let Some(existing) = target.as_ref()
                && existing != &alias.target
            {
                return Err(PeerSpecifierError::ConflictingTargets {
                    specifier: raw.to_string(),
                    first: existing.clone(),
                    second: alias.target,
                });
            }
            target.get_or_insert(alias.target);
            ranges.push(alias.range);
        }
        return PeerSpecifier::version(
            target.as_deref().unwrap_or(peer_name),
            raw,
            &ranges.join(" || "),
            PeerInstallSource::Registry,
        );
    }

    let alias = crate::ranges::parse_npm_alias(raw).ok_or_else(|| PeerSpecifierError::Invalid {
        specifier: raw.to_string(),
        detail: "npm alias is missing a target".to_string(),
    })?;
    validate_alias_target(raw, &alias.target)?;
    PeerSpecifier::version(
        &alias.target,
        raw,
        &alias.range,
        PeerInstallSource::Registry,
    )
}

fn validate_alias_target(raw: &str, target: &str) -> Result<(), PeerSpecifierError> {
    if is_valid_dep_name(target) {
        return Ok(());
    }
    Err(PeerSpecifierError::Invalid {
        specifier: raw.to_string(),
        detail: format!("invalid npm alias target {target:?}"),
    })
}

fn parse_named_registry_union(
    peer_name: &str,
    raw: &str,
) -> Result<PeerSpecifier, PeerSpecifierError> {
    let mut scheme: Option<&str> = None;
    let mut ranges = Vec::new();
    for part in raw.split("||").map(str::trim) {
        let (part_scheme, range) = split_named_registry(part).ok_or_else(|| {
            PeerSpecifierError::Invalid {
                specifier: raw.to_string(),
                detail: "every named-registry union alternative must include a valid registry name and version range".to_string(),
            }
        })?;
        if let Some(existing) = scheme
            && existing != part_scheme
        {
            return Err(PeerSpecifierError::ConflictingTargets {
                specifier: raw.to_string(),
                first: existing.to_string(),
                second: part_scheme.to_string(),
            });
        }
        scheme.get_or_insert(part_scheme);
        NpmRange::parse(range).map_err(|detail| PeerSpecifierError::Invalid {
            specifier: raw.to_string(),
            detail,
        })?;
        ranges.push(range);
    }
    let scheme = scheme.ok_or_else(|| PeerSpecifierError::Invalid {
        specifier: raw.to_string(),
        detail: "empty named-registry union".to_string(),
    })?;
    PeerSpecifier::version(
        peer_name,
        raw,
        &ranges.join(" || "),
        PeerInstallSource::UnsupportedOriginal {
            scheme: scheme.to_string(),
            specifier: raw.to_string(),
        },
    )
}

fn parse_named_registry(peer_name: &str, raw: &str) -> Result<PeerSpecifier, PeerSpecifierError> {
    let (scheme, range) = split_named_registry(raw).ok_or_else(|| PeerSpecifierError::Invalid {
        specifier: raw.to_string(),
        detail: "expected a semver range or a supported source protocol".to_string(),
    })?;
    PeerSpecifier::version(
        peer_name,
        raw,
        range,
        PeerInstallSource::UnsupportedOriginal {
            scheme: scheme.to_string(),
            specifier: raw.to_string(),
        },
    )
}

fn split_named_registry(raw: &str) -> Option<(&str, &str)> {
    let (scheme, range) = raw.split_once(':')?;
    if scheme.is_empty()
        || !scheme.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        || range.is_empty()
        || NpmRange::parse(range).is_err()
    {
        return None;
    }
    Some((scheme, range))
}

fn normalize_source_path(raw: &str) -> String {
    let path = Path::new(raw);
    let mut normalized = std::path::PathBuf::with_capacity(raw.len());
    for component in path.components() {
        if !matches!(component, Component::CurDir) {
            normalized.push(component.as_os_str());
        }
    }
    normalized.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn satisfies(spec: &PeerSpecifier, version: &str) -> bool {
        spec.matches_registry_version(&NpmVersion::parse(version).expect("test version must parse"))
    }

    #[test]
    fn semver_and_workspace_specs_keep_the_peer_name_and_range() {
        for raw in ["^18.0.0", "workspace:^18.0.0"] {
            let spec = PeerSpecifier::parse("react", raw).expect("specifier must parse");
            assert_eq!(spec.target(), "react");
            assert!(spec.install_source.is_registry());
            assert!(satisfies(&spec, "18.3.1"));
            assert!(!satisfies(&spec, "17.0.2"));
        }
    }

    #[test]
    fn npm_alias_uses_the_target_package_and_inner_range() {
        let spec =
            PeerSpecifier::parse("react-compat", "npm:react@^18.0.0").expect("alias must parse");
        assert_eq!(spec.target(), "react");
        assert!(spec.install_source.is_registry());
        assert!(satisfies(&spec, "18.3.1"));
        assert!(!satisfies(&spec, "17.0.2"));
    }

    #[test]
    fn npm_alias_union_keeps_one_target_and_all_range_alternatives() {
        let spec = PeerSpecifier::parse("react-compat", "npm:react@^17 || ^18")
            .expect("alias union must parse");
        assert_eq!(spec.target(), "react");
        assert!(satisfies(&spec, "17.0.2"));
        assert!(satisfies(&spec, "18.3.1"));
        assert!(!satisfies(&spec, "19.0.0"));

        let repeated = PeerSpecifier::parse("react-compat", "npm:react@^17 || npm:react@^18")
            .expect("repeated alias union must parse");
        assert!(satisfies(&repeated, "17.0.2"));
        assert!(satisfies(&repeated, "18.3.1"));
    }

    #[test]
    fn workspace_publish_shorthands_are_presence_constraints() {
        for raw in ["workspace:^", "workspace:~"] {
            let spec = PeerSpecifier::parse("react", raw).expect("workspace shorthand must parse");
            assert!(satisfies(&spec, "0.0.1"), "{raw}");
            assert!(satisfies(&spec, "18.3.1"), "{raw}");
        }
    }

    #[test]
    fn named_registry_spec_uses_its_version_body_for_comparison() {
        let spec =
            PeerSpecifier::parse("react", "work:^18.0.0").expect("named registry spec must parse");
        assert_eq!(spec.target(), "react");
        assert!(!spec.install_source.is_registry());
        assert!(satisfies(&spec, "18.3.1"));
        assert!(!satisfies(&spec, "17.0.2"));
    }

    #[test]
    fn source_specs_preserve_typed_source_identity() {
        let cases = [
            (
                "file:../react",
                PeerProviderSource::File("../react".to_string()),
            ),
            (
                "link:../react",
                PeerProviderSource::Link("../react".to_string()),
            ),
            (
                "https://example.com/react.tgz",
                PeerProviderSource::Tarball("https://example.com/react.tgz".to_string()),
            ),
        ];
        for (raw, expected) in cases {
            let spec = PeerSpecifier::parse("react", raw).expect("source spec must parse");
            assert!(
                matches!(spec.constraint(), PeerConstraint::Source(source) if source == &expected)
            );
            assert!(!spec.install_source.is_registry());
        }
    }

    #[test]
    fn source_specs_do_not_accept_registry_versions_as_equivalent_providers() {
        for raw in [
            "file:../react",
            "link:../react",
            "git+https://example.com/react.git",
            "https://example.com/react.tgz",
        ] {
            let spec = PeerSpecifier::parse("react", raw).expect("source spec must parse");
            assert!(!satisfies(&spec, "18.3.1"), "{raw}");
        }
    }

    #[test]
    fn unknown_and_malformed_protocols_are_rejected() {
        for raw in [
            "magic:whatever",
            "file:",
            "link:",
            "https:example.com/react.tgz",
        ] {
            assert!(
                matches!(
                    PeerSpecifier::parse("react", raw),
                    Err(PeerSpecifierError::Invalid { .. })
                ),
                "{raw}"
            );
        }
    }

    #[test]
    fn scheme_union_reduces_each_alternative_to_its_version_body() {
        let spec =
            PeerSpecifier::parse("react", "work:^17 || work:^18").expect("scheme union must parse");
        assert!(satisfies(&spec, "17.0.2"));
        assert!(satisfies(&spec, "18.3.1"));
        assert!(!satisfies(&spec, "19.0.0"));
    }

    #[test]
    fn bare_package_at_version_is_rejected() {
        assert!(matches!(
            PeerSpecifier::parse("react", "react@18.3.1"),
            Err(PeerSpecifierError::Invalid { .. })
        ));
    }
}
