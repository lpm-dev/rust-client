use std::path::{Component, Path, PathBuf};

use crate::provider::is_valid_dep_name;
use crate::ranges::NpmRange;
use crate::{NpmVersion, Specifier};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerProviderSource {
    Registry,
    File(String),
    Link(String),
    Tarball {
        url: String,
        integrity: Option<String>,
    },
    Git {
        url: String,
        refspec: Option<String>,
    },
}

impl PeerProviderSource {
    pub fn from_install_source(source: &str, integrity: Option<&str>) -> Option<Self> {
        Self::from_install_source_with_project(source, integrity, None)
    }

    /// Parse an install source while normalizing local paths into the install
    /// project's coordinate space.
    pub fn from_install_source_at(
        source: &str,
        integrity: Option<&str>,
        install_project_dir: &Path,
    ) -> Option<Self> {
        Self::from_install_source_with_project(source, integrity, Some(install_project_dir))
    }

    fn from_install_source_with_project(
        source: &str,
        integrity: Option<&str>,
        install_project_dir: Option<&Path>,
    ) -> Option<Self> {
        let normalize_local = |path: &str| {
            install_project_dir.map_or_else(
                || normalize_source_path(path),
                |project_dir| project_relative_source_path(path, project_dir, project_dir),
            )
        };
        if source.starts_with("registry+") {
            return Some(Self::Registry);
        }
        if let Some(path) = source.strip_prefix("directory+") {
            return Some(Self::File(normalize_local(path)));
        }
        if let Some(path) = source.strip_prefix("link+") {
            return Some(Self::Link(normalize_local(path)));
        }
        if let Some(value) = source.strip_prefix("tarball+") {
            if let Some(path) = value.strip_prefix("file:") {
                return Some(Self::File(normalize_local(path)));
            }
            return Some(Self::Tarball {
                url: value.to_string(),
                integrity: integrity.map(str::to_string),
            });
        }
        None
    }

    fn scheme(&self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::File(_) => "file",
            Self::Link(_) => "link",
            Self::Tarball { .. } => "url",
            Self::Git { .. } => "git",
        }
    }

    #[inline]
    pub fn matches_provider(&self, provider: &Self) -> bool {
        match (self, provider) {
            (
                Self::Tarball {
                    url: required_url,
                    integrity: required_integrity,
                },
                Self::Tarball {
                    url: provider_url,
                    integrity: provider_integrity,
                },
            ) => {
                required_url == provider_url
                    && required_integrity
                        .as_ref()
                        .is_none_or(|required| provider_integrity.as_ref() == Some(required))
            }
            _ => self == provider,
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
    pub fn matches(&self, version: Option<&NpmVersion>, source: &PeerProviderSource) -> bool {
        match self {
            Self::Version(range) => version.is_some_and(|version| range.satisfies(version)),
            Self::Source(required) => required.matches_provider(source),
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

    /// Parse a peer declared in a nested package while comparing local
    /// source paths in the install project's coordinate space.
    pub fn new_rebased(
        peer_name: &str,
        raw: impl Into<String>,
        declaring_dir: &Path,
        install_project_dir: &Path,
    ) -> Self {
        let raw = raw.into();
        let parsed = PeerSpecifier::parse(peer_name, &raw).map(|mut specifier| {
            specifier.rebase_local_source(declaring_dir, install_project_dir);
            specifier
        });
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
            Ok(Specifier::Tarball { url, integrity }) => Ok(Self::source(
                peer_name,
                raw,
                PeerProviderSource::Tarball { url, integrity },
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

    fn rebase_local_source(&mut self, declaring_dir: &Path, install_project_dir: &Path) {
        let path = match &mut self.constraint {
            PeerConstraint::Source(PeerProviderSource::File(path))
            | PeerConstraint::Source(PeerProviderSource::Link(path)) => path,
            _ => return,
        };
        *path = project_relative_source_path(path, declaring_dir, install_project_dir);
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
            .matches(Some(version), &PeerProviderSource::Registry)
    }

    #[inline]
    pub fn matches_provider(
        &self,
        version: Option<&NpmVersion>,
        source: &PeerProviderSource,
    ) -> bool {
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
    lexical_normalize(Path::new(raw))
        .to_string_lossy()
        .into_owned()
}

fn project_relative_source_path(
    raw: &str,
    declaring_dir: &Path,
    install_project_dir: &Path,
) -> String {
    let declaring_dir = declaring_dir
        .canonicalize()
        .unwrap_or_else(|_| lexical_normalize(declaring_dir));
    let install_project_dir = install_project_dir
        .canonicalize()
        .unwrap_or_else(|_| lexical_normalize(install_project_dir));
    let source_path = Path::new(raw);
    let absolute = if source_path.is_absolute() {
        source_path.to_path_buf()
    } else {
        declaring_dir.join(source_path)
    };
    let absolute = absolute
        .canonicalize()
        .unwrap_or_else(|_| lexical_normalize(&absolute));
    let rebased = pathdiff::diff_paths(&absolute, &install_project_dir).unwrap_or(absolute);
    normalize_source_path(&rebased.to_string_lossy())
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::with_capacity(path.as_os_str().len());
    for component in path.components() {
        match component {
            Component::ParentDir => match normalized.components().next_back() {
                Some(Component::Normal(_)) => {
                    normalized.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                _ => normalized.push(component.as_os_str()),
            },
            Component::CurDir => {}
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
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
                PeerProviderSource::Tarball {
                    url: "https://example.com/react.tgz".to_string(),
                    integrity: None,
                },
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
    fn nested_source_specs_rebase_into_install_project_coordinates() {
        let project = Path::new("/repo");
        let declaring_dir = Path::new("/repo/packages/consumer");
        for (raw, expected) in [
            (
                "file:../react",
                PeerProviderSource::File("packages/react".to_string()),
            ),
            (
                "link:../react",
                PeerProviderSource::Link("packages/react".to_string()),
            ),
        ] {
            let dependency = PeerDependencySpec::new_rebased("react", raw, declaring_dir, project);
            let specifier = dependency.parsed().expect("rebased source must parse");
            assert!(
                matches!(specifier.constraint(), PeerConstraint::Source(source) if source == &expected),
                "{raw} must be compared relative to the install project"
            );
            assert_eq!(
                dependency.raw(),
                raw,
                "diagnostics must retain manifest text"
            );
        }
    }

    #[test]
    fn install_source_paths_use_the_same_project_relative_identity() {
        let project = tempfile::tempdir().unwrap();
        let react = project.path().join("packages/react");
        std::fs::create_dir_all(&react).unwrap();
        let expected =
            PeerProviderSource::File(Path::new("packages/react").to_string_lossy().into_owned());
        let absolute_source = format!("directory+{}", react.display());

        for source in [
            "directory+./packages/consumer/../react",
            absolute_source.as_str(),
        ] {
            assert_eq!(
                PeerProviderSource::from_install_source_at(source, None, project.path()),
                Some(expected.clone()),
                "{source}"
            );
        }
    }

    #[test]
    fn tarball_source_identity_distinguishes_declared_integrity() {
        let first = PeerSpecifier::parse("react", "https://example.com/react.tgz#sha512-AAAAAAAA")
            .expect("first integrity-pinned URL must parse");
        let second = PeerSpecifier::parse("react", "https://example.com/react.tgz#sha512-BBBBBBBB")
            .expect("second integrity-pinned URL must parse");

        let PeerConstraint::Source(first_source) = first.constraint() else {
            panic!("first URL must be a source constraint");
        };
        let PeerConstraint::Source(second_source) = second.constraint() else {
            panic!("second URL must be a source constraint");
        };
        assert_ne!(
            first_source, second_source,
            "the same URL with different declared SRI must identify different peer content"
        );
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
