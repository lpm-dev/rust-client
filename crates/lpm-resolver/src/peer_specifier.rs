use crate::provider::is_valid_dep_name;
use crate::ranges::NpmRange;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerInstallSource {
    Registry,
    UnsupportedOriginal { scheme: String, specifier: String },
}

impl PeerInstallSource {
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
    comparable_range: NpmRange,
    install_source: PeerInstallSource,
}

impl PeerSpecifier {
    pub fn parse(peer_name: &str, raw: &str) -> Result<Self, PeerSpecifierError> {
        let raw = raw.trim();
        if raw.is_empty() {
            let comparable_range =
                NpmRange::parse("*").map_err(|detail| PeerSpecifierError::Invalid {
                    specifier: String::new(),
                    detail,
                })?;
            return Ok(Self {
                raw: String::new(),
                target: peer_name.to_string(),
                comparable_range,
                install_source: PeerInstallSource::Registry,
            });
        }

        let mut target: Option<String> = None;
        let mut comparable_parts = Vec::new();
        let mut unsupported_source: Option<(String, String)> = None;

        for raw_part in raw.split("||") {
            let part = raw_part.trim();
            if part.is_empty() {
                return Err(PeerSpecifierError::Invalid {
                    specifier: raw.to_string(),
                    detail: "empty alternative in `||` union".to_string(),
                });
            }
            let parsed = parse_part(peer_name, part)?;
            if let Some(existing) = target.as_ref()
                && existing != &parsed.target
            {
                return Err(PeerSpecifierError::ConflictingTargets {
                    specifier: raw.to_string(),
                    first: existing.clone(),
                    second: parsed.target,
                });
            }
            target.get_or_insert(parsed.target);
            comparable_parts.push(parsed.comparable);
            if unsupported_source.is_none() {
                unsupported_source = parsed.unsupported_source;
            }
        }

        let comparable = comparable_parts.join(" || ");
        let comparable_range =
            NpmRange::parse(&comparable).map_err(|detail| PeerSpecifierError::Invalid {
                specifier: raw.to_string(),
                detail,
            })?;
        let install_source = unsupported_source.map_or(PeerInstallSource::Registry, |value| {
            PeerInstallSource::UnsupportedOriginal {
                scheme: value.0,
                specifier: value.1,
            }
        });

        Ok(Self {
            raw: raw.to_string(),
            target: target.unwrap_or_else(|| peer_name.to_string()),
            comparable_range,
            install_source,
        })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn comparable_range(&self) -> &NpmRange {
        &self.comparable_range
    }

    pub fn into_parts(self) -> (String, NpmRange, PeerInstallSource) {
        (self.target, self.comparable_range, self.install_source)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
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

struct ParsedPart {
    target: String,
    comparable: String,
    unsupported_source: Option<(String, String)>,
}

fn parse_part(peer_name: &str, part: &str) -> Result<ParsedPart, PeerSpecifierError> {
    if let Some(body) = part.strip_prefix("workspace:") {
        return Ok(ParsedPart {
            target: peer_name.to_string(),
            comparable: range_or_wildcard(body, part)?,
            unsupported_source: None,
        });
    }

    if let Some(body) = part.strip_prefix("npm:") {
        if NpmRange::parse(body).is_ok() {
            return Ok(ParsedPart {
                target: peer_name.to_string(),
                comparable: range_or_wildcard(body, part)?,
                unsupported_source: Some(("npm".to_string(), part.to_string())),
            });
        }
        let alias =
            crate::ranges::parse_npm_alias(part).ok_or_else(|| PeerSpecifierError::Invalid {
                specifier: part.to_string(),
                detail: "npm alias is missing a target".to_string(),
            })?;
        if !is_valid_dep_name(&alias.target) {
            return Err(PeerSpecifierError::Invalid {
                specifier: part.to_string(),
                detail: format!("invalid npm alias target {:?}", alias.target),
            });
        }
        return Ok(ParsedPart {
            target: alias.target,
            comparable: range_or_wildcard(&alias.range, part)?,
            unsupported_source: None,
        });
    }

    if let Some(colon) = part.find(':')
        && colon > 0
    {
        let scheme = &part[..colon];
        let body = &part[colon + 1..];
        let comparable = if NpmRange::parse(body).is_ok() {
            range_or_wildcard(body, part)?
        } else if let Some(at) = body.rfind('@')
            && at > 0
            && NpmRange::parse(&body[at + 1..]).is_ok()
        {
            range_or_wildcard(&body[at + 1..], part)?
        } else {
            "*".to_string()
        };
        return Ok(ParsedPart {
            target: peer_name.to_string(),
            comparable,
            unsupported_source: Some((scheme.to_string(), part.to_string())),
        });
    }

    let comparable = range_or_wildcard(part, part)?;
    Ok(ParsedPart {
        target: peer_name.to_string(),
        comparable,
        unsupported_source: None,
    })
}

fn range_or_wildcard(range: &str, specifier: &str) -> Result<String, PeerSpecifierError> {
    let range = range.trim();
    let range = if range.is_empty() { "*" } else { range };
    NpmRange::parse(range).map_err(|detail| PeerSpecifierError::Invalid {
        specifier: specifier.to_string(),
        detail,
    })?;
    Ok(range.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NpmVersion;

    fn satisfies(spec: &PeerSpecifier, version: &str) -> bool {
        spec.comparable_range()
            .satisfies(&NpmVersion::parse(version).expect("test version must parse"))
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
    fn named_registry_spec_uses_its_version_body_for_comparison() {
        let spec =
            PeerSpecifier::parse("react", "work:^18.0.0").expect("named registry spec must parse");
        assert_eq!(spec.target(), "react");
        assert!(!spec.install_source.is_registry());
        assert!(satisfies(&spec, "18.3.1"));
        assert!(!satisfies(&spec, "17.0.2"));
    }

    #[test]
    fn source_specs_without_versions_compare_as_wildcards() {
        for raw in [
            "file:../react",
            "link:../react",
            "git+https://example.com/react.git",
            "https://example.com/react.tgz",
        ] {
            let spec = PeerSpecifier::parse("react", raw).expect("source spec must parse");
            assert!(satisfies(&spec, "0.0.1"), "{raw}");
            assert!(!spec.install_source.is_registry(), "{raw}");
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
