//! The lpm.dev package, or the one version of it, that `lpm unpublish`,
//! `lpm deprecate` and `lpm undeprecate` change.

use lpm_common::{LpmError, PackageName, sanitize_terminal_inline};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReleaseTarget {
    pub(crate) package: PackageName,
    /// One exact version, normalized as npm does (`v1.2.3` is `1.2.3`), or
    /// none for every version of the package.
    pub(crate) version: Option<String>,
}

impl ReleaseTarget {
    /// Parses `@lpm.dev/owner.name` or `owner.name`, with an optional
    /// `@<version>`. Ranges and dist-tags are refused: the registry changes
    /// one version or all of them, and a range resolved here could match a
    /// version published since the user last looked.
    pub(crate) fn parse(input: &str, command: &str) -> Result<Self, LpmError> {
        let (name, version) = match input.rfind('@') {
            Some(at) if at > 0 => (&input[..at], Some(&input[at + 1..])),
            _ => (input, None),
        };
        let package = PackageName::parse(name)?;
        let version = version
            .map(|raw| {
                lpm_semver::Version::parse(raw)
                    .map(|version| version.to_string())
                    .map_err(|_| {
                        LpmError::InvalidVersion(format!(
                            "{command} takes one exact version, such as {package}@1.2.3, not `{}`; ranges and dist-tags aren't supported",
                            sanitize_terminal_inline(raw)
                        ))
                    })
            })
            .transpose()?;
        Ok(Self { package, version })
    }

    /// The JSON `version` of a change: the version, or `all`, as the
    /// registry reports it.
    pub(crate) fn version_or_all(&self) -> &str {
        self.version.as_deref().unwrap_or("all")
    }
}

impl fmt::Display for ReleaseTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(version) => write!(f, "{}@{version}", self.package),
            None => write!(f, "{}", self.package),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMAND: &str = "lpm deprecate";

    fn parse(input: &str) -> Result<ReleaseTarget, LpmError> {
        ReleaseTarget::parse(input, COMMAND)
    }

    #[test]
    fn reads_a_scoped_or_short_name_with_or_without_a_version() {
        for (input, version) in [
            ("@lpm.dev/acme.kit", None),
            ("acme.kit", None),
            ("@lpm.dev/acme.kit@1.2.3", Some("1.2.3")),
            ("acme.kit@1.2.3-beta.1", Some("1.2.3-beta.1")),
        ] {
            let target = parse(input).unwrap();
            assert_eq!(target.package.scoped(), "@lpm.dev/acme.kit", "{input}");
            assert_eq!(target.version.as_deref(), version, "{input}");
        }
    }

    #[test]
    fn normalizes_the_version_as_npm_does() {
        assert_eq!(
            parse("@lpm.dev/acme.kit@v1.2.3")
                .unwrap()
                .version
                .as_deref(),
            Some("1.2.3")
        );
    }

    #[test]
    fn names_every_version_by_its_package_and_one_with_its_version() {
        assert_eq!(parse("acme.kit").unwrap().to_string(), "@lpm.dev/acme.kit");
        assert_eq!(
            parse("acme.kit@1.0.0").unwrap().to_string(),
            "@lpm.dev/acme.kit@1.0.0"
        );
        assert_eq!(parse("acme.kit").unwrap().version_or_all(), "all");
    }

    #[test]
    fn refuses_ranges_dist_tags_and_an_empty_version() {
        for input in [
            "@lpm.dev/acme.kit@^1.2.0",
            "@lpm.dev/acme.kit@1.2",
            "@lpm.dev/acme.kit@latest",
            "@lpm.dev/acme.kit@*",
            "@lpm.dev/acme.kit@",
        ] {
            let error = parse(input).unwrap_err();
            assert_eq!(error.error_code(), "invalid_version", "{input}");
            assert!(
                error.to_string().contains("one exact version"),
                "{input}: {error}"
            );
        }
    }

    #[test]
    fn refuses_a_package_that_isnt_on_lpm_dev() {
        for input in ["@types/node@20.0.0", "react@19.0.0", "react"] {
            assert_eq!(
                parse(input).unwrap_err().error_code(),
                "invalid_package_name",
                "{input}"
            );
        }
    }

    #[test]
    fn keeps_control_characters_out_of_the_error() {
        let error = parse("acme.kit@1.0\u{1b}[31m").unwrap_err();
        assert!(!error.to_string().contains('\u{1b}'), "{error}");
    }
}
