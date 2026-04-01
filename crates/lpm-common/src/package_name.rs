use crate::error::LpmError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A parsed LPM package name.
///
/// LPM format: `@lpm.dev/owner.package-name`
/// - Owner: the user or org that published the package
/// - Name: the package name (lowercase, hyphens allowed)
///
/// The full scoped name is `@lpm.dev/owner.package-name`.
/// This is what appears in package.json dependencies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageName {
    /// The owner (user or org slug). e.g., "tolgaergin"
    pub owner: String,
    /// The package name. e.g., "my-utils"
    pub name: String,
}

impl PackageName {
    /// Parse a full scoped name like `@lpm.dev/owner.package-name`.
    ///
    /// Also accepts the short form `owner.package-name` (without scope prefix).
    pub fn parse(input: &str) -> Result<Self, LpmError> {
        let name_part = if let Some(stripped) = input.strip_prefix("@lpm.dev/") {
            stripped
        } else if input.starts_with('@') {
            // This is some other scope like @types/node — not an LPM package
            return Err(LpmError::InvalidPackageName(format!(
                "{input} is not an LPM package (must start with @lpm.dev/)"
            )));
        } else {
            // Allow short form: owner.package-name
            input
        };

        // Strip version suffix if present: owner.package@1.0.0
        let name_part = match name_part.rfind('@') {
            Some(at_pos) if at_pos > 0 => &name_part[..at_pos],
            _ => name_part,
        };

        // Strip query params if present: owner.package?key=val
        let name_part = match name_part.find('?') {
            Some(q_pos) => &name_part[..q_pos],
            None => name_part,
        };

        // Split on first dot: owner.package-name
        let dot_pos = name_part.find('.').ok_or_else(|| {
            LpmError::InvalidPackageName(format!(
                "{input} missing dot separator between owner and package name"
            ))
        })?;

        let owner = &name_part[..dot_pos];
        let name = &name_part[dot_pos + 1..];

        if owner.is_empty() {
            return Err(LpmError::InvalidPackageName(format!(
                "{input} has empty owner"
            )));
        }
        if name.is_empty() {
            return Err(LpmError::InvalidPackageName(format!(
                "{input} has empty package name"
            )));
        }

        // Validate owner: alphanumeric and hyphens
        if !owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(LpmError::InvalidPackageName(format!(
                "owner '{owner}' contains invalid characters (only a-z, 0-9, - allowed)"
            )));
        }

        // Validate name: lowercase alphanumeric and hyphens
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(LpmError::InvalidPackageName(format!(
                "package name '{name}' must be lowercase (a-z, 0-9, - only)"
            )));
        }

        Ok(PackageName {
            owner: owner.to_string(),
            name: name.to_string(),
        })
    }

    /// Returns the full scoped name: `@lpm.dev/owner.package-name`
    pub fn scoped(&self) -> String {
        format!("@lpm.dev/{}.{}", self.owner, self.name)
    }

    /// Returns the short form: `owner.package-name`
    pub fn short(&self) -> String {
        format!("{}.{}", self.owner, self.name)
    }

    /// Returns the URL-encoded scoped name for use in API paths.
    /// `@lpm.dev/owner.pkg` → `%40lpm.dev%2Fowner.pkg`
    pub fn url_encoded(&self) -> String {
        let scoped = self.scoped();
        scoped.replace('@', "%40").replace('/', "%2F")
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@lpm.dev/{}.{}", self.owner, self.name)
    }
}

/// Check if a string looks like an LPM package name (starts with @lpm.dev/).
pub fn is_lpm_package(name: &str) -> bool {
    name.starts_with("@lpm.dev/")
}

/// Check if a string looks like an npm scoped package (starts with @ but not @lpm.dev/).
pub fn is_npm_scoped_package(name: &str) -> bool {
    name.starts_with('@') && !name.starts_with("@lpm.dev/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_scoped_name() {
        let pkg = PackageName::parse("@lpm.dev/tolgaergin.my-utils").unwrap();
        assert_eq!(pkg.owner, "tolgaergin");
        assert_eq!(pkg.name, "my-utils");
        assert_eq!(pkg.scoped(), "@lpm.dev/tolgaergin.my-utils");
        assert_eq!(pkg.short(), "tolgaergin.my-utils");
    }

    #[test]
    fn parse_short_form() {
        let pkg = PackageName::parse("tolgaergin.my-utils").unwrap();
        assert_eq!(pkg.owner, "tolgaergin");
        assert_eq!(pkg.name, "my-utils");
    }

    #[test]
    fn parse_with_version_suffix() {
        let pkg = PackageName::parse("@lpm.dev/acme-corp.design-system@2.1.0").unwrap();
        assert_eq!(pkg.owner, "acme-corp");
        assert_eq!(pkg.name, "design-system");
    }

    #[test]
    fn parse_with_query_params() {
        let pkg = PackageName::parse("@lpm.dev/tolgaergin.blocks?component=dialog&styling=panda")
            .unwrap();
        assert_eq!(pkg.owner, "tolgaergin");
        assert_eq!(pkg.name, "blocks");
    }

    #[test]
    fn parse_org_package() {
        let pkg = PackageName::parse("@lpm.dev/acme-corp.design-system").unwrap();
        assert_eq!(pkg.owner, "acme-corp");
        assert_eq!(pkg.name, "design-system");
    }

    #[test]
    fn reject_npm_scoped_package() {
        let result = PackageName::parse("@types/node");
        assert!(result.is_err());
    }

    #[test]
    fn reject_missing_dot() {
        let result = PackageName::parse("@lpm.dev/nodotshere");
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_owner() {
        let result = PackageName::parse("@lpm.dev/.package");
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_name() {
        let result = PackageName::parse("@lpm.dev/owner.");
        assert!(result.is_err());
    }

    #[test]
    fn reject_uppercase_in_name() {
        let result = PackageName::parse("@lpm.dev/owner.MyPackage");
        assert!(result.is_err());
    }

    #[test]
    fn url_encoding() {
        let pkg = PackageName::parse("@lpm.dev/tolgaergin.my-utils").unwrap();
        assert_eq!(pkg.url_encoded(), "%40lpm.dev%2Ftolgaergin.my-utils");
    }

    #[test]
    fn display_format() {
        let pkg = PackageName::parse("tolgaergin.my-utils").unwrap();
        assert_eq!(format!("{pkg}"), "@lpm.dev/tolgaergin.my-utils");
    }

    #[test]
    fn is_lpm_detection() {
        assert!(is_lpm_package("@lpm.dev/owner.pkg"));
        assert!(!is_lpm_package("react"));
        assert!(!is_lpm_package("@types/node"));
    }

    #[test]
    fn is_npm_scoped_detection() {
        assert!(is_npm_scoped_package("@types/node"));
        assert!(!is_npm_scoped_package("@lpm.dev/owner.pkg"));
        assert!(!is_npm_scoped_package("react"));
    }
}
