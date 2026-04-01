//! Workspace constraints engine.
//!
//! Enforce rules across workspace packages — like Yarn's constraints system but
//! configured in package.json `"lpm"` key instead of a separate file.
//!
//! Example config in root package.json:
//! ```json
//! {
//!   "lpm": {
//!     "constraints": {
//!       "enforce": {
//!         "react": "^19.0.0",
//!         "typescript": "^5.0.0"
//!       },
//!       "ban": ["lodash", "moment"],
//!       "requireLicense": ["MIT", "Apache-2.0", "ISC", "BSD-2-Clause", "BSD-3-Clause"]
//!     }
//!   }
//! }
//! ```

use std::collections::HashMap;
use std::path::Path;

/// A constraint violation found during checking.
#[derive(Debug)]
pub struct ConstraintViolation {
    /// The workspace member where the violation was found.
    pub package: String,
    /// What rule was violated.
    pub rule: String,
    /// Details of the violation.
    pub detail: String,
}

/// Constraints configuration.
#[derive(Debug, Default)]
pub struct Constraints {
    /// Enforce specific version ranges for these deps across all workspace members.
    pub enforce: HashMap<String, String>,
    /// Ban these packages — they cannot appear in any workspace member's deps.
    pub ban: Vec<String>,
    /// Require packages to have one of these licenses.
    pub require_license: Vec<String>,
}

impl Constraints {
    /// Parse constraints from root package.json's "lpm.constraints" field.
    pub fn from_package_json(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        let doc: serde_json::Value = serde_json::from_str(&content).ok()?;
        let constraints = doc.get("lpm")?.get("constraints")?;

        let enforce = constraints
            .get("enforce")
            .and_then(|e| e.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let ban = constraints
            .get("ban")
            .and_then(|b| b.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let require_license = constraints
            .get("requireLicense")
            .and_then(|l| l.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Some(Constraints {
            enforce,
            ban,
            require_license,
        })
    }

    /// Check constraints against a package.json's dependencies.
    pub fn check(
        &self,
        package_name: &str,
        deps: &HashMap<String, String>,
        license: Option<&str>,
    ) -> Vec<ConstraintViolation> {
        let mut violations = Vec::new();

        // Check enforced version ranges
        for (dep_name, required_range) in &self.enforce {
            if let Some(actual_range) = deps.get(dep_name)
                && actual_range != required_range
            {
                violations.push(ConstraintViolation {
                    package: package_name.to_string(),
                    rule: "enforce".to_string(),
                    detail: format!(
                        "{dep_name}: expected \"{required_range}\", found \"{actual_range}\""
                    ),
                });
            }
        }

        // Check banned packages
        for banned in &self.ban {
            if deps.contains_key(banned) {
                violations.push(ConstraintViolation {
                    package: package_name.to_string(),
                    rule: "ban".to_string(),
                    detail: format!("{banned} is banned"),
                });
            }
        }

        // Check license
        if !self.require_license.is_empty() {
            if let Some(lic) = license {
                if !self.require_license.contains(&lic.to_string()) {
                    violations.push(ConstraintViolation {
                        package: package_name.to_string(),
                        rule: "requireLicense".to_string(),
                        detail: format!(
                            "license \"{lic}\" not in allowed list: {:?}",
                            self.require_license
                        ),
                    });
                }
            } else {
                violations.push(ConstraintViolation {
                    package: package_name.to_string(),
                    rule: "requireLicense".to_string(),
                    detail: "no license field found".to_string(),
                });
            }
        }

        violations
    }
}
