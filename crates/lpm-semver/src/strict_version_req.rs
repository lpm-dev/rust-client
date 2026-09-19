use crate::{Version, parse_node_semver_range};
use lpm_common::LpmError;

/// A fully validated selector whose comparator conjunctions remain intersections.
///
/// Intended for explicit runtime selectors. Dependency ranges retain their
/// existing npm-compatible loose parsing through `VersionReq`.
#[derive(Debug, Clone)]
pub struct StrictVersionReq {
    alternatives: Vec<node_semver::Range>,
}

impl StrictVersionReq {
    pub fn parse(input: &str) -> Result<Self, LpmError> {
        let invalid = || LpmError::InvalidVersionRange(input.to_owned());
        let mut alternatives = Vec::new();
        for alternative in input.split("||") {
            let tokens: Vec<_> = alternative.split_whitespace().collect();
            if tokens.is_empty() {
                return Err(invalid());
            }
            let mut range: Option<node_semver::Range> = None;
            let mut prerelease_candidates = Vec::new();
            let mut empty = false;
            let mut index = 0;
            while index < tokens.len() {
                let token = tokens[index];
                let mut parts = Vec::with_capacity(2);
                if index + 2 < tokens.len() && tokens[index + 1] == "-" {
                    let upper = tokens[index + 2];
                    validate_partial(token).ok_or_else(invalid)?;
                    validate_partial(upper).ok_or_else(invalid)?;
                    parts.push(format!(">={token}"));
                    parts.push(format!("<={upper}"));
                    index += 3;
                } else {
                    let prefix_len = token
                        .bytes()
                        .take_while(|byte| matches!(byte, b'>' | b'<' | b'=' | b'~' | b'^'))
                        .count();
                    let (operator, attached) = token.split_at(prefix_len);
                    if !matches!(
                        operator,
                        "" | "=" | ">" | "<" | ">=" | "<=" | "~" | "~>" | "^"
                    ) {
                        return Err(invalid());
                    }
                    index += 1;
                    let operand = if attached.is_empty() {
                        let operand = *tokens.get(index).ok_or_else(invalid)?;
                        index += 1;
                        operand
                    } else {
                        attached
                    };
                    validate_partial(operand).ok_or_else(invalid)?;
                    let operator = if operator == "~>" { "~" } else { operator };
                    parts.push(format!("{operator}{operand}"));
                }
                for part in parts {
                    let atom = parse_node_semver_range(&part)?;
                    let operand = part.trim_start_matches(['<', '>', '=', '~', '^']);
                    if operand.contains('-')
                        && let Ok(version) = Version::parse(operand)
                        && version.as_inner().is_prerelease()
                    {
                        // The upstream minimum skips prereleases after a stable exclusive lower bound.
                        let mut candidate = version.as_inner().clone();
                        candidate.pre_release.clear();
                        candidate
                            .pre_release
                            .push(node_semver::Identifier::Numeric(0));
                        prerelease_candidates.push(candidate);
                    }

                    if empty {
                        continue;
                    }
                    range = match range {
                        Some(previous) => previous.intersect(&atom),
                        None => Some(atom),
                    };
                    empty = range.is_none();
                }
            }
            if let Some(range) = range
                && (range
                    .min_version()
                    .is_some_and(|version| range.satisfies(&version))
                    || prerelease_candidates
                        .iter()
                        .any(|version| range.satisfies(version)))
            {
                alternatives.push(range);
            }
        }
        Ok(Self { alternatives })
    }

    pub fn is_empty(&self) -> bool {
        self.alternatives.is_empty()
    }

    pub fn matches(&self, version: &Version) -> bool {
        self.alternatives
            .iter()
            .any(|range| range.satisfies(version.as_inner()))
    }
}

fn validate_partial(input: &str) -> Option<()> {
    let input = input.strip_prefix('v').unwrap_or(input);
    let (without_build, build) = input
        .split_once('+')
        .map_or((input, None), |(core, build)| (core, Some(build)));
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(core, pre)| (core, Some(pre)));
    let suffixed = prerelease.is_some() || build.is_some();
    let mut wildcard = false;
    let mut count = 0;
    for part in core.split('.') {
        count += 1;
        if count > 3 || part.is_empty() {
            return None;
        }
        if matches!(part, "*" | "x" | "X") && !suffixed {
            wildcard = true;
        } else if wildcard || !valid_number(part) {
            return None;
        }
    }
    if suffixed && count != 3 {
        return None;
    }
    if prerelease.is_some_and(|pre| !valid_identifiers(pre, true))
        || build.is_some_and(|build| !valid_identifiers(build, false))
    {
        return None;
    }
    Some(())
}

fn valid_number(part: &str) -> bool {
    !part.is_empty()
        && part.bytes().all(|b| b.is_ascii_digit())
        && (part.len() == 1 || !part.starts_with('0'))
        && part.parse::<u64>().is_ok()
}

fn valid_identifiers(input: &str, prerelease: bool) -> bool {
    input.split('.').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !(prerelease
                && part.len() > 1
                && part.starts_with('0')
                && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upper_prerelease_bounds_can_admit_versions_above_a_stable_lower_bound() {
        let range = StrictVersionReq::parse(">1.0.0 <1.0.1-rc.2").unwrap();
        assert!(!range.is_empty());
        assert!(range.matches(&Version::parse("1.0.1-0").unwrap()));
    }

    #[test]
    fn empty_wildcard_comparators_have_no_satisfiable_alternative() {
        for spec in [">*", "<*", "<0.0.0-0", "<0.0.0", ">1.0.0 <1.0.1"] {
            assert!(StrictVersionReq::parse(spec).unwrap().is_empty(), "{spec}");
        }
    }

    #[test]
    fn strict_prerelease_selectors_reject_loose_version_spellings() {
        for spec in ["022.12.0-rc.1", "22.12.0-01", "22.12.0rc-1"] {
            assert!(StrictVersionReq::parse(spec).is_err(), "{spec}");
        }
    }

    #[test]
    fn strict_selectors_preserve_the_tilde_greater_alias() {
        assert!(
            StrictVersionReq::parse("~>1.3.0")
                .unwrap()
                .matches(&Version::parse("1.3.14").unwrap())
        );
    }

    #[test]
    fn strict_selectors_preserve_runtime_range_forms() {
        for spec in [
            "22",
            "22.12",
            "22.12.0",
            "v22.12.0",
            "=22.12.0",
            "= 22.12.0",
            "22.x",
            "22.X",
            "22.*",
            "*",
            "^22",
            "~22.12",
            ">=22 <23",
            ">= 22 < 23",
            "20 - 22",
            "20.0.0 - 22.12.0",
            "^20 || ^22",
        ] {
            let req = StrictVersionReq::parse(spec).unwrap();
            assert!(req.matches(&Version::parse("22.12.0").unwrap()), "{spec}");
        }
    }

    #[test]
    fn strict_selectors_reject_every_unrecognized_token() {
        for spec in [
            "",
            " ",
            "22 foo",
            ">=22 garbage",
            "22 || nonsense",
            "22 ||",
            "||22",
            "22 | 23",
            "foo",
            "=",
            "22.1.2.3",
            "22..1",
            "22.x.1",
            "^^22",
            "22 -",
            "22 - foo",
            "22 / 23",
        ] {
            assert!(StrictVersionReq::parse(spec).is_err(), "{spec}");
        }
    }

    #[test]
    fn contradictory_conjunctions_never_become_alternatives() {
        for spec in [">=22 <20", "22 20", "22 - 20", ">=22 <20 >=18"] {
            let req = StrictVersionReq::parse(spec).unwrap();
            for version in ["18.0.0", "20.0.0", "22.12.0", "24.0.0"] {
                assert!(
                    !req.matches(&Version::parse(version).unwrap()),
                    "{spec} matched {version}"
                );
            }
        }
        let req = StrictVersionReq::parse(">=22 <20 || ^24").unwrap();
        assert!(req.matches(&Version::parse("24.1.0").unwrap()));
        assert!(!req.matches(&Version::parse("22.12.0").unwrap()));
    }

    #[test]
    fn conjunctions_preserve_prerelease_admission_and_bounds() {
        let req = StrictVersionReq::parse(">=22.0.0-rc.1 <22.0.0").unwrap();
        assert!(req.matches(&Version::parse("22.0.0-rc.2").unwrap()));
        assert!(!req.matches(&Version::parse("22.0.0").unwrap()));
        assert!(
            !StrictVersionReq::parse(">=22 <23")
                .unwrap()
                .matches(&Version::parse("22.1.0-rc.1").unwrap())
        );
    }
}
