use crate::version::Version;
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;

/// A version requirement (range) that versions can be matched against.
///
/// Supports the full npm range syntax:
/// - Exact: `1.2.3`
/// - Caret: `^1.2.3` (compatible with version)
/// - Tilde: `~1.2.3` (patch-level changes)
/// - Comparison: `>=1.0.0`, `<2.0.0`, `>=1.0.0 <2.0.0`
/// - OR: `^1.0.0 || ^2.0.0`
/// - Wildcard: `*`, `1.x`, `1.2.x`
/// - Hyphen ranges: `1.0.0 - 2.0.0`
///
/// Internally delegates to `node_semver::Range` for npm-compatible behavior.
#[derive(Debug, Clone)]
pub struct VersionReq {
    inner: node_semver::Range,
    /// Original string for display (node_semver normalizes the range on parse).
    original: String,
}

impl VersionReq {
    /// Parse a version range string.
    ///
    /// # Examples
    /// ```
    /// use lpm_semver::VersionReq;
    ///
    /// let range = VersionReq::parse("^1.0.0").unwrap();
    /// let range = VersionReq::parse(">=1.0.0 <2.0.0").unwrap();
    /// let range = VersionReq::parse("^1.0.0 || ^2.0.0").unwrap();
    /// let range = VersionReq::parse("*").unwrap();
    /// ```
    pub fn parse(input: &str) -> Result<Self, LpmError> {
        let trimmed = input.trim();
        let inner = parse_node_semver_range(input)?;
        Ok(VersionReq {
            inner,
            original: trimmed.to_string(),
        })
    }

    /// Check if a version satisfies this range.
    pub fn matches(&self, version: &Version) -> bool {
        self.inner.satisfies(version.as_inner())
    }

    /// Returns the original range string as provided to parse().
    pub fn original(&self) -> &str {
        &self.original
    }
}

/// Parse an npm semver range through LPM's defensive wrapper around `node-semver`.
pub fn parse_node_semver_range(input: &str) -> Result<node_semver::Range, LpmError> {
    let trimmed = input.trim();
    if !contains_only_range_characters(trimmed) {
        return Err(LpmError::InvalidVersionRange(format!(
            "{input}: contains unsupported semver range characters"
        )));
    }
    if has_invalid_range_token(trimmed) {
        return Err(LpmError::InvalidVersionRange(format!(
            "{input}: invalid range token"
        )));
    }
    if has_malformed_wildcard_range_operator(trimmed) {
        return Err(LpmError::InvalidVersionRange(format!(
            "{input}: invalid wildcard range"
        )));
    }
    if has_malformed_wildcard_comparator(trimmed) {
        return Err(LpmError::InvalidVersionRange(format!(
            "{input}: invalid wildcard comparator"
        )));
    }
    let parse_input = normalize_range_input(trimmed);
    parse_normalized_node_semver_range(input, parse_input.as_ref())
}

fn parse_normalized_node_semver_range(
    original: &str,
    normalized: &str,
) -> Result<node_semver::Range, LpmError> {
    let parsed = std::panic::catch_unwind(|| node_semver::Range::parse(normalized))
        .map_err(|_| LpmError::InvalidVersionRange(format!("{original}: invalid range")))?;
    parsed.map_err(|e| LpmError::InvalidVersionRange(format!("{original}: {e}")))
}

fn normalize_range_input(input: &str) -> Cow<'_, str> {
    // The Rust node_semver crate has rough edges around npm wildcard
    // operators; normalize those forms before they reach the parser.
    if let Some(normalized) = normalize_wildcard_hyphen(input) {
        Cow::Owned(normalized)
    } else if let Some(normalized) = normalize_wildcard_comparator(input) {
        Cow::Owned(normalized)
    } else if let Some(normalized) = normalize_wildcard_range_operators(input) {
        Cow::Owned(normalized)
    } else {
        Cow::Borrowed(input)
    }
}

#[derive(Clone, Copy)]
enum WildcardPart {
    Number(u64),
    Wildcard,
}

fn normalize_wildcard_comparator(input: &str) -> Option<String> {
    let (operator, operand) = split_comparator(input);
    let partial = parse_wildcard_partial(operand)?;
    if !partial.has_wildcard_or_missing() {
        return None;
    }
    if matches!(partial.major, WildcardPart::Wildcard) {
        return match operator {
            "" | "=" | ">=" | "<=" => Some("*".to_string()),
            "<" | ">" => Some("<0.0.0-0".to_string()),
            _ => None,
        };
    }
    let lower = partial.lower_bound();
    let upper = partial.upper_exclusive_bound()?;

    match operator {
        "" | "=" => Some(format!(
            ">={}.{}.{} <{}.{}.{}-0",
            lower.0, lower.1, lower.2, upper.0, upper.1, upper.2
        )),
        "<=" => Some(format!("<{}.{}.{}-0", upper.0, upper.1, upper.2)),
        "<" => Some(format!("<{}.{}.{}-0", lower.0, lower.1, lower.2)),
        ">=" => Some(format!(">={}.{}.{}", lower.0, lower.1, lower.2)),
        ">" => Some(format!(">={}.{}.{}", upper.0, upper.1, upper.2)),
        _ => None,
    }
}

fn normalize_wildcard_hyphen(input: &str) -> Option<String> {
    let (left, right) = input.split_once(" - ")?;
    if right.contains(" - ") {
        return None;
    }

    let left = parse_wildcard_partial(left)?;
    let right = parse_wildcard_partial(right)?;
    if !left.has_wildcard_or_missing() && !right.has_wildcard_or_missing() {
        return None;
    }

    let mut comparators = Vec::with_capacity(2);
    if !matches!(left.major, WildcardPart::Wildcard) {
        let lower = left.lower_bound();
        comparators.push(format!(">={}.{}.{}", lower.0, lower.1, lower.2));
    }
    if !matches!(right.major, WildcardPart::Wildcard) {
        if let Some(upper) = right.exact_bound() {
            comparators.push(format!("<={}.{}.{}", upper.0, upper.1, upper.2));
        } else {
            let upper = right.upper_exclusive_bound()?;
            comparators.push(format!("<{}.{}.{}-0", upper.0, upper.1, upper.2));
        }
    }

    if comparators.is_empty() {
        Some("*".to_string())
    } else {
        Some(comparators.join(" "))
    }
}

fn split_comparator(input: &str) -> (&'static str, &str) {
    let trimmed = input.trim();
    for operator in ["<=", ">=", "<", ">", "="] {
        if let Some(rest) = trimmed.strip_prefix(operator) {
            return (operator, rest.trim_start());
        }
    }
    ("", trimmed)
}

fn has_invalid_range_token(input: &str) -> bool {
    input
        .split("||")
        .flat_map(str::split_whitespace)
        .map(strip_range_operator)
        .map(|token| split_comparator(token).1)
        .filter(|operand| !operand.is_empty() && *operand != "-")
        .any(|operand| {
            operand
                .bytes()
                .all(|byte| !byte.is_ascii_alphanumeric() && byte != b'*')
        })
}

fn has_malformed_wildcard_range_operator(input: &str) -> bool {
    for disjunct in input.split("||") {
        let mut pending_range_operator = false;
        for token in disjunct.split_whitespace() {
            if pending_range_operator {
                if is_malformed_wildcard_operand(token) {
                    return true;
                }
                pending_range_operator = false;
                continue;
            }
            let Some(operand) = range_operator_operand(token) else {
                continue;
            };
            if operand.is_empty() {
                pending_range_operator = true;
                continue;
            }
            if is_malformed_wildcard_operand(operand) {
                return true;
            }
        }
    }
    false
}

fn normalize_wildcard_range_operators(input: &str) -> Option<String> {
    let mut changed = false;
    let mut disjuncts = Vec::new();
    for disjunct in input.split("||") {
        disjuncts.push(normalize_wildcard_operator_disjunct(
            disjunct.trim(),
            &mut changed,
        ));
    }
    if !changed {
        return None;
    }
    if disjuncts.iter().any(|disjunct| disjunct == "*") {
        Some("*".to_string())
    } else {
        Some(disjuncts.join(" || "))
    }
}

fn normalize_wildcard_operator_disjunct(disjunct: &str, changed: &mut bool) -> String {
    let mut local_changed = false;
    let mut normalized = Vec::new();
    let mut tokens = disjunct.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        if is_range_operator_token(token)
            && tokens
                .peek()
                .is_some_and(|operand| is_valid_wildcard_operand(operand))
        {
            tokens.next();
            local_changed = true;
            normalized.push("*".to_string());
            continue;
        }
        if range_operator_operand(token).is_some_and(is_valid_wildcard_operand) {
            local_changed = true;
            normalized.push("*".to_string());
            continue;
        }
        normalized.push(token.to_string());
    }
    if !local_changed {
        return disjunct.to_string();
    }

    *changed = true;
    normalized.retain(|token| token != "*");
    if normalized.is_empty() {
        "*".to_string()
    } else {
        normalized.join(" ")
    }
}

fn is_range_operator_token(token: &str) -> bool {
    matches!(token, "^" | "~" | "~>")
}

fn range_operator_operand(token: &str) -> Option<&str> {
    token
        .strip_prefix("~>")
        .or_else(|| token.strip_prefix('^'))
        .or_else(|| token.strip_prefix('~'))
}

fn has_malformed_wildcard_comparator(input: &str) -> bool {
    for disjunct in input.split("||") {
        let mut pending_operator = false;
        for token in disjunct.split_whitespace() {
            let token = strip_range_operator(token);
            if pending_operator {
                if is_malformed_wildcard_operand(token) {
                    return true;
                }
                pending_operator = false;
                continue;
            }
            let (operator, operand) = split_comparator(token);
            if operator.is_empty() {
                continue;
            }
            if operand.is_empty() {
                pending_operator = true;
                continue;
            }
            if is_malformed_wildcard_operand(operand) {
                return true;
            }
        }
    }
    false
}

fn strip_range_operator(token: &str) -> &str {
    let token = token.strip_prefix("~>").unwrap_or(token);
    token
        .strip_prefix('^')
        .or_else(|| token.strip_prefix('~'))
        .unwrap_or(token)
}

fn is_malformed_wildcard_operand(input: &str) -> bool {
    starts_like_wildcard(input) && parse_wildcard_partial(input).is_none()
}

fn is_valid_wildcard_operand(input: &str) -> bool {
    starts_like_wildcard(input) && parse_wildcard_partial(input).is_some()
}

fn starts_like_wildcard(input: &str) -> bool {
    matches!(input.as_bytes().first(), Some(b'*' | b'x' | b'X'))
}

struct WildcardPartial {
    major: WildcardPart,
    minor: Option<WildcardPart>,
    patch: Option<WildcardPart>,
}

impl WildcardPartial {
    fn has_wildcard_or_missing(&self) -> bool {
        matches!(self.major, WildcardPart::Wildcard)
            || self.minor.is_none()
            || matches!(self.minor, Some(WildcardPart::Wildcard))
            || self.patch.is_none()
            || matches!(self.patch, Some(WildcardPart::Wildcard))
    }

    fn lower_bound(&self) -> (u64, u64, u64) {
        let major = part_number_or_zero(self.major);
        let minor = self.minor.map_or(0, part_number_or_zero);
        let patch = self.patch.map_or(0, part_number_or_zero);
        (major, minor, patch)
    }

    fn upper_exclusive_bound(&self) -> Option<(u64, u64, u64)> {
        match (self.major, self.minor, self.patch) {
            (WildcardPart::Wildcard, _, _) => None,
            (WildcardPart::Number(major), None | Some(WildcardPart::Wildcard), _) => {
                Some((major.checked_add(1)?, 0, 0))
            }
            (
                WildcardPart::Number(major),
                Some(WildcardPart::Number(minor)),
                None | Some(WildcardPart::Wildcard),
            ) => Some((major, minor.checked_add(1)?, 0)),
            _ => None,
        }
    }

    fn exact_bound(&self) -> Option<(u64, u64, u64)> {
        match (self.major, self.minor, self.patch) {
            (
                WildcardPart::Number(major),
                Some(WildcardPart::Number(minor)),
                Some(WildcardPart::Number(patch)),
            ) => Some((major, minor, patch)),
            _ => None,
        }
    }
}

fn part_number_or_zero(part: WildcardPart) -> u64 {
    match part {
        WildcardPart::Number(value) => value,
        WildcardPart::Wildcard => 0,
    }
}

fn parse_wildcard_partial(input: &str) -> Option<WildcardPartial> {
    let token = input.trim();
    if token.is_empty()
        || token.split_whitespace().count() != 1
        || token.contains('-')
        || token.contains('+')
    {
        return None;
    }

    let token = token.strip_prefix('v').unwrap_or(token);
    let mut parts = token.split('.');
    let major = parse_wildcard_part(parts.next()?)?;
    let minor = match parts.next() {
        Some(part) => Some(parse_wildcard_part(part)?),
        None => None,
    };
    let patch = match parts.next() {
        Some(part) => Some(parse_wildcard_part(part)?),
        None => None,
    };
    if parts.next().is_some() {
        return None;
    }
    if !wildcard_hierarchy_is_valid(major, minor, patch) {
        return None;
    }

    Some(WildcardPartial {
        major,
        minor,
        patch,
    })
}

fn wildcard_hierarchy_is_valid(
    major: WildcardPart,
    minor: Option<WildcardPart>,
    patch: Option<WildcardPart>,
) -> bool {
    if matches!(major, WildcardPart::Wildcard) {
        return minor.is_none_or(|part| matches!(part, WildcardPart::Wildcard))
            && patch.is_none_or(|part| matches!(part, WildcardPart::Wildcard));
    }
    if matches!(minor, Some(WildcardPart::Wildcard)) {
        return patch.is_none_or(|part| matches!(part, WildcardPart::Wildcard));
    }
    true
}

fn parse_wildcard_part(part: &str) -> Option<WildcardPart> {
    match part {
        "*" | "x" | "X" => Some(WildcardPart::Wildcard),
        _ => part.parse::<u64>().ok().map(WildcardPart::Number),
    }
}

fn contains_only_range_characters(input: &str) -> bool {
    input.bytes().all(|byte| {
        matches!(
            byte,
            b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
                | b' '
                | b'\t'
                | b'.'
                | b'-'
                | b'+'
                | b'*'
                | b'<'
                | b'>'
                | b'='
                | b'~'
                | b'^'
                | b'|'
        )
    })
}

impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.original)
    }
}

impl PartialEq for VersionReq {
    fn eq(&self, other: &Self) -> bool {
        // Compare the normalized internal representation
        self.inner.to_string() == other.inner.to_string()
    }
}

impl Eq for VersionReq {}

impl Serialize for VersionReq {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.original)
    }
}

impl<'de> Deserialize<'de> for VersionReq {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        VersionReq::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn r(s: &str) -> VersionReq {
        VersionReq::parse(s).unwrap()
    }

    // --- Caret ranges (^) ---
    // ^1.2.3 := >=1.2.3 <2.0.0
    // ^0.2.3 := >=0.2.3 <0.3.0
    // ^0.0.3 := >=0.0.3 <0.0.4

    #[test]
    fn caret_major() {
        let range = r("^1.2.3");
        assert!(range.matches(&v("1.2.3")));
        assert!(range.matches(&v("1.9.9")));
        assert!(!range.matches(&v("2.0.0")));
        assert!(!range.matches(&v("1.2.2")));
    }

    #[test]
    fn caret_minor_zero() {
        let range = r("^0.2.3");
        assert!(range.matches(&v("0.2.3")));
        assert!(range.matches(&v("0.2.9")));
        assert!(!range.matches(&v("0.3.0")));
    }

    #[test]
    fn caret_patch_zero() {
        let range = r("^0.0.3");
        assert!(range.matches(&v("0.0.3")));
        assert!(!range.matches(&v("0.0.4")));
    }

    // --- Tilde ranges (~) ---
    // ~1.2.3 := >=1.2.3 <1.3.0
    // ~0.2.3 := >=0.2.3 <0.3.0

    #[test]
    fn tilde_range() {
        let range = r("~1.2.3");
        assert!(range.matches(&v("1.2.3")));
        assert!(range.matches(&v("1.2.9")));
        assert!(!range.matches(&v("1.3.0")));
    }

    #[test]
    fn tilde_wildcard_matches_stable_versions_without_panicking() {
        let range = r("~x");
        assert!(range.matches(&v("0.0.9")));
        assert!(range.matches(&v("1.2.3")));
        assert_eq!(range.original(), "~x");
    }

    #[test]
    fn caret_wildcard_matches_stable_versions() {
        let range = r("^x");
        assert!(range.matches(&v("0.0.9")));
        assert!(range.matches(&v("1.2.3")));
        assert_eq!(range.original(), "^x");
    }

    #[test]
    fn wildcard_range_operators_are_valid_in_compound_ranges() {
        let or_with_caret_wildcard = r("^x || ^1.0.0");
        assert!(or_with_caret_wildcard.matches(&v("0.0.9")));
        assert!(or_with_caret_wildcard.matches(&v("4.2.0")));

        let or_with_tilde_wildcard = r("~x || 1.0.0");
        assert!(or_with_tilde_wildcard.matches(&v("0.0.9")));
        assert!(or_with_tilde_wildcard.matches(&v("4.2.0")));

        let compound_with_wildcard_identity = r(">=1.0.0 ~x");
        assert!(!compound_with_wildcard_identity.matches(&v("0.9.9")));
        assert!(compound_with_wildcard_identity.matches(&v("1.0.0")));
        assert!(compound_with_wildcard_identity.matches(&v("4.2.0")));

        let spaced_tilde_wildcard = r("~ x");
        assert!(spaced_tilde_wildcard.matches(&v("0.0.9")));
        assert!(spaced_tilde_wildcard.matches(&v("4.2.0")));

        let spaced_caret_wildcard = r("^ x");
        assert!(spaced_caret_wildcard.matches(&v("0.0.9")));
        assert!(spaced_caret_wildcard.matches(&v("4.2.0")));
    }

    // --- Comparison operators ---

    #[test]
    fn gte_range() {
        let range = r(">=1.0.0");
        assert!(range.matches(&v("1.0.0")));
        assert!(range.matches(&v("2.0.0")));
        assert!(!range.matches(&v("0.9.9")));
    }

    #[test]
    fn compound_range() {
        let range = r(">=1.0.0 <2.0.0");
        assert!(range.matches(&v("1.0.0")));
        assert!(range.matches(&v("1.9.9")));
        assert!(!range.matches(&v("2.0.0")));
        assert!(!range.matches(&v("0.9.9")));
    }

    // --- OR ranges (||) ---

    #[test]
    fn or_range() {
        let range = r("^1.0.0 || ^2.0.0");
        assert!(range.matches(&v("1.5.0")));
        assert!(range.matches(&v("2.5.0")));
        assert!(!range.matches(&v("3.0.0")));
    }

    // --- Wildcard ranges ---

    #[test]
    fn star_matches_everything() {
        let range = r("*");
        assert!(range.matches(&v("0.0.1")));
        assert!(range.matches(&v("999.999.999")));
    }

    #[test]
    fn x_range_minor() {
        let range = r("1.x");
        assert!(range.matches(&v("1.0.0")));
        assert!(range.matches(&v("1.9.9")));
        assert!(!range.matches(&v("2.0.0")));
    }

    #[test]
    fn x_range_patch() {
        let range = r("1.2.x");
        assert!(range.matches(&v("1.2.0")));
        assert!(range.matches(&v("1.2.9")));
        assert!(!range.matches(&v("1.3.0")));
    }

    #[test]
    fn comparator_wildcard_ranges_follow_npm_boundaries() {
        let at_most_minor = r("<=0.7.x");
        assert!(at_most_minor.matches(&v("0.7.2")));
        assert!(at_most_minor.matches(&v("0.6.2")));
        assert!(!at_most_minor.matches(&v("0.8.0")));

        let below_minor = r("<0.7.x");
        assert!(below_minor.matches(&v("0.6.9")));
        assert!(!below_minor.matches(&v("0.7.0")));

        let at_least_minor = r(">=0.7.x");
        assert!(at_least_minor.matches(&v("0.7.0")));
        assert!(at_least_minor.matches(&v("0.8.0")));
        assert!(!at_least_minor.matches(&v("0.6.9")));

        let above_minor = r(">0.7.x");
        assert!(above_minor.matches(&v("0.8.0")));
        assert!(!above_minor.matches(&v("0.7.9")));

        let exact_any = r("=*");
        assert!(exact_any.matches(&v("0.0.1")));
        assert!(exact_any.matches(&v("9.9.9")));
    }

    // --- Exact version ---

    #[test]
    fn exact_version() {
        let range = r("1.2.3");
        assert!(range.matches(&v("1.2.3")));
        assert!(!range.matches(&v("1.2.4")));
    }

    // --- Pre-release handling ---

    #[test]
    fn prerelease_only_matches_same_major_minor_patch() {
        // npm semver rule: pre-releases only match ranges that explicitly
        // include a pre-release on the same [major, minor, patch] tuple
        let range = r(">=1.0.0-alpha <1.0.0");
        assert!(range.matches(&v("1.0.0-beta")));
        assert!(!range.matches(&v("1.0.1-alpha")));
    }

    // --- Hyphen range ---

    #[test]
    fn hyphen_range() {
        let range = r("1.0.0 - 2.0.0");
        assert!(range.matches(&v("1.0.0")));
        assert!(range.matches(&v("1.5.0")));
        assert!(range.matches(&v("2.0.0")));
        assert!(!range.matches(&v("2.0.1")));
        assert!(!range.matches(&v("0.9.9")));
    }

    #[test]
    fn hyphen_wildcard_ranges_follow_npm_boundaries() {
        let unbounded_lower = r("x - 1.x");
        assert!(unbounded_lower.matches(&v("0.9.7")));
        assert!(unbounded_lower.matches(&v("1.9.7")));
        assert!(!unbounded_lower.matches(&v("2.0.0")));

        let unbounded_upper = r("1.0.0 - x");
        assert!(unbounded_upper.matches(&v("1.0.0")));
        assert!(unbounded_upper.matches(&v("1.9.7")));
        assert!(!unbounded_upper.matches(&v("0.9.9")));

        let partial_lower = r("1.x - x");
        assert!(partial_lower.matches(&v("1.0.0")));
        assert!(partial_lower.matches(&v("9.9.9")));
        assert!(!partial_lower.matches(&v("0.9.9")));
    }

    // --- Edge cases ---

    #[test]
    fn empty_string_rejected() {
        // node-semver crate rejects empty strings (npm CLI treats as "*").
        // This is acceptable — real package.json never has empty version ranges.
        assert!(VersionReq::parse("").is_err());
    }

    #[test]
    fn reject_invalid_range() {
        assert!(VersionReq::parse("not a range at all!!!").is_err());
    }

    #[test]
    fn malformed_wildcard_range_returns_error() {
        assert!(VersionReq::parse("=xx").is_err());
        assert!(VersionReq::parse("^1.0.0 ||=*3").is_err());
        assert!(VersionReq::parse("=x.1.00 .00 1 1").is_err());
        assert!(VersionReq::parse(". ~x\n").is_err());
        assert!(VersionReq::parse("~X0^.00").is_err());
        assert!(VersionReq::parse("~\tx~x\n\n").is_err());
    }

    // --- Display ---

    #[test]
    fn display_preserves_original() {
        let range = r("^1.0.0 || ^2.0.0");
        assert_eq!(range.to_string(), "^1.0.0 || ^2.0.0");
    }

    #[test]
    fn parse_trims_surrounding_whitespace() {
        let range = VersionReq::parse("  ^1.0.0 || ^2.0.0  ").unwrap();
        assert!(range.matches(&v("1.5.0")));
        assert!(range.matches(&v("2.5.0")));
        assert_eq!(range.original(), "^1.0.0 || ^2.0.0");
    }

    // --- Serde ---

    #[test]
    fn serde_roundtrip() {
        let range = r("^1.0.0");
        let json = serde_json::to_string(&range).unwrap();
        let parsed: VersionReq = serde_json::from_str(&json).unwrap();
        assert_eq!(range.original(), parsed.original());
    }
}
