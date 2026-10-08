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
    normalize_wildcard_comparator_operand(operator, operand)
}

fn normalize_wildcard_comparator_operand(operator: &str, operand: &str) -> Option<String> {
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
    let (left, right) = split_hyphen_bounds(input)?;
    normalize_hyphen_bounds(left, right)
}

#[derive(Clone, Copy)]
struct HyphenBound<'a> {
    operand: &'a str,
    equality: bool,
}

fn split_hyphen_bounds(input: &str) -> Option<(HyphenBound<'_>, HyphenBound<'_>)> {
    let mut tokens = input.split_whitespace();
    let left = take_hyphen_bound(&mut tokens)?;
    if tokens.next()? != "-" {
        return None;
    }
    let right = take_hyphen_bound(&mut tokens)?;
    if tokens.next().is_some() {
        return None;
    }
    Some((left, right))
}

fn take_hyphen_bound<'a>(tokens: &mut std::str::SplitWhitespace<'a>) -> Option<HyphenBound<'a>> {
    let token = tokens.next()?;
    let operand = if token == "=" { tokens.next()? } else { token };
    let version_then_equality = operand.strip_prefix("v=");
    Some(HyphenBound {
        operand: version_then_equality.unwrap_or_else(|| operand.trim_start_matches('=')),
        equality: token.starts_with('=') || version_then_equality.is_some(),
    })
}

fn normalize_hyphen_bounds(left: HyphenBound<'_>, right: HyphenBound<'_>) -> Option<String> {
    let left = normalize_hyphen_bound(left, true)?;
    let right = normalize_hyphen_bound(right, false)?;
    if !left.is_empty() && !right.is_empty() {
        let (_, lower) = split_comparator(&left);
        let (operator, upper) = split_comparator(&right);
        let lower = node_semver::Version::parse(lower).ok()?;
        let upper = node_semver::Version::parse(upper).ok()?;
        if lower > upper || (lower == upper && operator == "<") {
            return Some("<0.0.0-0".to_string());
        }
    }
    match (left.is_empty(), right.is_empty()) {
        (true, true) => Some("*".to_string()),
        (false, true) => Some(left),
        (true, false) => Some(right),
        (false, false) => Some(format!("{left} {right}")),
    }
}

fn normalize_hyphen_bound(bound: HyphenBound<'_>, is_lower: bool) -> Option<String> {
    let input = bound.operand;
    if let Some(partial) = parse_wildcard_partial(input) {
        if bound.equality && !partial.has_wildcard_or_missing() {
            return None;
        }
        if matches!(partial.major, WildcardPart::Wildcard) {
            return Some(String::new());
        }
        if is_lower {
            let lower = partial.lower_bound();
            return Some(format!(">={}.{}.{}", lower.0, lower.1, lower.2));
        }
        if let Some(upper) = partial.exact_bound() {
            return Some(format!("<={}.{}.{}", upper.0, upper.1, upper.2));
        }
        let upper = partial.upper_exclusive_bound()?;
        return Some(format!("<{}.{}.{}-0", upper.0, upper.1, upper.2));
    }
    let version = node_semver::Version::parse(input).ok()?;
    if bound.equality && (is_lower || !version.is_prerelease()) {
        return None;
    }
    Some(format!("{}{version}", if is_lower { ">=" } else { "<=" }))
}

fn split_comparator(input: &str) -> (&'static str, &str) {
    let trimmed = input.trim();
    for operator in ["<=", ">=", "<", ">", "="] {
        if let Some(rest) = trimmed.strip_prefix(operator) {
            return (operator, rest.trim_start().trim_start_matches('='));
        }
    }
    ("", trimmed)
}

fn has_invalid_range_token(input: &str) -> bool {
    for disjunct in input.split("||") {
        if disjunct.split_whitespace().any(|token| token == "-") {
            if normalize_wildcard_hyphen(disjunct).is_none() {
                return true;
            }
            continue;
        }
        let mut previous = None;
        let mut tokens = disjunct.split_whitespace().peekable();
        while let Some(token) = tokens.next() {
            if is_operator_only_token(token) && tokens.peek().is_none() {
                return true;
            }
            if previous == Some("~>") && token == "=" {
                return true;
            }
            if previous
                .is_some_and(|token: &str| is_range_operator_token(token.trim_end_matches('=')))
                && is_comparison_operator(token)
                && token != "="
            {
                return true;
            }
            if previous.is_some_and(is_comparison_operator) && is_comparison_operator(token) {
                return true;
            }
            if previous.is_some_and(is_comparison_operator)
                && token.starts_with("==")
                && node_semver::Version::parse(token.trim_start_matches('=')).is_ok()
            {
                return true;
            }
            if previous.is_some_and(|token: &str| {
                is_comparison_operator(token)
                    || is_range_operator_token(token.trim_end_matches('='))
            }) && token.starts_with(['<', '>', '^', '~'])
            {
                return true;
            }
            let operand = split_comparator(strip_range_operator(token)).1;
            let normalized_operand = strip_loose_version_equality(operand);
            if !operand.is_empty()
                && operand != "-"
                && ((parse_wildcard_partial(normalized_operand).is_none()
                    && node_semver::Version::parse(normalized_operand).is_err())
                    || is_malformed_wildcard_operand(operand)
                    || normalized_operand
                        .bytes()
                        .any(|byte| matches!(byte, b'<' | b'>' | b'=' | b'^' | b'~'))
                    || normalized_operand
                        .bytes()
                        .all(|byte| !byte.is_ascii_alphanumeric() && byte != b'*'))
            {
                return true;
            }
            previous = Some(token);
        }
    }
    false
}

fn is_operator_only_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| matches!(byte, b'<' | b'>' | b'=' | b'^' | b'~'))
}

fn is_comparison_operator(token: &str) -> bool {
    matches!(token, "<" | ">" | "<=" | ">=")
        || (!token.is_empty() && token.bytes().all(|byte| byte == b'='))
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
    if let Some(range) = normalize_wildcard_hyphen(disjunct) {
        *changed = true;
        return range;
    }
    let mut local_changed = false;
    let mut normalized = Vec::new();
    let mut tokens = disjunct.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        let range_operator = token.trim_end_matches('=');
        if is_range_operator_token(range_operator) {
            let mut operand = tokens.peek().copied().unwrap_or_default();
            if operand == "=" {
                tokens.next();
                operand = tokens.peek().copied().unwrap_or_default();
            }
            if !operand.is_empty() {
                tokens.next();
                local_changed = true;
                let operand = operand.trim_start_matches('=');
                normalized.push(if is_valid_wildcard_operand(operand) {
                    "*".to_string()
                } else {
                    format!("{range_operator}{operand}")
                });
                continue;
            }
        }
        let (operator, operand) = split_comparator(token);
        let candidate_operand = if operand.is_empty() {
            tokens.peek().copied().unwrap_or_default()
        } else {
            operand
        }
        .trim_start_matches('=');
        if !operator.is_empty()
            && let Some(range) = normalize_wildcard_comparator_operand(operator, candidate_operand)
        {
            if operand.is_empty() {
                tokens.next();
            }
            local_changed = true;
            normalized.push(range);
            continue;
        }
        if let Some(operand) = range_operator_operand(token) {
            if is_valid_wildcard_operand(operand) {
                local_changed = true;
                normalized.push("*".to_string());
                continue;
            }
            if token.contains('=') {
                local_changed = true;
                let operator = if token.starts_with('^') { "^" } else { "~" };
                normalized.push(format!("{operator}{operand}"));
                continue;
            }
        }
        normalized.push(token.to_string());
    }
    if normalized.iter().any(|token| token == "<0.0.0-0") {
        *changed = true;
        return "<0.0.0-0".to_string();
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
        .map(|operand| strip_loose_version_equality(operand.trim_start_matches('=')))
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
    let input = strip_loose_version_equality(input);
    let input = input.strip_prefix('v').unwrap_or(input);
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

    let token = strip_loose_version_equality(token);
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

fn strip_loose_version_equality(input: &str) -> &str {
    input.strip_prefix("v=").unwrap_or(input)
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

    #[test]
    fn embedded_range_operators_are_rejected_before_upstream_parsing() {
        for input in ["1>0.0 - =x", ">10.0>- =x", "1= x", "1.2>3", "1.0.0-alpha^1"] {
            assert!(has_invalid_range_token(input), "accepted {input:?}");
        }
    }

    #[test]
    fn repeated_comparison_operators_are_rejected_before_upstream_parsing() {
        for input in ["= = x", "= = *1.0-", "x- 9-x- 9- = = *1.0- = 1", "= === X"] {
            assert!(has_invalid_range_token(input), "accepted {input:?}");
        }
    }

    #[test]
    fn malformed_wildcard_operands_are_rejected_after_separated_equality() {
        for input in [">1 N 2 = =*2.", "^= = *1.0", "= =x-"] {
            assert!(has_invalid_range_token(input), "accepted {input:?}");
        }
    }

    #[test]
    fn non_version_comparator_operands_are_rejected_before_upstream_parsing() {
        for input in ["=v * -2", "=v", ">N", "1 N 2"] {
            assert!(has_invalid_range_token(input), "accepted {input:?}");
        }
    }

    #[test]
    fn separated_range_operators_reject_other_range_operators() {
        for input in ["~ > X", "~\t\t>\t\t\t X", "^ < x", "~ ^x", "~ === X"] {
            assert!(has_invalid_range_token(input), "accepted {input:?}");
        }
    }

    #[test]
    fn range_operators_without_operands_are_rejected() {
        for input in ["1 >=", "1 =", "1 ^", "1 ^=", "1 ~=", ">= || 1", "^= || 1"] {
            assert!(VersionReq::parse(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn separated_comparators_reject_repeated_equality_on_exact_versions() {
        for input in [
            ">= ==1.2.3",
            "= ==1.2.3",
            "1 >= ==1.2.3",
            "1 = ==1.2.3",
            ">= ==1.2.3-alpha",
        ] {
            assert!(VersionReq::parse(input).is_err(), "accepted {input:?}");
        }
        assert!(VersionReq::parse(">= ==1").is_ok());
    }

    #[test]
    fn tilde_greater_equality_spacing_matches_npm() {
        for input in ["~> = 1.2.3", "~> = x", "~> = x || 1"] {
            assert!(VersionReq::parse(input).is_err(), "accepted {input:?}");
        }
        for input in ["~> =1.2.3", "~> =x", "^ = 1.2.3", "~ = 1.2.3"] {
            assert!(VersionReq::parse(input).is_ok(), "rejected {input:?}");
        }
    }

    #[test]
    fn version_prefixed_wildcard_operators_match_stable_versions() {
        for input in ["~vx", "^vx", "~ vx", "^ vx", "1 ~vx"] {
            let range = r(input);
            assert!(range.matches(&v("1.0.0")), "{input}");
            if input != "1 ~vx" {
                assert!(range.matches(&v("9.0.0")), "{input}");
            }
        }
    }

    #[test]
    fn version_then_equality_prefix_matches_npm_partial_ranges() {
        for input in ["v=1", "^v=1", "~v=1", "v=x", "^v=x"] {
            let range = r(input);
            assert!(range.matches(&v("1.0.0")), "{input}");
        }
        let exact_caret = r("^v=1.2.3");
        assert!(exact_caret.matches(&v("1.2.3")));
        assert!(!exact_caret.matches(&v("2.0.0")));
    }

    #[test]
    fn equality_prefixes_preserve_npm_range_operator_meaning() {
        for input in ["^=x", "^ = x", "~=x", "~ = x", "==x", "= =x", ">= =x"] {
            let range = r(input);
            assert!(range.matches(&v("0.0.0")), "{input}");
            assert!(range.matches(&v("9.0.0")), "{input}");
        }
        for input in ["^=1.2", "^ = 1.2", "^ =1.2"] {
            let range = r(input);
            assert!(range.matches(&v("1.9.0")), "{input}");
            assert!(!range.matches(&v("2.0.0")), "{input}");
        }
        for input in ["==1", "= =1", "1 - ==2"] {
            let range = r(input);
            assert!(range.matches(&v("1.0.0")), "{input}");
            assert!(!range.matches(&v("3.0.0")), "{input}");
        }
    }

    #[test]
    fn reversed_hyphen_bounds_match_no_version() {
        for input in ["1 - 0.x", "2 - 1", "2.0.0 - 1.0.0", "1.x - 0.x"] {
            let range = r(input);
            for version in ["0.0.0", "0.9.9", "1.0.0", "1.9.9", "2.0.0", "9.0.0"] {
                assert!(!range.matches(&v(version)), "{input} matched {version}");
            }
        }
        let disjunction = r("2 - 1 || 3");
        assert!(!disjunction.matches(&v("2.0.0")));
        assert!(disjunction.matches(&v("3.0.0")));
    }

    #[test]
    fn hyphen_ranges_reject_additional_conjuncts() {
        for input in [
            "^ = 1 - 2",
            "> = 1 - 2",
            "1 - =x 3",
            ">=1 1 - 2",
            "1 - 2 <=3",
        ] {
            assert!(VersionReq::parse(input).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn full_stable_hyphen_bounds_reject_equality_prefixes() {
        for input in [
            "=1.2.3 - 2",
            "1 - =2.0.0",
            "=1.2.3+build - 2",
            "1 - =2.0.0+build",
            "v=1.2.3 - 2",
            "v=1.0.0-alpha - 2",
            "1 - v=2.0.0",
        ] {
            assert!(VersionReq::parse(input).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn hyphen_range_bounds_allow_versions_prereleases_and_wildcards() {
        for input in [
            "1 - 2",
            "1.0 - 2.5",
            "1.2.3 - 2.0.0",
            "1.x - 2.x",
            "v1.2.3 - v2.0.0",
            "1.2.3-alpha+build - 2.0.0-beta",
            "1\t-\t2",
            "1 - 2 || >=3",
            "1 - =x",
            "=x - 1",
        ] {
            assert!(!has_invalid_range_token(input), "rejected {input:?}");
        }
    }

    #[test]
    fn wildcard_comparator_conjunctions_preserve_numeric_bounds() {
        for input in ["1 =x", "1 = x", "1 =X", "1 =*", "1 >=x"] {
            let range = r(input);
            assert!(range.matches(&v("1.0.0")), "rejected lower bound: {input}");
            assert!(range.matches(&v("1.9.9")), "rejected major range: {input}");
            assert!(!range.matches(&v("2.0.0")), "lost upper bound: {input}");
        }
    }

    #[test]
    fn hyphen_range_equality_prefixes_follow_npm_bounds() {
        for input in ["1 - =x", "1\t-\t=x", "1 - =x || 3", "v=1 - 2"] {
            let range = r(input);
            assert!(!range.matches(&v("0.9.9")), "lost lower bound: {input}");
            assert!(range.matches(&v("1.0.0")), "rejected lower bound: {input}");
            if !input.ends_with(" - 2") {
                assert!(
                    range.matches(&v("9.0.0")),
                    "lost wildcard upper bound: {input}"
                );
            }
        }
        let version_prefixed_upper = r("1 - v=2");
        assert!(version_prefixed_upper.matches(&v("2.9.9")));
        assert!(!version_prefixed_upper.matches(&v("3.0.0")));
        let range = r("=x - 1");
        assert!(range.matches(&v("0.0.0")));
        assert!(range.matches(&v("1.9.9")));
        assert!(!range.matches(&v("2.0.0")));
    }

    #[test]
    fn wildcard_comparator_disjunctions_preserve_empty_and_any_ranges() {
        let any = r("^1 || =x");
        assert!(any.matches(&v("0.0.0")));
        assert!(any.matches(&v("9.0.0")));
        assert!(!any.matches(&v("1.0.0-alpha")));

        let empty = r(">=1 <x");
        assert!(!empty.matches(&v("0.0.0")));
        assert!(!empty.matches(&v("1.0.0")));
        assert!(!empty.matches(&v("9.0.0")));
    }

    #[test]
    fn empty_wildcard_comparators_absorb_only_their_conjunction() {
        for input in [">=1 <x", ">=1 < x", ">x >=1", "> x >=1"] {
            let range = r(input);
            for version in ["0.0.0", "1.0.0", "3.0.0"] {
                assert!(!range.matches(&v(version)), "{input} matched {version}");
            }
        }
        for input in [">=1 <x || 3", "3 || > x >=1"] {
            let range = r(input);
            assert!(!range.matches(&v("1.0.0")), "{input}");
            assert!(range.matches(&v("3.0.0")), "{input}");
        }
    }

    #[test]
    fn hyphen_bounds_reject_operators_other_than_equality() {
        for input in [
            ">=1 - 2",
            "1 - <=2",
            "1 - ~x",
            "^1 - 2 || 3",
            ">=x - 1",
            "1 - <=x",
        ] {
            assert!(VersionReq::parse(input).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn spaced_equality_hyphen_bounds_preserve_disjunctions() {
        for input in ["1 - = x || 0", "0 || 1 - = x"] {
            let range = r(input);
            for version in ["0.0.0", "1.0.0", "9.0.0"] {
                assert!(range.matches(&v(version)), "{input} rejected {version}");
            }
        }
        let range = r("1 - = 2 || 4");
        assert!(range.matches(&v("2.9.9")));
        assert!(range.matches(&v("4.0.0")));
        assert!(!range.matches(&v("3.0.0")));
    }

    #[test]
    fn equality_hyphen_bounds_preserve_prereleases_and_metadata() {
        for input in [
            "1 - =2.0.0-beta",
            "1 - = 2.0.0-beta || 4",
            "1 - v=2.0.0-beta",
        ] {
            let range = r(input);
            assert!(range.matches(&v("2.0.0-alpha")), "{input}");
            assert!(range.matches(&v("2.0.0-beta")), "{input}");
            assert!(!range.matches(&v("2.0.0")), "{input}");
        }
        for input in ["1.0.0-alpha - =x", "1.0.0-alpha+build - = x || 3"] {
            let range = r(input);
            assert!(range.matches(&v("1.0.0-alpha")), "{input}");
            assert!(range.matches(&v("1.0.0")), "{input}");
            assert!(range.matches(&v("9.0.0")), "{input}");
        }
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
