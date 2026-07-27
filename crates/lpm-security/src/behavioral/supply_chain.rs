//! Supply chain & code quality tag detection (7 tags).
//!
//! Detects patterns beyond API usage: obfuscation, high-entropy strings,
//! minified code, telemetry SDKs, URL literals, trivial packages, and
//! protestware patterns.
//!
//! SECURITY: All patterns use the `regex` crate (linear-time).

use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Supply chain behavioral tags — new, from Socket gap analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SupplyChainTags {
    pub obfuscated: bool,
    pub high_entropy_strings: bool,
    pub minified: bool,
    pub telemetry: bool,
    pub url_strings: bool,
    pub trivial: bool,
    pub protestware: bool,
    /// Obfuscation confidence score (0.0–1.0).
    /// - < 0.3: not obfuscated
    /// - 0.3–0.7: possible obfuscation (likely compiled/minified output)
    /// - > 0.7: high-confidence deliberate obfuscation
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub obfuscation_confidence: f64,
}

fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}

/// Metadata collected during supply chain analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupplyChainMeta {
    /// Unique domains extracted from URL strings in source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url_domains: Vec<String>,
}

const OBF_HEX_ESCAPES: usize = 0;
const OBF_VAR_NAMES: usize = 1;
const OBF_FROM_CHAR_CODE: usize = 2;
const OBF_BUFFER_BASE64: usize = 3;
const TELEMETRY_START: usize = 4;
const TELEMETRY_END: usize = 12;
const PROTESTWARE_START: usize = 12;
const PROTESTWARE_END: usize = 16;

fn supply_patterns() -> &'static [Regex] {
    static INSTANCE: OnceLock<Vec<Regex>> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        [
            r"\\x[0-9a-fA-F]{2}",
            r"\b_0x[0-9a-f]{4,}\b",
            r"String\.fromCharCode\s*\(",
            r#"Buffer\.from\s*\([^)]*["']base64["']"#,
            r#"["'](?:@?segment(?:/analytics-node)?|analytics-node)["']"#,
            r#"["']mixpanel["']"#,
            r#"["']posthog-node["']"#,
            r#"["'](?:@amplitude/node|amplitude)["']"#,
            r#"["']keen-tracking["']"#,
            r#"["']countly-sdk-nodejs["']"#,
            r"\bnavigator\.sendBeacon\s*\(",
            r#"\bnew\s+Image\s*\(\s*\)\s*\.src\s*=\s*["']https?://"#,
            r"(?:Intl\.DateTimeFormat|resolvedOptions\(\)\.(?:timeZone|locale)|os\.networkInterfaces)[\s\S]{0,200}process\.exit",
            r"process\.exit[\s\S]{0,200}(?:Intl\.DateTimeFormat|resolvedOptions\(\)\.(?:timeZone|locale)|os\.networkInterfaces)",
            r"for\s*\(\s*let\s+\w+\s*=.*Infinity",
            r"while\s*\(\s*true\s*\)[\s\S]{0,50}replace",
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("supply-chain pattern must compile"))
        .collect()
    })
}

#[derive(Debug, Clone, Copy)]
struct SupplyPatternSummary {
    obfuscation: [bool; 4],
    telemetry: bool,
    protestware: bool,
}

fn supply_pattern_summary(stripped: &str) -> SupplyPatternSummary {
    let patterns = supply_patterns();
    SupplyPatternSummary {
        obfuscation: [
            patterns[OBF_HEX_ESCAPES].is_match(stripped),
            patterns[OBF_VAR_NAMES].is_match(stripped),
            patterns[OBF_FROM_CHAR_CODE].is_match(stripped),
            patterns[OBF_BUFFER_BASE64].is_match(stripped),
        ],
        telemetry: patterns[TELEMETRY_START..TELEMETRY_END]
            .iter()
            .any(|pattern| pattern.is_match(stripped)),
        protestware: patterns[PROTESTWARE_START..PROTESTWARE_END]
            .iter()
            .any(|pattern| pattern.is_match(stripped)),
    }
}

// ── Obfuscation detection ─────────────────────────────────────

/// Obfuscation confidence score (0.0–1.0).
///
/// Replaces the old boolean `detect_obfuscation` with a graduated score
/// that accounts for signal density:
///
/// - **< 0.3** — not flagged (legitimate minified/compiled code)
/// - **0.3–0.7** — flagged as info (possible obfuscation, likely compiled output)
/// - **> 0.7** — flagged as critical (high-confidence deliberate obfuscation)
///
/// Factors:
/// - Signal density (per 1000 lines) instead of raw counts
/// - Dispatcher pattern presence (array + rotation + indexed access)
/// - File is minified → density thresholds are higher, but obfuscation is not suppressed
/// - Number of distinct signal types (2+ required)
pub fn obfuscation_confidence(stripped: &str, is_minified: bool) -> f64 {
    obfuscation_confidence_with_summary(stripped, is_minified, supply_pattern_summary(stripped))
}

fn obfuscation_confidence_with_summary(
    stripped: &str,
    is_minified: bool,
    patterns: SupplyPatternSummary,
) -> f64 {
    let line_count = source_line_count(stripped);
    let per_1k = 1000.0 / line_count as f64;

    let mut score = 0.0_f64;
    let mut signal_types = 0u32;

    // Signal 0: hex escapes — density-based threshold
    if patterns.obfuscation[OBF_HEX_ESCAPES] {
        let hex_count = stripped.matches("\\x").count();
        let density = hex_count as f64 * per_1k;
        // Threshold: >5 per 1000 lines for normal files, >20 for minified
        let threshold = if is_minified { 20.0 } else { 5.0 };
        if density > threshold {
            signal_types += 1;
            score += (density / threshold).min(2.0) * 0.15;
        }
    }

    // Signal 1: _0x style variable names — density-based
    if patterns.obfuscation[OBF_VAR_NAMES] {
        let re = _0x_var_regex();
        let count = re.find_iter(stripped).count();
        let density = count as f64 * per_1k;
        // Threshold: >5 per 1000 lines for normal, >15 for minified
        let threshold = if is_minified { 15.0 } else { 5.0 };
        if density > threshold {
            signal_types += 1;
            score += (density / threshold).min(2.0) * 0.2;
        }
    }

    // Signal 2: String.fromCharCode — density-based
    if patterns.obfuscation[OBF_FROM_CHAR_CODE] {
        let count = stripped.matches("String.fromCharCode").count();
        let density = count as f64 * per_1k;
        let threshold = if is_minified { 10.0 } else { 5.0 };
        if density > threshold {
            signal_types += 1;
            score += (density / threshold).min(2.0) * 0.15;
        }
    }

    // Signal 3: Buffer.from base64
    if patterns.obfuscation[OBF_BUFFER_BASE64] {
        signal_types += 1;
        score += 0.1;
    }

    // Dispatcher pattern: large string array + rotation function + indexed access.
    // This is the hallmark of javascript-obfuscator / obfuscator.io output.
    let has_dispatcher =
        detect_dispatcher_pattern_with_var_names(stripped, patterns.obfuscation[OBF_VAR_NAMES]);
    if has_dispatcher {
        signal_types += 1;
        score += 0.5; // Strong signal — this pattern is almost exclusively malicious
    }

    // Require 2+ independent signal types (same as before, but graduated)
    if signal_types < 2 && !has_dispatcher {
        return 0.0;
    }

    score.min(1.0)
}

fn source_line_count(source: &str) -> usize {
    let newline_count = bytecount::count(source.as_bytes(), b'\n');
    (newline_count + usize::from(!source.is_empty() && !source.ends_with('\n'))).max(1)
}

/// Regex for _0x variable names (compiled once).
fn _0x_var_regex() -> &'static Regex {
    &supply_patterns()[OBF_VAR_NAMES]
}

/// Detect the classic dispatcher pattern used by javascript-obfuscator:
///
/// 1. A large array of string literals assigned to a `_0x` variable
/// 2. A rotation/shuffle function that rearranges the array
/// 3. Indexed access into the array via function call: `_0x1234(0x56)`
///
/// This pattern is almost exclusively produced by obfuscation tools and
/// is NOT generated by legitimate minifiers.
#[cfg(test)]
fn detect_dispatcher_pattern(stripped: &str) -> bool {
    detect_dispatcher_pattern_with_var_names(stripped, _0x_var_regex().is_match(stripped))
}

fn detect_dispatcher_pattern_with_var_names(stripped: &str, has_0x_var_names: bool) -> bool {
    // Check 1: _0x array declaration with string elements
    // Pattern: var _0xHEX = ["...", "...", ...]  or  const _0xHEX = [...]
    let has_array =
        has_0x_var_names && (stripped.contains("=[\"") || stripped.contains("=['")) && {
            // Multiple string elements (double or single quoted)
            stripped.contains("\",\"") || stripped.contains("','")
        };

    if !has_array {
        return false;
    }

    // Check 2: function-call indexed access like _0xNNNN(0xNN)
    // This is the decoder function call pattern
    static INDEXED_ACCESS: OnceLock<Regex> = OnceLock::new();
    let indexed = INDEXED_ACCESS.get_or_init(|| {
        Regex::new(r"\b_0x[0-9a-f]{4,}\s*\(\s*0x[0-9a-f]+\s*\)").expect("indexed access regex")
    });

    indexed.is_match(stripped)
}

/// Legacy boolean detection — returns true when confidence > 0.3.
///
/// Wraps `obfuscation_confidence` for backward compatibility.
pub fn detect_obfuscation(stripped: &str) -> bool {
    obfuscation_confidence(stripped, false) > 0.3
}

// ── URL extraction ────────────────────────────────────────────

/// Compiled URL pattern for extracting domains from source.
fn url_regex() -> &'static Regex {
    static INSTANCE: OnceLock<Regex> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        Regex::new(r"https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)")
            .expect("URL regex must compile")
    })
}

/// Extract unique domains from URL strings in source code.
pub fn extract_url_domains(stripped: &str) -> Vec<String> {
    let re = url_regex();
    let mut domains: Vec<String> = re
        .captures_iter(stripped)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();

    domains.sort_unstable();
    domains.dedup();
    domains
}

// ── Shannon entropy ───────────────────────────────────────────

/// Compute Shannon entropy of a byte slice.
///
/// Returns bits per byte (0.0 to 8.0). Higher values indicate more randomness.
/// API keys, encrypted blobs, and encoded payloads typically have entropy > 4.5.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Regex for known high-entropy exclusions (UUIDs, hex hashes, data URIs, semver).
fn entropy_exclusion_regex() -> &'static RegexSet {
    static INSTANCE: OnceLock<RegexSet> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        RegexSet::new([
            // UUID
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            // Hex hash (MD5, SHA-1, SHA-256, SHA-512)
            r"^[0-9a-f]{32,128}$",
            // Base64 data URI
            r"^data:[a-zA-Z]+/[a-zA-Z0-9.+-]+;base64,",
            // Semver range
            r"^[\d.^~>=<|x* -]+$",
            // File path
            r"^[./\\]",
        ])
        .expect("entropy exclusion patterns must compile")
    })
}

/// Extract string literals from source and check for high-entropy content.
///
/// Uses a two-pass approach:
/// 1. Fast pre-filter: skip files with no long strings
/// 2. Targeted extraction: compute entropy on strings > 30 chars
pub fn detect_high_entropy(stripped: &str) -> bool {
    // Fast pre-filter: does the source have any string > 30 chars?
    if !has_long_string_literals(stripped, 30) {
        return false;
    }

    let exclusions = entropy_exclusion_regex();

    // Extract string literals and check entropy
    for literal in extract_string_literals(stripped) {
        if literal.len() < 30 {
            continue;
        }

        // Skip known high-entropy formats
        if entropy_exclusion_matches(exclusions, literal) {
            continue;
        }

        let entropy = shannon_entropy(literal.as_bytes());
        if entropy > 4.5 {
            return true;
        }
    }

    false
}

fn entropy_exclusion_matches(exclusions: &RegexSet, literal: &str) -> bool {
    if exclusions.is_match(literal) {
        return true;
    }
    if literal.is_ascii() && !literal.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return false;
    }
    exclusions.is_match(&literal.to_lowercase())
}

/// Fast check: does the source contain any string literal longer than `min_len` chars?
fn has_long_string_literals(src: &str, min_len: usize) -> bool {
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            let quote = b;
            let start = i + 1;
            i += 1;
            while i < len {
                if bytes[i] == b'\\' {
                    i += 2; // skip escaped char
                    continue;
                }
                if bytes[i] == quote {
                    if i - start >= min_len {
                        return true;
                    }
                    break;
                }
                i += 1;
            }
        }
        i += 1;
    }

    false
}

/// Extract string literal contents from source code.
///
/// Handles `"..."` and `'...'` strings. Skips template literals (too complex
/// to reliably extract from). Returns the inner content of each string.
fn extract_string_literals(src: &str) -> Vec<&str> {
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut literals = Vec::new();
    let mut i = 0;

    while i < len {
        let b = bytes[i];
        if b == b'"' || b == b'\'' {
            let quote = b;
            let start = i + 1;
            i += 1;
            let mut has_escape = false;
            while i < len {
                if bytes[i] == b'\\' {
                    has_escape = true;
                    i += 2;
                    continue;
                }
                if bytes[i] == quote {
                    // Only return literals without escapes for accurate entropy
                    if !has_escape && i > start {
                        literals.push(&src[start..i]);
                    }
                    break;
                }
                i += 1;
            }
        }
        i += 1;
    }

    literals
}

// ── Minified code detection ───────────────────────────────────

/// Check if source content is minified.
///
/// Criteria:
/// - Single-line file > 10KB (one giant line = minified/bundled)
/// - Average line length > 500 chars across the file
///
/// Also checks filename pattern: `.min.js` files are always minified.
pub fn detect_minified(content: &[u8]) -> bool {
    if content.is_empty() {
        return false;
    }

    let newline_count = bytecount::count(content, b'\n');

    // Single giant line > 10KB
    if newline_count <= 3 && content.len() > 10_240 {
        return true;
    }

    // Average line length > 500 chars
    if newline_count > 0 {
        let avg_line_len = content.len() / (newline_count + 1);
        if avg_line_len > 500 {
            return true;
        }
    }

    false
}

/// Check if a filename indicates minified code.
pub fn is_minified_filename(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    lower.ends_with(".min.js")
        || lower.ends_with(".min.cjs")
        || lower.ends_with(".min.mjs")
        || lower.ends_with(".bundle.js")
}

// ── Trivial package detection ─────────────────────────────────

/// Result of trivial package analysis.
pub struct TrivialAnalysis {
    pub total_code_lines: usize,
    pub export_count: usize,
}

/// Count non-empty, non-comment lines and exports in source text.
pub fn analyze_trivial(stripped: &str) -> TrivialAnalysis {
    let mut code_lines = 0usize;
    let mut export_count = 0usize;

    for line in stripped.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            code_lines += 1;
        }
        // Count exports
        if trimmed.starts_with("module.exports")
            || trimmed.starts_with("exports.")
            || trimmed.starts_with("export default")
            || trimmed.starts_with("export {")
            || trimmed.starts_with("export function")
            || trimmed.starts_with("export const")
            || trimmed.starts_with("export class")
        {
            export_count += 1;
        }
    }

    TrivialAnalysis {
        total_code_lines: code_lines,
        export_count,
    }
}

// ── Aggregated analysis ───────────────────────────────────────

/// Analyze source text for all 7 supply chain tags.
///
/// Takes already-stripped source content. `raw_content` is the original
/// file content before comment stripping (needed for minification detection).
pub fn analyze_supply_chain(stripped: &str, raw_content: &[u8]) -> SupplyChainTags {
    analyze_supply_chain_with_url_presence(stripped, raw_content, url_regex().is_match(stripped))
}

pub(crate) fn analyze_supply_chain_with_url_presence(
    stripped: &str,
    raw_content: &[u8],
    has_url_strings: bool,
) -> SupplyChainTags {
    let patterns = supply_pattern_summary(stripped);
    let is_minified = detect_minified(raw_content);
    let confidence = obfuscation_confidence_with_summary(stripped, is_minified, patterns);

    SupplyChainTags {
        obfuscated: confidence > 0.3,
        high_entropy_strings: detect_high_entropy(stripped),
        minified: is_minified,
        telemetry: patterns.telemetry,
        url_strings: has_url_strings,
        trivial: false, // Set at package level, not file level
        protestware: patterns.protestware,
        obfuscation_confidence: confidence,
    }
}

/// Merge two SupplyChainTags with OR logic.
pub fn merge_supply_chain_tags(a: &SupplyChainTags, b: &SupplyChainTags) -> SupplyChainTags {
    let confidence = a.obfuscation_confidence.max(b.obfuscation_confidence);
    SupplyChainTags {
        obfuscated: confidence > 0.3,
        high_entropy_strings: a.high_entropy_strings || b.high_entropy_strings,
        minified: a.minified || b.minified,
        telemetry: a.telemetry || b.telemetry,
        url_strings: a.url_strings || b.url_strings,
        trivial: a.trivial || b.trivial,
        protestware: a.protestware || b.protestware,
        obfuscation_confidence: confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_line_count_matches_str_lines_semantics() {
        for source in ["", "a", "\n", "a\n", "a\nb", "a\nb\n", "\r\n", "a\r\nb\r\n"] {
            assert_eq!(
                source_line_count(source),
                source.lines().count().max(1),
                "line count changed for {source:?}"
            );
        }
    }

    // ── Shannon entropy ───────────────────────────────────────

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn entropy_uniform() {
        // All same byte = zero entropy
        assert!(shannon_entropy(b"aaaaaaaaaa") < 0.01);
    }

    #[test]
    fn entropy_high_random() {
        // A string that looks like a secret key
        let key = b"aK3mP9xR2vT8qL5nB7wF4jD6hG1cE0i";
        let e = shannon_entropy(key);
        assert!(
            e > 4.0,
            "random-looking string should have high entropy, got {e}"
        );
    }

    #[test]
    fn entropy_english_text() {
        let text = b"the quick brown fox jumps over the lazy dog";
        let e = shannon_entropy(text);
        // English text typically has entropy ~3.5-4.2
        assert!(
            e < 4.5,
            "english text should have moderate entropy, got {e}"
        );
    }

    // ── Obfuscation ───────────────────────────────────────────

    #[test]
    fn detect_obfuscated_code() {
        // 2 signals: _0x variable names + hex escapes
        let code = r#"
			var _0x1a2b = "\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64";
			var _0x3c4d = _0x1a2b;
		"#;
        assert!(detect_obfuscation(code));
    }

    #[test]
    fn no_false_positive_jquery() {
        // jQuery minified has short variable names but not _0x patterns
        let code = "function(a,b){return a.length?a.push(b):void 0}";
        assert!(!detect_obfuscation(code));
    }

    #[test]
    fn no_false_positive_single_hex_escape() {
        // A single hex escape in a regex or string is not obfuscation
        let code = r#"const re = /\x00/; const msg = "hello";"#;
        assert!(!detect_obfuscation(code));
    }

    #[test]
    fn detect_fromcharcode_obfuscation() {
        let code = r#"
			String.fromCharCode(72, 101, 108)
			String.fromCharCode(108, 111, 32)
			String.fromCharCode(87, 111, 114)
			var _0xabcd = "test"
		"#;
        assert!(detect_obfuscation(code));
    }

    // ── Minified code ─────────────────────────────────────────

    #[test]
    fn detect_minified_single_line() {
        // > 10KB on a single line
        let code = "a".repeat(11_000);
        assert!(detect_minified(code.as_bytes()));
    }

    #[test]
    fn detect_minified_long_avg_line() {
        // Lines averaging > 500 chars
        let line = "x".repeat(600);
        let code = format!("{line}\n{line}\n{line}");
        assert!(detect_minified(code.as_bytes()));
    }

    #[test]
    fn no_false_positive_normal_code() {
        let code = "const x = 1;\nconst y = 2;\nconst z = 3;\n";
        assert!(!detect_minified(code.as_bytes()));
    }

    #[test]
    fn is_min_js_filename() {
        assert!(is_minified_filename("jquery.min.js"));
        assert!(is_minified_filename("app.bundle.js"));
        assert!(!is_minified_filename("index.js"));
        assert!(!is_minified_filename("utils.ts"));
    }

    // ── Telemetry ─────────────────────────────────────────────

    #[test]
    fn detect_segment_import() {
        let code = r#"import analytics from "analytics-node""#;
        assert!(supply_pattern_summary(code).telemetry);
    }

    #[test]
    fn detect_mixpanel_require() {
        let code = r#"const mp = require("mixpanel")"#;
        assert!(supply_pattern_summary(code).telemetry);
    }

    #[test]
    fn detect_send_beacon() {
        let code = "navigator.sendBeacon('/analytics', data)";
        assert!(supply_pattern_summary(code).telemetry);
    }

    #[test]
    fn no_false_positive_analytics_word() {
        let code = "const analytics = { track() {} }";
        assert!(!supply_pattern_summary(code).telemetry);
    }

    #[test]
    fn supply_patterns_preserve_unicode_word_boundaries() {
        assert!(!supply_pattern_summary("é_0x1234").obfuscation[OBF_VAR_NAMES]);
        assert!(supply_pattern_summary("é _0x1234").obfuscation[OBF_VAR_NAMES]);
    }

    // ── URL strings ───────────────────────────────────────────

    #[test]
    fn extract_urls() {
        let code =
            r#"const url = "https://api.example.com/v1"; fetch("https://cdn.example.com/file")"#;
        let domains = extract_url_domains(code);
        assert_eq!(domains, vec!["api.example.com", "cdn.example.com"]);
    }

    #[test]
    fn extract_urls_deduplicates() {
        let code = r#"fetch("https://api.example.com/a"); fetch("https://api.example.com/b")"#;
        let domains = extract_url_domains(code);
        assert_eq!(domains, vec!["api.example.com"]);
    }

    // ── High entropy strings ──────────────────────────────────

    #[test]
    fn detect_high_entropy_secret() {
        let code = r#"const key = "aK3mP9xR2vT8qL5nB7wF4jD6hG1cE0iaK3m""#;
        assert!(detect_high_entropy(code));
    }

    #[test]
    fn no_false_positive_uuid() {
        let code = r#"const id = "550e8400-e29b-41d4-a716-446655440000""#;
        assert!(!detect_high_entropy(code));
    }

    #[test]
    fn no_false_positive_hex_hash() {
        let code = r#"const hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4""#;
        assert!(!detect_high_entropy(code));
    }

    #[test]
    fn no_false_positive_short_string() {
        let code = r#"const msg = "hello world""#;
        assert!(!detect_high_entropy(code));
    }

    #[test]
    fn entropy_exclusions_preserve_case_insensitive_matching() {
        let exclusions = entropy_exclusion_regex();
        assert!(entropy_exclusion_matches(
            exclusions,
            "550E8400-E29B-41D4-A716-446655440000"
        ));
        assert!(entropy_exclusion_matches(
            exclusions,
            "data:image/png;base64,ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ));
        assert!(!entropy_exclusion_matches(
            exclusions,
            "aK3mP9xR2vT8qL5nB7wF4jD6hG1cE0i"
        ));
    }

    // ── Protestware ───────────────────────────────────────────

    #[test]
    fn detect_locale_exit_pattern() {
        let code = r#"
			if (Intl.DateTimeFormat().resolvedOptions().timeZone === 'Europe/Moscow') {
				process.exit(1)
			}
		"#;
        assert!(supply_pattern_summary(code).protestware);
    }

    #[test]
    fn detect_infinite_loop_pattern() {
        let code = "for (let i = 666; i < Infinity; i++) { console.log(i) }";
        assert!(supply_pattern_summary(code).protestware);
    }

    #[test]
    fn no_false_positive_normal_locale() {
        // Normal i18n code shouldn't trigger
        let code = "const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;";
        assert!(!supply_pattern_summary(code).protestware);
    }

    // ── Trivial package ───────────────────────────────────────

    #[test]
    fn detect_trivial() {
        let code = "module.exports = (a, b) => a + b;\n";
        let analysis = analyze_trivial(code);
        assert_eq!(analysis.total_code_lines, 1);
        assert_eq!(analysis.export_count, 1);
        assert!(analysis.total_code_lines < 10 && analysis.export_count <= 1);
    }

    #[test]
    fn not_trivial_normal_package() {
        let code = (0..50)
            .map(|i| format!("export const fn{i} = () => {i};"))
            .collect::<Vec<_>>()
            .join("\n");
        let analysis = analyze_trivial(&code);
        assert!(analysis.total_code_lines >= 10);
    }

    // ── Protestware: colors@1.4.1 pattern (Infinity loop) ───────

    #[test]
    fn detect_colors_infinity_loop_pattern() {
        // colors@1.4.1 added: for (let i = 0; i < Infinity; i++) { ... }
        // triggered by locale/timezone check before the loop
        let code = r#"
			const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
			if (tz === "America/New_York") {
				for (let i = 0; i < Infinity; i++) {
					console.log("LIBERTY LIBERTY LIBERTY");
				}
			}
		"#;
        assert!(
            supply_pattern_summary(code).protestware,
            "colors@1.4.1 Infinity loop pattern should be detected"
        );
    }

    // ── Protestware: normal i18n locale check (NOT protestware) ──

    #[test]
    fn no_false_positive_i18n_locale() {
        // Normal i18n library that checks locale for formatting — no process.exit
        let code = r#"
			const locale = Intl.DateTimeFormat().resolvedOptions().locale;
			const formatter = new Intl.NumberFormat(locale, { style: 'currency' });
			export function formatPrice(amount) {
				return formatter.format(amount);
			}
		"#;
        assert!(
            !supply_pattern_summary(code).protestware,
            "normal i18n locale usage must NOT be flagged as protestware"
        );
    }

    #[test]
    fn no_false_positive_generic_locale_property_with_exit() {
        let code = r#"
			const config = { locale: 'en-US' };
			if (!config.locale) {
				process.exit(1);
			}
		"#;
        assert!(
            !supply_pattern_summary(code).protestware,
            "generic locale properties near process.exit should not be flagged as protestware"
        );
    }

    // ── High entropy: base64 data URI excluded ───────────────────

    #[test]
    fn no_false_positive_base64_data_uri() {
        // data: URIs are excluded from high-entropy detection
        let code = r#"
			const icon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
		"#;
        let tags = analyze_supply_chain(code, code.as_bytes());
        assert!(
            !tags.high_entropy_strings,
            "base64 data URIs should be excluded from high-entropy detection"
        );
    }

    // ── Obfuscation confidence scoring ──────────────────────────

    #[test]
    fn minified_file_does_not_suppress_obfuscation() {
        // Minification raises density thresholds for noisy signals, but strong
        // obfuscation patterns must still be visible to the scanner.
        let code = r#"
            var _0x1a2b = "\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64";
            var _0x3c4d = _0x1a2b;
        "#;
        let normal_conf = obfuscation_confidence(code, false);
        assert!(
            normal_conf > 0.3,
            "non-minified should detect obfuscation, got {normal_conf}"
        );

        let minified_conf = obfuscation_confidence(code, true);
        assert!(
            minified_conf > 0.3,
            "minified confidence ({minified_conf}) should still detect obfuscation"
        );
    }

    #[test]
    fn dispatcher_pattern_detected() {
        // Classic javascript-obfuscator output pattern
        let code = r#"
            var _0x1234=['hello','world','foo','bar','baz','qux','test','data','key','val'];
            var _0x5678=function(_0xabcd,_0xef01){return _0x1234[_0xabcd];};
            console.log(_0x5678(0x0));
            console.log(_0x5678(0x1));
        "#;
        assert!(
            detect_dispatcher_pattern(code),
            "classic dispatcher pattern should be detected"
        );
    }

    #[test]
    fn no_false_positive_dispatcher_normal_array() {
        // Normal array usage should not trigger dispatcher pattern
        let code = r#"
            const colors = ["red","green","blue"];
            console.log(colors[0]);
        "#;
        assert!(
            !detect_dispatcher_pattern(code),
            "normal array should not trigger dispatcher pattern"
        );
    }

    #[test]
    fn confidence_score_ranges() {
        // No signals → 0.0
        let clean = "const x = 1;\nconst y = 2;\n";
        assert_eq!(obfuscation_confidence(clean, false), 0.0);

        // Dispatcher pattern → high confidence
        let dispatcher = r#"
            var _0x1234=["a","b","c","d","e","f","g","h","i","j"];
            function _0xdecoder(_0xarg){return _0x1234[_0xarg];}
            var x=_0xdecoder(0x0);var y=_0xdecoder(0x1);
            var _0xabcd="\x48\x65\x6c\x6c\x6f\x20";
        "#;
        let high = obfuscation_confidence(dispatcher, false);
        assert!(
            high > 0.5,
            "dispatcher pattern should give high confidence, got {high}"
        );
    }

    #[test]
    fn dispatcher_only_pattern_still_scores_as_obfuscated() {
        let dispatcher_only = r#"
            var _0x1234=['hello','world','foo','bar','baz','qux','test','data','key','val'];
            function _0x5678(_0xabcd){return _0x1234[_0xabcd];}
            console.log(_0x5678(0x0));
        "#;

        let confidence = obfuscation_confidence(dispatcher_only, false);
        assert!(
            confidence > 0.3,
            "dispatcher-only obfuscation should still cross the detection threshold, got {confidence}"
        );
    }

    #[test]
    fn analyze_supply_chain_stores_confidence() {
        let code = r#"
            var _0x1a2b = "\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64";
            var _0x3c4d = _0x1a2b;
        "#;
        let tags = analyze_supply_chain(code, code.as_bytes());
        assert!(tags.obfuscation_confidence > 0.0);
        assert_eq!(tags.obfuscated, tags.obfuscation_confidence > 0.3);
    }
}
