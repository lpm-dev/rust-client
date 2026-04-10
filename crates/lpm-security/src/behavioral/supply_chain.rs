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
    /// Obfuscation confidence score (0.0–1.0). Added in Phase 31.
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

// ── Telemetry SDK detection ───────────────────────────────────

/// Known telemetry/analytics SDK import patterns.
fn telemetry_patterns() -> &'static RegexSet {
    static INSTANCE: OnceLock<RegexSet> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        RegexSet::new([
            r#"["'](?:@?segment(?:/analytics-node)?|analytics-node)["']"#,
            r#"["']mixpanel["']"#,
            r#"["']posthog-node["']"#,
            r#"["'](?:@amplitude/node|amplitude)["']"#,
            r#"["']keen-tracking["']"#,
            r#"["']countly-sdk-nodejs["']"#,
            r"\bnavigator\.sendBeacon\s*\(",
            r#"\bnew\s+Image\s*\(\s*\)\s*\.src\s*=\s*["']https?://"#,
        ])
        .expect("telemetry patterns must compile")
    })
}

// ── Obfuscation detection ─────────────────────────────────────

/// Signals indicating obfuscated code. Any 2+ signals = obfuscated.
fn obfuscation_patterns() -> &'static RegexSet {
    static INSTANCE: OnceLock<RegexSet> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        RegexSet::new([
            // Signal 0: Hex escape sequences in string literals (>= 5 occurrences suggests obfuscation)
            r"\\x[0-9a-fA-F]{2}",
            // Signal 1: Obfuscator-style variable names (_0x followed by hex digits)
            r"\b_0x[0-9a-f]{4,}\b",
            // Signal 2: String construction from char codes
            r"String\.fromCharCode\s*\(",
            // Signal 3: Buffer.from with base64 decoding
            r#"Buffer\.from\s*\([^)]*["']base64["']"#,
        ])
        .expect("obfuscation patterns must compile")
    })
}

/// Obfuscation confidence score (0.0–1.0).
///
/// Replaces the old boolean `detect_obfuscation` with a graduated score
/// that accounts for signal density and minification context:
///
/// - **< 0.3** — not flagged (legitimate minified/compiled code)
/// - **0.3–0.7** — flagged as info (possible obfuscation, likely compiled output)
/// - **> 0.7** — flagged as critical (high-confidence deliberate obfuscation)
///
/// Factors:
/// - Signal density (per 1000 lines) instead of raw counts
/// - Dispatcher pattern presence (array + rotation + indexed access)
/// - File is minified → signals suppressed (minified code naturally has short vars)
/// - Number of distinct signal types (2+ required)
pub fn obfuscation_confidence(stripped: &str, is_minified: bool) -> f64 {
    let patterns = obfuscation_patterns();
    let matches = patterns.matches(stripped);

    let line_count = stripped.lines().count().max(1);
    let per_1k = 1000.0 / line_count as f64;

    let mut score = 0.0_f64;
    let mut signal_types = 0u32;

    // Signal 0: hex escapes — density-based threshold
    if matches.matched(0) {
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
    if matches.matched(1) {
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
    if matches.matched(2) {
        let count = stripped.matches("String.fromCharCode").count();
        let density = count as f64 * per_1k;
        let threshold = if is_minified { 10.0 } else { 5.0 };
        if density > threshold {
            signal_types += 1;
            score += (density / threshold).min(2.0) * 0.15;
        }
    }

    // Signal 3: Buffer.from base64
    if matches.matched(3) {
        signal_types += 1;
        score += 0.1;
    }

    // Dispatcher pattern: large string array + rotation function + indexed access.
    // This is the hallmark of javascript-obfuscator / obfuscator.io output.
    let has_dispatcher = detect_dispatcher_pattern(stripped);
    if has_dispatcher {
        signal_types += 1;
        score += 0.5; // Strong signal — this pattern is almost exclusively malicious
    }

    // Require 2+ independent signal types (same as before, but graduated)
    if signal_types < 2 && !has_dispatcher {
        return 0.0;
    }

    // Minified files get a penalty — obfuscation signals in minified code
    // are much more likely to be false positives from UglifyJS/Terser
    if is_minified {
        score *= 0.4;
    }

    score.min(1.0)
}

/// Regex for _0x variable names (compiled once).
fn _0x_var_regex() -> &'static Regex {
    static INSTANCE: OnceLock<Regex> = OnceLock::new();
    INSTANCE.get_or_init(|| Regex::new(r"\b_0x[0-9a-f]{4,}\b").expect("_0x regex must compile"))
}

/// Detect the classic dispatcher pattern used by javascript-obfuscator:
///
/// 1. A large array of string literals assigned to a `_0x` variable
/// 2. A rotation/shuffle function that rearranges the array
/// 3. Indexed access into the array via function call: `_0x1234(0x56)`
///
/// This pattern is almost exclusively produced by obfuscation tools and
/// is NOT generated by legitimate minifiers.
fn detect_dispatcher_pattern(stripped: &str) -> bool {
    // Check 1: _0x array declaration with string elements
    // Pattern: var _0xHEX = ["...", "...", ...]  or  const _0xHEX = [...]
    let has_array = _0x_var_regex().is_match(stripped)
        && (stripped.contains("=[\"") || stripped.contains("=['"))
        && {
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

// ── Protestware detection ─────────────────────────────────────

/// Compiled protestware pattern set.
fn protestware_patterns() -> &'static RegexSet {
    static INSTANCE: OnceLock<RegexSet> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        RegexSet::new([
			// process.exit near locale/timezone/IP conditional
            r"(?:Intl\.DateTimeFormat|resolvedOptions\(\)\.(?:timeZone|locale)|os\.networkInterfaces)[\s\S]{0,200}process\.exit",
            r"process\.exit[\s\S]{0,200}(?:Intl\.DateTimeFormat|resolvedOptions\(\)\.(?:timeZone|locale)|os\.networkInterfaces)",
			// Infinite loop pattern (colors@1.4.1 style)
			r"for\s*\(\s*let\s+\w+\s*=.*Infinity",
			r"while\s*\(\s*true\s*\)[\s\S]{0,50}replace",
		])
		.expect("protestware patterns must compile")
    })
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
        let lower = literal.to_lowercase();
        if exclusions.is_match(&lower) {
            continue;
        }

        let entropy = shannon_entropy(literal.as_bytes());
        if entropy > 4.5 {
            return true;
        }
    }

    false
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
    let is_minified = detect_minified(raw_content);
    let confidence = obfuscation_confidence(stripped, is_minified);

    SupplyChainTags {
        obfuscated: confidence > 0.3,
        high_entropy_strings: detect_high_entropy(stripped),
        minified: is_minified,
        telemetry: telemetry_patterns().is_match(stripped),
        url_strings: url_regex().is_match(stripped),
        trivial: false, // Set at package level, not file level
        protestware: protestware_patterns().is_match(stripped),
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
        assert!(telemetry_patterns().is_match(code));
    }

    #[test]
    fn detect_mixpanel_require() {
        let code = r#"const mp = require("mixpanel")"#;
        assert!(telemetry_patterns().is_match(code));
    }

    #[test]
    fn detect_send_beacon() {
        let code = "navigator.sendBeacon('/analytics', data)";
        assert!(telemetry_patterns().is_match(code));
    }

    #[test]
    fn no_false_positive_analytics_word() {
        let code = "const analytics = { track() {} }";
        assert!(!telemetry_patterns().is_match(code));
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

    // ── Protestware ───────────────────────────────────────────

    #[test]
    fn detect_locale_exit_pattern() {
        let code = r#"
			if (Intl.DateTimeFormat().resolvedOptions().timeZone === 'Europe/Moscow') {
				process.exit(1)
			}
		"#;
        assert!(protestware_patterns().is_match(code));
    }

    #[test]
    fn detect_infinite_loop_pattern() {
        let code = "for (let i = 666; i < Infinity; i++) { console.log(i) }";
        assert!(protestware_patterns().is_match(code));
    }

    #[test]
    fn no_false_positive_normal_locale() {
        // Normal i18n code shouldn't trigger
        let code = "const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;";
        assert!(!protestware_patterns().is_match(code));
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
            protestware_patterns().is_match(code),
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
            !protestware_patterns().is_match(code),
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
            !protestware_patterns().is_match(code),
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
    fn minified_file_suppresses_obfuscation() {
        // This pattern would trigger obfuscation in a normal file,
        // but should be suppressed when the file is minified.
        let code = r#"
            var _0x1a2b = "\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64";
            var _0x3c4d = _0x1a2b;
        "#;
        // Normal: should detect as obfuscated
        let normal_conf = obfuscation_confidence(code, false);
        assert!(
            normal_conf > 0.3,
            "non-minified should detect obfuscation, got {normal_conf}"
        );

        // Minified: should have lower confidence (suppressed)
        let minified_conf = obfuscation_confidence(code, true);
        assert!(
            minified_conf < normal_conf,
            "minified confidence ({minified_conf}) should be lower than normal ({normal_conf})"
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
