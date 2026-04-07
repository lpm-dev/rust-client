//! Secret detection in source code and configuration files.
//!
//! Detects hardcoded API keys, tokens, private keys, and other secrets
//! using known format patterns. Used by:
//! - `lpm publish` — pre-publish scan blocks upload if secrets found
//! - `lpm audit --secrets` — scans installed packages for leaked credentials
//!
//! Pattern matching uses `RegexSet` (compiled once, thread-safe) for
//! linear-time multi-pattern scanning against untrusted input.

use regex::RegexSet;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// A single secret detection match.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretMatch {
    /// The pattern name that matched (e.g., "stripe_live_key").
    pub pattern_name: String,
    /// Human-readable description (e.g., "Stripe live secret key").
    pub description: String,
    /// The matched text (truncated for display — first 8 + last 4 chars).
    pub matched_text: String,
    /// Line number where the match was found (1-based).
    pub line: usize,
    /// Severity: "critical" (live keys), "high" (test keys), "medium" (generic patterns).
    pub severity: String,
}

/// Result of secret scanning across a package or set of files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretScanResult {
    /// All matches found.
    pub matches: Vec<SecretMatch>,
    /// Number of files scanned.
    pub files_scanned: usize,
}

impl SecretScanResult {
    pub fn has_secrets(&self) -> bool {
        !self.matches.is_empty()
    }

    pub fn critical_count(&self) -> usize {
        self.matches
            .iter()
            .filter(|m| m.severity == "critical")
            .count()
    }

    pub fn high_count(&self) -> usize {
        self.matches.iter().filter(|m| m.severity == "high").count()
    }

    pub fn merge(&mut self, other: &SecretScanResult) {
        self.matches.extend(other.matches.iter().cloned());
        self.files_scanned += other.files_scanned;
    }
}

/// Known secret patterns with their metadata.
///
/// Each tuple: (regex_pattern, pattern_name, description, severity)
const SECRET_PATTERNS: &[(&str, &str, &str, &str)] = &[
    // ── Stripe ──
    (
        r"sk_live_[a-zA-Z0-9]{20,}",
        "stripe_live_secret",
        "Stripe live secret key",
        "critical",
    ),
    (
        r"sk_test_[a-zA-Z0-9]{20,}",
        "stripe_test_secret",
        "Stripe test secret key",
        "high",
    ),
    (
        r"rk_live_[a-zA-Z0-9]{20,}",
        "stripe_live_restricted",
        "Stripe live restricted key",
        "critical",
    ),
    (
        r"rk_test_[a-zA-Z0-9]{20,}",
        "stripe_test_restricted",
        "Stripe test restricted key",
        "high",
    ),
    (
        r"whsec_[a-zA-Z0-9]{20,}",
        "stripe_webhook_secret",
        "Stripe webhook signing secret",
        "high",
    ),
    // ── GitHub ──
    (
        r"ghp_[a-zA-Z0-9]{36,}",
        "github_pat",
        "GitHub personal access token",
        "critical",
    ),
    (
        r"gho_[a-zA-Z0-9]{36,}",
        "github_oauth",
        "GitHub OAuth access token",
        "critical",
    ),
    (
        r"ghu_[a-zA-Z0-9]{36,}",
        "github_user_token",
        "GitHub user-to-server token",
        "critical",
    ),
    (
        r"ghs_[a-zA-Z0-9]{36,}",
        "github_server_token",
        "GitHub server-to-server token",
        "critical",
    ),
    (
        r"github_pat_[a-zA-Z0-9]{22,}",
        "github_fine_grained",
        "GitHub fine-grained PAT",
        "critical",
    ),
    // ── AWS ──
    (
        r"AKIA[A-Z0-9]{16}",
        "aws_access_key",
        "AWS access key ID",
        "critical",
    ),
    (
        r#"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?[a-zA-Z0-9/+=]{40}"#,
        "aws_secret_key",
        "AWS secret access key",
        "critical",
    ),
    // ── Google ──
    (
        r"AIza[a-zA-Z0-9_-]{35}",
        "google_api_key",
        "Google API key",
        "high",
    ),
    // ── Twilio ──
    (
        r"SK[a-f0-9]{32}",
        "twilio_api_key",
        "Twilio API key",
        "high",
    ),
    // ── SendGrid ──
    (
        r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "sendgrid_api_key",
        "SendGrid API key",
        "critical",
    ),
    // ── Slack ──
    (
        r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}",
        "slack_bot_token",
        "Slack bot token",
        "critical",
    ),
    (
        r"xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}",
        "slack_user_token",
        "Slack user token",
        "critical",
    ),
    // ── Private Keys ──
    (
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        "private_key_rsa",
        "RSA private key",
        "critical",
    ),
    (
        r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
        "private_key_ec",
        "EC private key",
        "critical",
    ),
    (
        r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
        "private_key_openssh",
        "OpenSSH private key",
        "critical",
    ),
    // ── Supabase ──
    (
        r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{50,}",
        "supabase_service_key",
        "Supabase service role key (JWT)",
        "critical",
    ),
    // ── Vercel ──
    (
        r#"(?:VERCEL_TOKEN|vercel_token)\s*[=:]\s*["']?[a-zA-Z0-9]{24,}"#,
        "vercel_token",
        "Vercel API token",
        "high",
    ),
    // ── npm ──
    (
        r"npm_[a-zA-Z0-9]{36,}",
        "npm_token",
        "npm access token",
        "critical",
    ),
    // ── Generic high-value patterns ──
    (
        r#"(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{8,}"#,
        "generic_password",
        "Hardcoded password",
        "medium",
    ),
];

/// Filenames that should NEVER be in a published package.
const BLOCKED_FILES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".env.live",
    "credentials.json",
    "service-account.json",
    "gcloud-key.json",
];

/// Get the compiled RegexSet (singleton, thread-safe).
fn secret_regex_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| {
        let patterns: Vec<&str> = SECRET_PATTERNS.iter().map(|(p, _, _, _)| *p).collect();
        RegexSet::new(patterns).expect("failed to compile secret patterns")
    })
}

/// Scan a single source file for secrets.
///
/// Returns matches with line numbers. The `content` should be the raw file content
/// (NOT comment-stripped — secrets can appear in comments too, and we want to catch them).
pub fn scan_content(content: &str, file_path: &str) -> Vec<SecretMatch> {
    let set = secret_regex_set();
    let mut matches = Vec::new();

    // Check each line for pattern matches
    for (line_idx, line) in content.lines().enumerate() {
        let line_matches: Vec<usize> = set.matches(line).into_iter().collect();

        for pattern_idx in line_matches {
            let (_, name, desc, severity) = SECRET_PATTERNS[pattern_idx];

            // Extract the matched text for display (truncated)
            let matched_text = truncate_secret(line.trim());

            matches.push(SecretMatch {
                pattern_name: name.to_string(),
                description: format!("{desc} in {file_path}"),
                matched_text,
                line: line_idx + 1,
                severity: severity.to_string(),
            });
        }
    }

    matches
}

/// Check if a filename is a blocked .env or credentials file.
pub fn is_blocked_file(filename: &str) -> bool {
    let name = filename.rsplit('/').next().unwrap_or(filename);
    let name = name.rsplit('\\').next().unwrap_or(name);
    BLOCKED_FILES.iter().any(|b| name.eq_ignore_ascii_case(b))
}

/// Truncate a secret value for safe display: show first 8 and last 4 chars.
fn truncate_secret(value: &str) -> String {
    if value.len() > 20 {
        let start = &value[..8];
        let end = &value[value.len() - 4..];
        format!("{start}...{end}")
    } else if value.len() > 12 {
        let start = &value[..6];
        format!("{start}...")
    } else {
        "••••••••".to_string()
    }
}

/// Scan all files in a directory for secrets and blocked files.
///
/// Walks the directory tree, skipping node_modules and hidden directories.
/// Returns a combined result with all matches.
pub fn scan_directory(dir: &std::path::Path) -> SecretScanResult {
    let mut result = SecretScanResult::default();

    let walker = ignore::WalkBuilder::new(dir)
        .hidden(false) // We DO want to check hidden files like .env
        .git_ignore(true)
        .filter_entry(|entry| {
            let name = entry.file_name().to_str().unwrap_or("");
            // Skip node_modules and .git
            name != "node_modules" && name != ".git"
        })
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }

        let path = entry.path();
        let rel_path = path
            .strip_prefix(dir)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        // Check for blocked filenames
        if is_blocked_file(&rel_path) {
            result.matches.push(SecretMatch {
                pattern_name: "blocked_file".to_string(),
                description: format!("'{rel_path}' should not be included in a published package"),
                matched_text: rel_path.clone(),
                line: 0,
                severity: "critical".to_string(),
            });
            result.files_scanned += 1;
            continue;
        }

        // Only scan text files (skip binaries, images, etc.)
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let scannable = matches!(
            ext,
            "js" | "mjs"
                | "cjs"
                | "ts"
                | "mts"
                | "cts"
                | "jsx"
                | "tsx"
                | "json"
                | "yml"
                | "yaml"
                | "toml"
                | "env"
                | "cfg"
                | "conf"
                | "ini"
                | "sh"
                | "bash"
                | "zsh"
                | "py"
                | "rb"
                | "rs"
                | "go"
                | "java"
                | "kt"
                | "swift"
                | "md"
                | "txt"
                | "xml"
                | "pem"
        ) || rel_path.starts_with(".env")
            || rel_path.ends_with("rc")
            || rel_path.ends_with(".npmrc");

        if !scannable {
            continue;
        }

        // Size guard: skip files > 2MB
        if path.metadata().is_ok_and(|m| m.len() > 2 * 1024 * 1024) {
            continue;
        }

        if let Ok(content) = std::fs::read_to_string(path) {
            let matches = scan_content(&content, &rel_path);
            result.matches.extend(matches);
            result.files_scanned += 1;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test fixtures use obviously fake values that still match detection patterns.
    // Values are constructed to pass regex matching without triggering GitHub push protection.

    #[test]
    fn detect_stripe_live_key() {
        // Construct the test value at runtime to avoid GitHub secret scanning
        let prefix = "sk_live_";
        let suffix = "FAKEFAKEFAKEFAKEFAKE";
        let content = format!(r#"const key = "{prefix}{suffix}";"#);
        let matches = scan_content(&content, "config.js");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "stripe_live_secret");
        assert_eq!(matches[0].severity, "critical");
        assert_eq!(matches[0].line, 1);
    }

    #[test]
    fn detect_stripe_test_key() {
        let prefix = "sk_test_";
        let suffix = "FAKEFAKEFAKEFAKEFAKE00";
        let content = format!("STRIPE_KEY={prefix}{suffix}");
        let matches = scan_content(&content, ".env");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, "high");
    }

    #[test]
    fn detect_github_pat() {
        let content = r#"token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij""#;
        let matches = scan_content(content, "src/api.js");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "github_pat");
        assert_eq!(matches[0].severity, "critical");
    }

    #[test]
    fn detect_aws_access_key() {
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let matches = scan_content(content, "deploy.sh");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "aws_access_key");
    }

    #[test]
    fn detect_private_key() {
        let content =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBA...\n-----END RSA PRIVATE KEY-----";
        let matches = scan_content(content, "key.pem");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "private_key_rsa");
        assert_eq!(matches[0].severity, "critical");
    }

    #[test]
    fn detect_ec_private_key() {
        let content = "-----BEGIN EC PRIVATE KEY-----";
        let matches = scan_content(content, "ec.pem");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "private_key_ec");
    }

    #[test]
    fn detect_openssh_private_key() {
        let content = "-----BEGIN OPENSSH PRIVATE KEY-----";
        let matches = scan_content(content, "id_ed25519");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "private_key_openssh");
    }

    #[test]
    fn detect_sendgrid_key() {
        // SG.{22 base64url}.{43 base64url} — construct at runtime
        let seg1 = "F".repeat(22); // 22 chars
        let seg2 = "A".repeat(43); // 43 chars
        let content = format!(r#"apiKey: "SG.{seg1}.{seg2}""#);
        let matches = scan_content(&content, "mailer.js");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "sendgrid_api_key");
    }

    #[test]
    fn detect_slack_bot_token() {
        let prefix = "xoxb-";
        let content = format!("SLACK_TOKEN={prefix}0000000000-0000000000-FAKEFAKEFAKEFAKEFAKEFAKE");
        let matches = scan_content(&content, "config.js");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "slack_bot_token");
    }

    #[test]
    fn detect_npm_token() {
        let content =
            r#"//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz1234567890"#;
        let matches = scan_content(content, ".npmrc");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "npm_token");
    }

    #[test]
    fn no_false_positive_on_clean_code() {
        let content = r#"
            const stripe = require('stripe')(process.env.STRIPE_KEY);
            const url = 'https://api.example.com';
            const port = 3000;
            console.log("hello world");
        "#;
        let matches = scan_content(content, "app.js");
        assert!(
            matches.is_empty(),
            "clean code should have no matches: {matches:?}"
        );
    }

    #[test]
    fn multiple_secrets_in_one_file() {
        let sk = format!("sk_live_{}", "F".repeat(20));
        let ghp = format!("ghp_{}", "A".repeat(36));
        let content = format!(
            r#"
            const stripe = "{sk}";
            const github = "{ghp}";
        "#
        );
        let matches = scan_content(&content, "config.js");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn line_numbers_correct() {
        let sk = format!("sk_live_{}", "F".repeat(20));
        let content = format!("line1\nline2\n{sk}\nline4");
        let matches = scan_content(&content, "test.js");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].line, 3);
    }

    #[test]
    fn blocked_env_files() {
        assert!(is_blocked_file(".env"));
        assert!(is_blocked_file(".env.local"));
        assert!(is_blocked_file(".env.production"));
        assert!(is_blocked_file("path/to/.env"));
        assert!(is_blocked_file("credentials.json"));
        assert!(!is_blocked_file("app.js"));
        assert!(!is_blocked_file(".env.example"));
        assert!(!is_blocked_file("package.json"));
    }

    #[test]
    fn truncate_long_secret() {
        let value = format!("sk_live_{}", "F".repeat(20));
        let truncated = truncate_secret(&value);
        assert!(truncated.contains("sk_live_"), "should show prefix");
        assert!(truncated.contains("..."), "should have ellipsis");
    }

    #[test]
    fn truncate_short_value() {
        let truncated = truncate_secret("short");
        assert_eq!(truncated, "••••••••");
    }

    #[test]
    fn detect_google_api_key() {
        let content = r#"const key = "AIzaSyBcdef123456789_abcdefghijklmnopqrst""#;
        let matches = scan_content(content, "config.js");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "google_api_key");
    }

    #[test]
    fn detect_generic_password() {
        let content = r#"password = "my-super-secret-password""#;
        let matches = scan_content(content, "config.js");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_name, "generic_password");
        assert_eq!(matches[0].severity, "medium");
    }

    #[test]
    fn secret_scan_result_merge() {
        let mut a = SecretScanResult {
            matches: vec![SecretMatch {
                pattern_name: "test".into(),
                description: "test".into(),
                matched_text: "test".into(),
                line: 1,
                severity: "high".into(),
            }],
            files_scanned: 1,
        };
        let b = SecretScanResult {
            matches: vec![SecretMatch {
                pattern_name: "test2".into(),
                description: "test2".into(),
                matched_text: "test2".into(),
                line: 5,
                severity: "critical".into(),
            }],
            files_scanned: 2,
        };
        a.merge(&b);
        assert_eq!(a.matches.len(), 2);
        assert_eq!(a.files_scanned, 3);
        assert_eq!(a.critical_count(), 1);
        assert_eq!(a.high_count(), 1);
    }
}
