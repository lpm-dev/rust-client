//! Secret detection in source code and configuration files.
//!
//! Detects hardcoded API keys, tokens, private keys, and other secrets
//! using known format patterns. Used by:
//! - `lpm publish` — pre-publish scan blocks upload if secrets found
//! - `lpm audit --secrets` — scans installed packages for leaked credentials
//!
//! Pattern matching uses `RegexSet` (compiled once, thread-safe) for
//! linear-time multi-pattern scanning against untrusted input.

use regex::bytes::RegexSet;
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
    /// Resource limit that stopped the scan before completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_exceeded: Option<SecretScanLimit>,
    /// Input failure that prevented a complete directory scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<String>,
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
        if self.limit_exceeded.is_none() {
            self.limit_exceeded = other.limit_exceeded;
        }
        if self.incomplete_reason.is_none() {
            self.incomplete_reason = other.incomplete_reason.clone();
        }
    }
}

/// Resource whose operation-wide secret scan budget was exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScanLimit {
    Files,
    Bytes,
    Findings,
}

impl std::fmt::Display for SecretScanLimit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Files => "file",
            Self::Bytes => "byte",
            Self::Findings => "finding",
        })
    }
}

/// Maximum files inspected by one secret-scan operation.
pub const SECRET_SCAN_MAX_FILES: usize = 250_000;
/// Maximum source bytes inspected by one secret-scan operation.
pub const SECRET_SCAN_MAX_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum findings retained by one secret-scan operation.
pub const SECRET_SCAN_MAX_FINDINGS: usize = 10_000;

/// Shared resource budget for one complete audit or publish operation.
#[derive(Debug, Clone)]
pub struct SecretScanBudget {
    /// `None` for no limit.
    remaining_files: Option<usize>,
    /// `None` for no limit.
    remaining_bytes: Option<u64>,
    remaining_findings: usize,
    exceeded: Option<SecretScanLimit>,
}

impl SecretScanBudget {
    /// The budget of a command that scans what it copies, whose own work is
    /// as large as what it scans: only its findings are limited.
    pub const fn for_copy() -> Self {
        Self {
            remaining_files: None,
            remaining_bytes: None,
            remaining_findings: SECRET_SCAN_MAX_FINDINGS,
            exceeded: None,
        }
    }

    /// Create the aggregate budget for one audit or publish operation.
    pub const fn for_operation() -> Self {
        Self {
            remaining_files: Some(SECRET_SCAN_MAX_FILES),
            remaining_bytes: Some(SECRET_SCAN_MAX_BYTES),
            remaining_findings: SECRET_SCAN_MAX_FINDINGS,
            exceeded: None,
        }
    }

    #[cfg(test)]
    const fn new(files: usize, bytes: u64, findings: usize) -> Self {
        Self {
            remaining_files: Some(files),
            remaining_bytes: Some(bytes),
            remaining_findings: findings,
            exceeded: None,
        }
    }

    /// Return the first resource limit that stopped the scan.
    pub const fn exceeded(&self) -> Option<SecretScanLimit> {
        self.exceeded
    }

    fn consume_file(&mut self) -> bool {
        match &mut self.remaining_files {
            None => true,
            Some(0) => {
                self.exceeded = Some(SecretScanLimit::Files);
                false
            }
            Some(remaining) => {
                *remaining -= 1;
                true
            }
        }
    }

    fn consume_bytes(&mut self, bytes: u64) -> bool {
        match &mut self.remaining_bytes {
            None => true,
            Some(remaining) if bytes > *remaining => {
                self.exceeded = Some(SecretScanLimit::Bytes);
                false
            }
            Some(remaining) => {
                *remaining -= bytes;
                true
            }
        }
    }

    fn consume_findings(&mut self, findings: usize) {
        self.remaining_findings -= findings;
    }

    fn exceed_findings(&mut self) {
        self.exceeded = Some(SecretScanLimit::Findings);
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
    // ── Private Keys ── (every `private_key_` pattern is also looked for at
    // the start of a file of any name; see `PRIVATE_KEY_SNIFF_BYTES`)
    (
        r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----",
        "private_key_rsa",
        "RSA private key",
        "critical",
    ),
    (
        r"-----BEGIN\s+PRIVATE\s+KEY-----",
        "private_key_pkcs8",
        "PKCS #8 private key",
        "critical",
    ),
    (
        r"-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----",
        "private_key_pkcs8_encrypted",
        "Encrypted PKCS #8 private key",
        "critical",
    ),
    (
        r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
        "private_key_ec",
        "EC private key",
        "critical",
    ),
    (
        r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----",
        "private_key_dsa",
        "DSA private key",
        "critical",
    ),
    (
        r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
        "private_key_openssh",
        "OpenSSH private key",
        "critical",
    ),
    (
        r"----\s+BEGIN\s+SSH2\s+ENCRYPTED\s+PRIVATE\s+KEY\s+----",
        "private_key_ssh2",
        "SSH2 private key",
        "critical",
    ),
    (
        r"PuTTY-User-Key-File-[0-9]+:",
        "private_key_putty",
        "PuTTY private key",
        "critical",
    ),
    (
        r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
        "private_key_pgp",
        "PGP private key",
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

/// Credential files that never belong in a published package, besides
/// `.env` files: shell, network and registry credentials, SSH private keys,
/// and cloud service-account keys.
const BLOCKED_FILES: &[&str] = &[
    ".envrc",
    ".netrc",
    "_netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials.json",
    "service-account.json",
    "gcloud-key.json",
];

/// `.env.<name>` files that hold no secrets by convention and are committed.
const ENV_TEMPLATE_NAMES: &[&str] = &["example", "sample", "template", "defaults", "vault"];

const MAX_SCANNABLE_FILE_BYTES: usize = 2 * 1024 * 1024;

/// How much of a file's start is looked through for a private key when its
/// name doesn't call for its whole content to be scanned: a key file of any
/// name, or one an export put a few attribute lines ahead of, starts with
/// its key. Not charged to the byte budget, which counts what is scanned in
/// full.
pub const PRIVATE_KEY_SNIFF_BYTES: usize = 64 * 1024;

/// Pieces a file is read in by [`scan_file_reader_with_budget`].
const READ_PIECE_BYTES: usize = 256 * 1024;

/// The longest line [`scan_file_reader_with_budget`] holds to match whole.
/// A longer one goes through the set's lazy DFA as it arrives, which finds
/// what matching it whole would.
const HELD_LINE_BYTES: usize = 4 * 1024 * 1024;

/// Some of [`SECRET_PATTERNS`], compiled into one set.
struct PatternSet {
    set: RegexSet,
    /// The [`SECRET_PATTERNS`] index of each pattern in `set`.
    patterns: Vec<usize>,
    /// The same patterns as one DFA that reports every pattern that matches,
    /// built for the first line too long to hold.
    long_lines: OnceLock<regex_automata::hybrid::dfa::DFA>,
}

impl PatternSet {
    fn of(keep: impl Fn(&str) -> bool) -> Self {
        let patterns: Vec<usize> = SECRET_PATTERNS
            .iter()
            .enumerate()
            .filter(|(_, (_, name, _, _))| keep(name))
            .map(|(index, _)| index)
            .collect();
        let set = RegexSet::new(patterns.iter().map(|&index| SECRET_PATTERNS[index].0))
            .expect("failed to compile secret patterns");
        Self {
            set,
            patterns,
            long_lines: OnceLock::new(),
        }
    }

    fn long_lines(&self) -> &regex_automata::hybrid::dfa::DFA {
        use regex_automata::hybrid::dfa::DFA;
        self.long_lines.get_or_init(|| {
            let patterns: Vec<&str> = self
                .patterns
                .iter()
                .map(|&index| SECRET_PATTERNS[index].0)
                .collect();
            // As `regex::bytes` compiles them, so the two find the same.
            DFA::builder()
                .configure(DFA::config().match_kind(regex_automata::MatchKind::All))
                .syntax(regex_automata::util::syntax::Config::new().utf8(false))
                .thompson(regex_automata::nfa::thompson::Config::new().utf8(false))
                .build_many(&patterns)
                .expect("failed to compile secret patterns")
        })
    }
}

/// A line too long to hold, matched as its bytes arrive.
struct LongLine {
    cache: regex_automata::hybrid::dfa::Cache,
    state: regex_automata::hybrid::LazyStateID,
    /// For each pattern of the set, whether it has matched.
    matched: Vec<bool>,
}

fn every_pattern() -> &'static PatternSet {
    static SET: OnceLock<PatternSet> = OnceLock::new();
    SET.get_or_init(|| PatternSet::of(|_| true))
}

fn private_key_patterns() -> &'static PatternSet {
    static SET: OnceLock<PatternSet> = OnceLock::new();
    SET.get_or_init(|| PatternSet::of(|name| name.starts_with("private_key_")))
}

/// Matches of one pattern set in a file, gathered line by line.
struct LineScan<'a> {
    patterns: &'static PatternSet,
    file_path: &'a str,
    maximum_findings: usize,
    matches: Vec<SecretMatch>,
    line: usize,
    exceeded: bool,
}

impl<'a> LineScan<'a> {
    fn new(patterns: &'static PatternSet, file_path: &'a str, maximum_findings: usize) -> Self {
        Self {
            patterns,
            file_path,
            maximum_findings,
            matches: Vec::with_capacity(maximum_findings.min(16)),
            line: 1,
            exceeded: false,
        }
    }

    /// Scans `content`, all of the file or what is left of it.
    fn scan_rest(&mut self, content: &[u8]) {
        let mut rest = content;
        while let Some(end) = memchr::memchr(b'\n', rest) {
            self.scan_line(&rest[..end]);
            rest = &rest[end + 1..];
        }
        self.scan_line(rest);
    }

    /// Scans the next line, whole, as a pattern can span all of it.
    fn scan_line(&mut self, line: &[u8]) {
        let number = self.line;
        self.line += 1;
        for index in self.patterns.set.matches(line).into_iter() {
            self.record(index, number);
        }
    }

    /// Starts the next line, too long to hold, with `start`.
    fn start_long_line(&self, start: &[u8]) -> std::io::Result<LongLine> {
        let dfa = self.patterns.long_lines();
        let mut cache = dfa.create_cache();
        let state = dfa
            .start_state(
                &mut cache,
                &regex_automata::util::start::Config::new().anchored(regex_automata::Anchored::No),
            )
            .map_err(std::io::Error::other)?;
        let mut line = LongLine {
            cache,
            state,
            matched: vec![false; self.patterns.patterns.len()],
        };
        self.continue_long_line(&mut line, start)?;
        Ok(line)
    }

    fn continue_long_line(&self, line: &mut LongLine, bytes: &[u8]) -> std::io::Result<()> {
        let dfa = self.patterns.long_lines();
        for &byte in bytes {
            line.state = dfa
                .next_state(&mut line.cache, line.state, byte)
                .map_err(std::io::Error::other)?;
            if line.state.is_match() {
                Self::note_matches(dfa, line);
            }
        }
        Ok(())
    }

    fn end_long_line(&mut self, mut line: LongLine) -> std::io::Result<()> {
        let dfa = self.patterns.long_lines();
        // A DFA reports a match one byte late, so the line's end can.
        line.state = dfa
            .next_eoi_state(&mut line.cache, line.state)
            .map_err(std::io::Error::other)?;
        if line.state.is_match() {
            Self::note_matches(dfa, &mut line);
        }
        let number = self.line;
        self.line += 1;
        for (index, _) in line
            .matched
            .iter()
            .enumerate()
            .filter(|(_, matched)| **matched)
        {
            self.record(index, number);
        }
        Ok(())
    }

    fn note_matches(dfa: &regex_automata::hybrid::dfa::DFA, line: &mut LongLine) {
        for match_index in 0..dfa.match_len(&line.cache, line.state) {
            line.matched[dfa
                .match_pattern(&line.cache, line.state, match_index)
                .as_usize()] = true;
        }
    }

    fn record(&mut self, index: usize, line: usize) {
        if self.exceeded {
            return;
        }
        if self.matches.len() == self.maximum_findings {
            self.exceeded = true;
            return;
        }
        let (_, name, description, severity) = SECRET_PATTERNS[self.patterns.patterns[index]];
        self.matches.push(SecretMatch {
            pattern_name: name.to_string(),
            description: format!("{description} in {}", self.file_path),
            line,
            severity: severity.to_string(),
        });
    }

    /// The matches, charged to `budget`, as `result`'s.
    fn finish_into(self, result: &mut SecretScanResult, budget: &mut SecretScanBudget) {
        budget.consume_findings(self.matches.len());
        result.matches = self.matches;
        result.files_scanned = 1;
        if self.exceeded {
            budget.exceed_findings();
            result.limit_exceeded = budget.exceeded();
        }
    }
}

/// Scan a single source file for secrets.
///
/// Returns matches with line numbers. The `content` should be the raw file content
/// (NOT comment-stripped — secrets can appear in comments too, and we want to catch them).
/// At most [`SECRET_SCAN_MAX_FINDINGS`] matches are retained.
pub fn scan_content(content: &str, file_path: &str) -> Vec<SecretMatch> {
    let mut scan = LineScan::new(every_pattern(), file_path, SECRET_SCAN_MAX_FINDINGS);
    scan.scan_rest(content.as_bytes());
    scan.matches
}

/// Whether a file, by its name and whatever its directory, holds credentials
/// that never belong in a published package: `.env` and `.env.<name>`
/// files other than templates such as `.env.example` or
/// `.env.production.example`, and the files in [`BLOCKED_FILES`]. Case is
/// ignored, as on a case-insensitive disk.
pub fn is_blocked_file(filename: &str) -> bool {
    let filename = &*folded(filename);
    let name = file_name(filename).to_ascii_lowercase();
    if name == ".env" {
        return true;
    }
    if let Some(variant) = name.strip_prefix(".env.") {
        let last = variant.rsplit('.').next().unwrap_or(variant);
        return !ENV_TEMPLATE_NAMES.contains(&last);
    }
    BLOCKED_FILES.contains(&name.as_str())
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// `path` with case set aside beyond ASCII too, as a case-insensitive
/// filesystem sets it aside: on APFS `.pgpaſſ` and `.pgpaẞ` are the file
/// `.pgpass`, so the rules here judge the name that way. Lowercasing first
/// takes `ẞ` to `ß`, which uppercases to `SS`.
fn folded(path: &str) -> std::borrow::Cow<'_, str> {
    lpm_common::names::fold_name(path)
}

/// Scan one prepared package file without rediscovering it from the filesystem.
///
/// Blocked filenames are reported even when their contents are binary or empty.
/// Other binary and unsupported files are skipped consistently with
/// [`scan_directory`]. Publishing callers already enforce artifact size limits,
/// so selected text files are scanned regardless of size.
pub fn scan_file_content(content: &[u8], file_path: &str) -> SecretScanResult {
    let mut budget = SecretScanBudget::for_operation();
    scan_file_content_with_budget(content, file_path, &mut budget)
}

/// Scan one prepared package file while charging an operation-wide budget.
pub fn scan_file_content_with_budget(
    content: &[u8],
    file_path: &str,
    budget: &mut SecretScanBudget,
) -> SecretScanResult {
    let mut result = SecretScanResult::default();
    if let Some(limit) = budget.exceeded() {
        result.limit_exceeded = Some(limit);
        return result;
    }
    if !budget.consume_file() {
        result.limit_exceeded = budget.exceeded();
        return result;
    }

    scan_file_content_after_file_charge(content, file_path, budget)
}

fn scan_file_content_after_file_charge(
    content: &[u8],
    file_path: &str,
    budget: &mut SecretScanBudget,
) -> SecretScanResult {
    if is_blocked_file(file_path) {
        return blocked_file_result(file_path, budget);
    }
    let mut result = SecretScanResult::default();
    if !is_scannable_file(file_path)
        || is_scannable_only_as_text(file_path) && is_binary_content(content)
    {
        let start = &content[..content.len().min(PRIVATE_KEY_SNIFF_BYTES)];
        let mut scan = LineScan::new(private_key_patterns(), file_path, budget.remaining_findings);
        scan.scan_rest(start);
        if !start.is_empty() {
            scan.finish_into(&mut result, budget);
        }
        return result;
    }
    if !budget.consume_bytes(content.len() as u64) {
        result.limit_exceeded = budget.exceeded();
        return result;
    }

    let mut scan = LineScan::new(every_pattern(), file_path, budget.remaining_findings);
    scan.scan_rest(content);
    scan.finish_into(&mut result, budget);
    result
}

fn blocked_file_result(file_path: &str, budget: &mut SecretScanBudget) -> SecretScanResult {
    let mut result = SecretScanResult::default();
    if budget.remaining_findings == 0 {
        budget.exceed_findings();
        result.limit_exceeded = budget.exceeded();
        return result;
    }
    result.matches.push(SecretMatch {
        pattern_name: "blocked_file".to_string(),
        description: format!("'{file_path}' should not be included in a published package"),
        line: 0,
        severity: "critical".to_string(),
    });
    budget.consume_findings(1);
    result.files_scanned = 1;
    result
}

/// Scans the file `reader` reads, `size` bytes of it, as
/// [`scan_file_content_with_budget`] scans that content, reading it a piece
/// at a time: memory holds a piece and a line of at most
/// [`HELD_LINE_BYTES`], whatever the file's size, a file the byte budget
/// can't cover is not read, and a file whose name doesn't call for its
/// content is read only as far as [`PRIVATE_KEY_SNIFF_BYTES`].
pub fn scan_file_reader_with_budget(
    reader: &mut dyn std::io::Read,
    size: u64,
    file_path: &str,
    budget: &mut SecretScanBudget,
) -> std::io::Result<SecretScanResult> {
    use std::io::Read as _;

    let mut result = SecretScanResult::default();
    if let Some(limit) = budget.exceeded() {
        result.limit_exceeded = Some(limit);
        return Ok(result);
    }
    if !budget.consume_file() {
        result.limit_exceeded = budget.exceeded();
        return Ok(result);
    }
    if is_blocked_file(file_path) {
        return Ok(blocked_file_result(file_path, budget));
    }
    let mut reader = reader.take(size);
    let sniff_only = !is_scannable_file(file_path);
    let text_only = is_scannable_only_as_text(file_path);
    let first = if sniff_only {
        PRIVATE_KEY_SNIFF_BYTES
    } else if text_only {
        BINARY_SNIFF_BYTES
    } else {
        0
    };
    let mut pending = Vec::with_capacity(usize::try_from(size).map_or(READ_PIECE_BYTES, |size| {
        size.min(first.max(READ_PIECE_BYTES))
    }));
    (&mut reader).take(first as u64).read_to_end(&mut pending)?;
    if sniff_only || text_only && is_binary_content(&pending) {
        (&mut reader)
            .take((PRIVATE_KEY_SNIFF_BYTES - pending.len().min(PRIVATE_KEY_SNIFF_BYTES)) as u64)
            .read_to_end(&mut pending)?;
        return Ok(scan_file_content_after_file_charge(
            &pending, file_path, budget,
        ));
    }
    if !budget.consume_bytes(size) {
        result.limit_exceeded = budget.exceeded();
        return Ok(result);
    }

    let mut scan = LineScan::new(every_pattern(), file_path, budget.remaining_findings);
    let mut piece = vec![0; READ_PIECE_BYTES];
    // `pending` holds the line so far, until it is too long to hold.
    let first = std::mem::take(&mut pending);
    let mut long: Option<LongLine> = None;
    let mut arrived: &[u8] = &first;
    loop {
        let mut rest = arrived;
        while !rest.is_empty() {
            let end = memchr::memchr(b'\n', rest);
            let (part, after) = match end {
                Some(end) => (&rest[..end], &rest[end + 1..]),
                None => (rest, &rest[rest.len()..]),
            };
            if let Some(line) = long.as_mut() {
                scan.continue_long_line(line, part)?;
            } else if end.is_some() && pending.is_empty() {
                scan.scan_line(part);
            } else {
                pending.extend_from_slice(part);
                if pending.len() > HELD_LINE_BYTES {
                    long = Some(scan.start_long_line(&pending)?);
                    pending.clear();
                }
            }
            if end.is_some() {
                match long.take() {
                    Some(line) => scan.end_long_line(line)?,
                    None if !pending.is_empty() => {
                        scan.scan_line(&pending);
                        pending.clear();
                    }
                    None => {}
                }
            }
            rest = after;
        }
        if scan.exceeded {
            break;
        }
        let read = loop {
            match reader.read(&mut piece) {
                Ok(read) => break read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        };
        if read == 0 {
            break;
        }
        arrived = &piece[..read];
    }
    match long.take() {
        Some(line) => scan.end_long_line(line)?,
        None => scan.scan_line(&pending),
    }
    scan.finish_into(&mut result, budget);
    Ok(result)
}

/// How much of a file's start [`is_binary_content`] reads.
pub const BINARY_SNIFF_BYTES: usize = 8 * 1024;

/// Whether content that starts with `prefix` is binary, as git decides it:
/// a NUL byte in the first [`BINARY_SNIFF_BYTES`]. Native executables (ELF,
/// Mach-O, PE) all have one in their headers.
pub fn is_binary_content(prefix: &[u8]) -> bool {
    prefix[..prefix.len().min(BINARY_SNIFF_BYTES)].contains(&0)
}

/// Whether `file_path` is read only for being a file without an extension,
/// such as a `bin/` script or a key file, which can also be a native
/// executable: its content is scanned only when it is text.
pub fn is_scannable_only_as_text(file_path: &str) -> bool {
    let file_path = &*folded(file_path);
    file_extension(file_path).is_empty() && !is_scannable_by_name(file_path)
}

fn file_extension(file_path: &str) -> &str {
    std::path::Path::new(file_name(file_path))
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
}

fn is_scannable_file(file_path: &str) -> bool {
    let file_path = &*folded(file_path);
    file_extension(file_path).is_empty() || is_scannable_by_name(file_path)
}

fn is_scannable_by_name(file_path: &str) -> bool {
    const SCANNABLE_EXTENSIONS: &[&str] = &[
        "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "json", "yml", "yaml", "toml", "env",
        "cfg", "conf", "ini", "sh", "bash", "zsh", "py", "rb", "rs", "go", "java", "kt", "swift",
        "md", "txt", "xml", "pem", "key", "p8", "pk8", "ppk",
    ];

    let file_path = &*folded(file_path);
    let name = file_name(file_path);
    let ext = file_extension(file_path);
    SCANNABLE_EXTENSIONS
        .iter()
        .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        || file_path.split(['/', '\\']).any(|component| {
            [
                "private",
                "secrets",
                ".secrets",
                "credentials",
                ".credentials",
            ]
            .iter()
            .any(|sensitive| component.eq_ignore_ascii_case(sensitive))
        })
        || name
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(".env"))
        || file_path
            .get(file_path.len().saturating_sub(2)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case("rc"))
        || file_path
            .get(file_path.len().saturating_sub(6)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".npmrc"))
}

/// Return whether secret detection needs the file contents for this path.
///
/// Blocked filenames remain detectable without reading their contents because
/// [`scan_file_content_with_budget`] reports them from the path alone.
pub fn file_content_requires_scan(file_path: &str) -> bool {
    is_scannable_file(file_path)
}

/// Scan all files in a directory for secrets and blocked files.
///
/// Walks the directory tree, skipping nested `node_modules` and `.git` directories.
/// Returns a combined result with all matches.
pub fn scan_directory(dir: &std::path::Path) -> SecretScanResult {
    let mut budget = SecretScanBudget::for_operation();
    scan_directory_with_budget(dir, &mut budget)
}

/// Scan a package directory while charging work to a command-wide budget.
pub fn scan_directory_with_budget(
    dir: &std::path::Path,
    budget: &mut SecretScanBudget,
) -> SecretScanResult {
    let mut result = SecretScanResult::default();

    if let Some(limit) = budget.exceeded() {
        result.limit_exceeded = Some(limit);
        return result;
    }

    let walker = ignore::WalkBuilder::new(dir)
        .standard_filters(false)
        .filter_entry(|entry| {
            let name = entry.file_name().to_str().unwrap_or("");
            // Skip node_modules and .git
            name != "node_modules" && name != ".git"
        })
        .build();

    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                result.incomplete_reason =
                    Some(format!("cannot enumerate package sources: {error}"));
                return result;
            }
        };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        if !budget.consume_file() {
            result.limit_exceeded = budget.exceeded();
            return result;
        }
        let path = entry.path();
        let rel_path = path
            .strip_prefix(dir)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        let content = if is_blocked_file(&rel_path) || !is_scannable_file(&rel_path) {
            Vec::new()
        } else {
            match read_scannable_content(path, &rel_path) {
                Ok(Some(content)) => content,
                Ok(None) => continue,
                Err(error) => {
                    result.incomplete_reason = Some(format!("cannot scan {rel_path}: {error}"));
                    return result;
                }
            }
        };
        let mut file_scan = scan_file_content_after_file_charge(&content, &rel_path, budget);
        result.matches.append(&mut file_scan.matches);
        result.files_scanned += file_scan.files_scanned;
        if file_scan.limit_exceeded.is_some() {
            result.limit_exceeded = file_scan.limit_exceeded;
            return result;
        }
    }

    result
}

/// The content the scan reads at `path`, or `None` for a file it reads only
/// as text whose start is binary, which is not read further.
fn read_scannable_content(
    path: &std::path::Path,
    rel_path: &str,
) -> Result<Option<Vec<u8>>, String> {
    if is_scannable_only_as_text(rel_path) {
        use std::io::Read as _;
        let mut prefix = Vec::with_capacity(BINARY_SNIFF_BYTES);
        std::fs::File::open(path)
            .and_then(|file| {
                file.take(BINARY_SNIFF_BYTES as u64)
                    .read_to_end(&mut prefix)
            })
            .map_err(|error| error.to_string())?;
        if is_binary_content(&prefix) {
            return Ok(None);
        }
    }
    lpm_common::read_file_capped(path, MAX_SCANNABLE_FILE_BYTES as u64)
        .map(Some)
        .map_err(|error| error.to_string())
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
    fn private_keys_are_found_in_key_files_and_in_every_pem_form() {
        for path in [
            "server.key",
            "certs/client.p8",
            "signing.pk8",
            "TLS.KEY",
            "deploy.ppk",
        ] {
            assert!(file_content_requires_scan(path), "{path}");
        }
        for header in [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
            "PuTTY-User-Key-File-3: ssh-ed25519",
        ] {
            let matches = scan_content(header, "server.key");
            assert_eq!(matches.len(), 1, "{header}");
            assert_eq!(matches[0].severity, "critical", "{header}");
        }
    }

    #[test]
    fn a_private_key_a_file_starts_with_is_found_whatever_the_file_is_named() {
        let key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n";
        let exported = format!("Bag Attributes\n    localKeyID: 01 02 03\n{key}");
        let in_a_data_file = scan_file_content(exported.as_bytes(), "assets/config.dat");
        assert_eq!(in_a_data_file.matches.len(), 1);
        assert_eq!(in_a_data_file.matches[0].pattern_name, "private_key_pkcs8");
        assert_eq!(in_a_data_file.matches[0].line, 3);

        let mut executable = b"\x7fELF\x02\x01\x01\0\0\0\n".to_vec();
        executable.extend_from_slice(b"-----BEGIN OPENSSH PRIVATE KEY-----\n");
        let in_a_binary = scan_file_content(&executable, "bin/tool");
        assert_eq!(in_a_binary.matches.len(), 1);
        assert_eq!(in_a_binary.matches[0].pattern_name, "private_key_openssh");

        let mut past_the_start = vec![b'x'; PRIVATE_KEY_SNIFF_BYTES];
        past_the_start.extend_from_slice(key.as_bytes());
        assert!(
            scan_file_content(&past_the_start, "assets/config.dat")
                .matches
                .is_empty()
        );
        assert!(
            scan_file_content(b"just data, nothing secret", "assets/config.dat")
                .matches
                .is_empty()
        );
    }

    /// Hands out what it holds a few bytes at a time.
    struct Trickle<'a> {
        content: &'a [u8],
        piece: usize,
    }

    impl std::io::Read for Trickle<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let length = self.piece.min(buffer.len()).min(self.content.len());
            buffer[..length].copy_from_slice(&self.content[..length]);
            self.content = &self.content[length..];
            Ok(length)
        }
    }

    fn found(result: &SecretScanResult) -> Vec<(String, usize)> {
        result
            .matches
            .iter()
            .map(|found| (found.pattern_name.clone(), found.line))
            .collect()
    }

    #[test]
    fn a_file_read_a_piece_at_a_time_is_scanned_as_its_whole_content_is() {
        let stripe = format!("sk_live_{}", "FAKEFAKEFAKEFAKEFAKE");
        let mut long_line = "x".repeat(3 * 1024 * 1024 + 17);
        long_line.push_str(&stripe);
        long_line.push_str(&format!(" and again {stripe}"));
        let content = format!(
            "const a = 1;\nconst key = \"{stripe}\";\n{long_line}\n\n-----BEGIN RSA PRIVATE KEY-----\nlast line {stripe}"
        );
        let whole = scan_file_content(content.as_bytes(), "src/config.js");
        assert_eq!(
            found(&whole),
            [
                ("stripe_live_secret".to_string(), 2),
                ("stripe_live_secret".to_string(), 3),
                ("private_key_rsa".to_string(), 5),
                ("stripe_live_secret".to_string(), 6),
            ]
        );
        for piece in [1, 7, 4096, 1 << 20, usize::MAX] {
            let mut budget = SecretScanBudget::for_operation();
            let streamed = scan_file_reader_with_budget(
                &mut Trickle {
                    content: content.as_bytes(),
                    piece,
                },
                content.len() as u64,
                "src/config.js",
                &mut budget,
            )
            .unwrap();
            assert_eq!(found(&streamed), found(&whole), "{piece}-byte pieces");
            assert_eq!(streamed.files_scanned, 1);
        }

        let mut budget = SecretScanBudget::for_operation();
        let key_file = scan_file_reader_with_budget(
            &mut Trickle {
                content: b"MZ\0\0\n-----BEGIN EC PRIVATE KEY-----\n",
                piece: 3,
            },
            38,
            "native/addon.node",
            &mut budget,
        )
        .unwrap();
        assert_eq!(
            found(&key_file),
            [("private_key_ec".to_string(), 2)],
            "a file of any name is checked for a private key at its start"
        );
    }

    #[test]
    fn a_secret_spread_over_a_long_line_is_found_however_the_file_is_read() {
        // The name a megabyte in, the value 20,000 spaces past it.
        let mut content = format!(
            "/*{}*/ const AWS_SECRET_ACCESS_KEY",
            "x".repeat((1 << 20) - 10_000)
        );
        content.push_str(&" ".repeat(20_000));
        content.push_str(&format!("= \"{}\";\n", "A".repeat(40)));
        let expected = [("aws_secret_key".to_string(), 1)];

        assert_eq!(
            found(&scan_file_content(content.as_bytes(), "index.js")),
            expected
        );
        for piece in [7, 4096, 1 << 20] {
            let mut budget = SecretScanBudget::for_operation();
            let streamed = scan_file_reader_with_budget(
                &mut Trickle {
                    content: content.as_bytes(),
                    piece,
                },
                content.len() as u64,
                "index.js",
                &mut budget,
            )
            .unwrap();
            assert_eq!(found(&streamed), expected, "{piece}-byte pieces");
        }
    }

    #[test]
    fn a_line_too_long_to_hold_is_scanned_as_it_arrives_with_the_same_findings() {
        let stripe = format!("sk_live_{}", "FAKEFAKEFAKEFAKEFAKE");
        let mut line = String::with_capacity(10 << 20);
        line.push_str(&stripe);
        line.push_str(&"x".repeat((4 << 20) - 30));
        // Across the length at which the line stops being held.
        line.push_str("AWS_SECRET_ACCESS_KEY");
        line.push_str(&" ".repeat(100));
        line.push_str(&format!("= \"{}\"", "A".repeat(40)));
        line.push_str(&"y".repeat(5 << 20));
        line.push_str("-----BEGIN OPENSSH PRIVATE KEY-----");
        let content = format!("first {stripe}\n{line}\nlast line\n{line}");
        let whole = scan_file_content(content.as_bytes(), "bundle.js");
        assert_eq!(
            found(&whole),
            [
                ("stripe_live_secret".to_string(), 1),
                ("stripe_live_secret".to_string(), 2),
                ("aws_secret_key".to_string(), 2),
                ("private_key_openssh".to_string(), 2),
                ("stripe_live_secret".to_string(), 4),
                ("aws_secret_key".to_string(), 4),
                ("private_key_openssh".to_string(), 4),
            ]
        );
        for piece in [4096, 1 << 20, 3 << 20] {
            let mut budget = SecretScanBudget::for_operation();
            let streamed = scan_file_reader_with_budget(
                &mut Trickle {
                    content: content.as_bytes(),
                    piece,
                },
                content.len() as u64,
                "bundle.js",
                &mut budget,
            )
            .unwrap();
            assert_eq!(found(&streamed), found(&whole), "{piece}-byte pieces");
        }
    }

    #[test]
    fn a_copy_budget_limits_findings_only() {
        let mut budget = SecretScanBudget::for_copy();
        for _ in 0..SECRET_SCAN_MAX_FILES + 1 {
            let result =
                scan_file_reader_with_budget(&mut &b"x"[..], u64::MAX, "a.js", &mut budget)
                    .unwrap();
            assert_eq!(result.limit_exceeded, None);
        }
    }

    #[test]
    fn a_file_the_byte_budget_cannot_cover_is_not_read() {
        struct Unreadable;
        impl std::io::Read for Unreadable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("a file past the budget was read");
            }
        }
        let mut budget = SecretScanBudget::new(10, 100, 10);
        let result =
            scan_file_reader_with_budget(&mut Unreadable, 101, "src/index.js", &mut budget)
                .unwrap();
        assert_eq!(result.limit_exceeded, Some(SecretScanLimit::Bytes));
        assert!(result.matches.is_empty());
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
        assert!(is_blocked_file(".env.development.local"));
        assert!(is_blocked_file(".env.preview"));
        assert!(is_blocked_file("path/to/.env"));
        assert!(is_blocked_file("config\\.ENV.Staging"));
        assert!(is_blocked_file("credentials.json"));
        assert!(!is_blocked_file("app.js"));
        assert!(!is_blocked_file(".env.example"));
        // As APFS reads them: `ſ` is `s`, `ẞ` is `ss`, the Kelvin sign `k`.
        assert!(is_blocked_file(".pgpa\u{17F}\u{17F}"));
        assert!(is_blocked_file(".pgpa\u{1E9E}"));
        assert!(is_blocked_file("id_r\u{17F}a"));
        assert!(is_blocked_file("gcloud-\u{212A}ey.json"));
        assert!(file_content_requires_scan("\u{17F}ecrets/payload.bin"));
        assert!(!is_scannable_only_as_text("\u{17F}ecrets/payload"));
        assert!(!is_blocked_file(".env.production.example"));
        assert!(!is_blocked_file(".env.sample"));
        assert!(!is_blocked_file(".environment"));
        assert!(!is_blocked_file("package.json"));
    }

    #[test]
    fn blocked_credential_files() {
        for name in [
            ".envrc",
            "keys/id_rsa",
            "ID_ED25519",
            ".netrc",
            "_netrc",
            ".pgpass",
            ".pypirc",
            ".git-credentials",
            "deploy/service-account.json",
            // HFS+ leaves zero-width and directional marks out of names.
            "config/.e\u{200C}nv",
            "id_r\u{FEFF}sa",
        ] {
            assert!(is_blocked_file(name), "{name}");
        }
        assert!(!is_blocked_file("keys/id_rsa.pub"));
    }

    #[test]
    fn files_without_an_extension_and_nested_env_files_are_scanned() {
        assert!(file_content_requires_scan("bin/deploy"));
        assert!(file_content_requires_scan("keys/id_rsa"));
        assert!(file_content_requires_scan("config/.env.preview"));
        assert!(!file_content_requires_scan("logo.png"));
    }

    #[test]
    fn scan_file_content_reports_blocked_filename_without_readable_content() {
        let result = scan_file_content(&[0xff, 0xfe], "config/credentials.json");

        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].pattern_name, "blocked_file");
        assert_eq!(result.matches[0].line, 0);
        assert_eq!(result.files_scanned, 1);
    }

    #[test]
    fn scan_file_content_preserves_path_and_line_for_detected_secret() {
        let secret = format!(
            "first line\npassword = \"{}\"\n",
            "fixture-secret".repeat(2)
        );
        let result = scan_file_content(secret.as_bytes(), "ignored/selected.js");

        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].pattern_name, "generic_password");
        assert_eq!(result.matches[0].line, 2);
        assert!(
            result.matches[0]
                .description
                .contains("ignored/selected.js")
        );
    }

    #[test]
    fn scan_file_content_skips_clean_selected_file() {
        let result = scan_file_content(b"module.exports = {}", "index.js");

        assert!(!result.has_secrets());
        assert_eq!(result.files_scanned, 1);
    }

    #[test]
    fn scan_file_content_scans_selected_text_larger_than_directory_audit_limit() {
        let mut content = vec![b'x'; MAX_SCANNABLE_FILE_BYTES];
        content.push(b'\n');
        content.extend_from_slice(b"sk_live_");
        content.extend_from_slice(b"FAKEFAKEFAKEFAKEFAKE\n");

        let result = scan_file_content(&content, "bundle.js");

        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].pattern_name, "stripe_live_secret");
        assert_eq!(result.files_scanned, 1);
    }

    #[test]
    fn scan_file_content_matches_supported_extensions_case_insensitively() {
        let secret = format!("token=npm_{}", "A".repeat(36));

        let result = scan_file_content(secret.as_bytes(), "CONFIG.JSON");

        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].pattern_name, "npm_token");
        assert_eq!(result.files_scanned, 1);
    }

    #[test]
    fn scan_file_content_scans_unknown_extensions_inside_sensitive_directories() {
        let secret = format!("token=npm_{}", "S".repeat(36));

        for path in [
            "private/export.dat",
            "secrets/export.dat",
            ".secrets/export.dat",
            "credentials/export.dat",
            ".credentials/export.dat",
        ] {
            let result = scan_file_content(secret.as_bytes(), path);

            assert_eq!(result.matches.len(), 1, "secret was not detected in {path}");
            assert_eq!(result.matches[0].pattern_name, "npm_token");
            assert_eq!(result.files_scanned, 1);
        }
    }

    #[test]
    fn scan_file_content_detects_ascii_secrets_around_invalid_utf8() {
        let mut content = vec![0xff, b'\n'];
        content.extend_from_slice(format!("token=npm_{}", "B".repeat(36)).as_bytes());

        let result = scan_file_content(&content, "config.json");

        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].pattern_name, "npm_token");
        assert_eq!(result.files_scanned, 1);
    }

    fn native_executable_with_key_text(size: usize) -> Vec<u8> {
        let mut content = b"\x7fELF\x02\x01\x01\x00".to_vec();
        content.extend_from_slice(
            b"\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBA\nAKIAIOSFODNN7EXAMPLE\n",
        );
        content.resize(size.max(content.len()), 0);
        content
    }

    #[test]
    fn an_extensionless_native_executable_is_not_scanned_as_text() {
        let binary = native_executable_with_key_text(64 * 1024);
        let mut budget = SecretScanBudget::for_operation();

        let executable = scan_file_content_with_budget(&binary, "bin/esbuild", &mut budget);
        assert_eq!(
            found(&executable),
            [("private_key_rsa".to_string(), 2)],
            "a binary is checked for a private key at its start, not read for the rest"
        );

        let named = scan_file_content_with_budget(&binary, "bin/tool.sh", &mut budget);
        assert!(named.has_secrets(), "a listed extension keeps its scan");

        let script = scan_file_content_with_budget(
            b"#!/bin/sh\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
            "bin/deploy",
            &mut budget,
        );
        assert!(
            script.has_secrets(),
            "an extensionless script is still scanned"
        );
    }

    #[test]
    fn a_large_extensionless_executable_leaves_the_directory_scan_complete() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("bin")).unwrap();
        std::fs::write(
            dir.path().join("bin/esbuild"),
            native_executable_with_key_text(MAX_SCANNABLE_FILE_BYTES + 1024),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("bin/deploy"),
            "#!/bin/sh\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        )
        .unwrap();

        let result = scan_directory(dir.path());

        assert_eq!(result.incomplete_reason, None);
        assert_eq!(result.files_scanned, 1);
        assert!(result.has_secrets());
    }

    #[test]
    fn scan_directory_retains_large_file_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut content = vec![b'x'; MAX_SCANNABLE_FILE_BYTES];
        content.push(b'\n');
        content.extend_from_slice(b"sk_live_");
        content.extend_from_slice(b"FAKEFAKEFAKEFAKEFAKE\n");
        std::fs::write(dir.path().join("bundle.js"), content).unwrap();

        let result = scan_directory(dir.path());

        assert!(!result.has_secrets());
        assert_eq!(result.files_scanned, 0);
        assert!(
            result
                .incomplete_reason
                .as_deref()
                .unwrap()
                .contains("bundle.js")
        );
    }

    #[test]
    fn scan_directory_does_not_retain_more_than_ten_thousand_findings() {
        let dir = tempfile::tempdir().unwrap();
        let secret = format!("sk_{}_{}", "live", "F".repeat(20));
        let mut content = String::with_capacity((secret.len() + 1) * 10_001);
        for _ in 0..10_001 {
            content.push_str(&secret);
            content.push('\n');
        }
        std::fs::write(dir.path().join("secrets.js"), content).unwrap();

        let result = scan_directory(dir.path());

        assert!(
            result.matches.len() <= 10_000,
            "secret scanning must cap retained findings, got {}",
            result.matches.len()
        );
        assert_eq!(result.limit_exceeded, Some(SecretScanLimit::Findings));
    }

    #[test]
    fn detected_secret_metadata_does_not_retain_credential_fragments() {
        let secret = format!("sk_{}_{}", "live", "F".repeat(20));

        let matches = scan_content(&secret, "config.js");
        let serialized = serde_json::to_string(&matches).unwrap();

        assert!(!serialized.contains(&secret));
    }

    #[test]
    fn non_ascii_secret_is_redacted_without_panicking() {
        let matches = scan_content("password: 'Contraseña',", "messages.js");

        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn shared_file_budget_stops_before_scanning_another_file() {
        let mut budget = SecretScanBudget::new(1, 1024, 10);
        let first = scan_file_content_with_budget(b"module.exports = {};", "first.js", &mut budget);
        assert_eq!(first.limit_exceeded, None);

        let second =
            scan_file_content_with_budget(b"module.exports = {};", "second.js", &mut budget);

        assert_eq!(second.limit_exceeded, Some(SecretScanLimit::Files));
        assert_eq!(second.files_scanned, 0);
    }

    #[test]
    fn shared_byte_budget_rejects_content_before_matching() {
        let mut budget = SecretScanBudget::new(1, 3, 10);

        let result = scan_file_content_with_budget(b"four", "config.js", &mut budget);

        assert_eq!(result.limit_exceeded, Some(SecretScanLimit::Bytes));
        assert_eq!(result.files_scanned, 0);
    }

    #[test]
    fn shared_finding_budget_stops_at_the_configured_limit() {
        let mut budget = SecretScanBudget::new(1, 1024, 1);
        let first = format!("sk_{}_{}", "live", "A".repeat(20));
        let second = format!("sk_{}_{}", "test", "B".repeat(20));
        let content = format!("{first}\n{second}\n");

        let result = scan_file_content_with_budget(content.as_bytes(), "config.js", &mut budget);

        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.limit_exceeded, Some(SecretScanLimit::Findings));
    }

    #[test]
    fn scan_directory_does_not_allow_package_ignore_rules_to_hide_secrets() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("ignored/nested")).unwrap();
        std::fs::write(dir.path().join(".gitignore"), "ignored/\n").unwrap();
        std::fs::write(dir.path().join(".ignore"), "also-ignored.js\n").unwrap();
        std::fs::write(
            dir.path().join("ignored/nested/secret.js"),
            format!("const token = 'ghp_{}';\n", "A".repeat(36)),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("also-ignored.js"),
            "const token = 'AKIAIOSFODNN7EXAMPLE';\n",
        )
        .unwrap();

        let result = scan_directory(dir.path());

        assert_eq!(
            result.matches.len(),
            2,
            "installed package ignore files must not reduce secret-scan coverage: {result:?}"
        );
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
                line: 1,
                severity: "high".into(),
            }],
            files_scanned: 1,
            limit_exceeded: None,
            incomplete_reason: None,
        };
        let b = SecretScanResult {
            matches: vec![SecretMatch {
                pattern_name: "test2".into(),
                description: "test2".into(),
                line: 5,
                severity: "critical".into(),
            }],
            files_scanned: 2,
            limit_exceeded: None,
            incomplete_reason: None,
        };
        a.merge(&b);
        assert_eq!(a.matches.len(), 2);
        assert_eq!(a.files_scanned, 3);
        assert_eq!(a.critical_count(), 1);
        assert_eq!(a.high_count(), 1);
    }
}
