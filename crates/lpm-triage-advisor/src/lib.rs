//! Layer 4 triage-advisor adapter.
//!
//! Shared infrastructure for invoking an external LLM advisor to
//! classify a Layer-1 amber script as Approve / Manual / Abstain.
//! Used by both the audit harness (offline measurement of advisor
//! uplift) and the eventual `lpm config triage` wizard / install-time
//! advisor invocation.
//!
//! Three providers in v1:
//! - [`Provider::ClaudeCli`] — Anthropic's `claude` CLI in print mode.
//! - [`Provider::Codex`] — OpenAI's `codex` CLI in exec mode.
//! - [`Provider::Ollama`] — local `ollama` server at `localhost:11434`.
//!
//! All three are CLI/server invocation models with the same surface
//! contract: send a structured prompt, receive a one-token verdict.
//! No SDK integrations in v1 — cloud paths route through the user's
//! existing CLI / API key configuration.
//!
//! # The triage contract
//!
//! L4 is an **optional advisor** plugged into `script-policy = "triage"`.
//! Portable triage (advisor = none) is the decision-grade product
//! contract; the advisor only converts amber → auto-run when it is
//! confident the script is safe. Its job is to recover prompts, not
//! to relax red blocks. The classifier owns red/green; the advisor
//! owns amber-to-auto-run with high confidence.
//!
//! # Failure modes
//!
//! Two distinct categories — see [`AdvisorFailure`]:
//! - [`AdvisorFailure::EnvironmentNotReady`]: auth missing, daemon
//!   not running, model not downloaded. **Recoverable** — the wizard
//!   can offer "save anyway" and `lpm install` degrades to
//!   `triage-advisor = "none"` for that run with a warning.
//! - [`AdvisorFailure::IntegrationFailure`]: adapter could not
//!   produce a structured verdict even on a known-safe test input.
//!   Indicates a broken adapter contract. The wizard blocks save;
//!   the install also degrades but the operator should investigate.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod adapters;
mod detection;
mod l4_cache;
mod metadata;
mod prompt;
mod verdict;

pub use adapters::{ClaudeCliAdapter, CodexAdapter, OllamaAdapter};
pub use detection::{ProbeReport, detect, probe_all};
pub use l4_cache::{CacheKeyInputs, DEFAULT_TTL as L4_CACHE_DEFAULT_TTL, L4Cache, build_cache_key};
pub use metadata::{binary_path, prompt_template_hash, provider_version};
pub use prompt::build_prompt;
pub use verdict::parse_verdict;

/// Default timeout for a single advisor invocation. Cloud CLIs add
/// network latency; local models are fast but not instant. 60s keeps
/// the audit harness moving without truncating slow responses.
pub const DEFAULT_INVOCATION_TIMEOUT: Duration = Duration::from_secs(60);

/// The four supported providers. Adapter implementations live in
/// `adapters::*`. The ordering here is the canonical preference order
/// the wizard uses when multiple are detected (local first, then by
/// likelihood of being already-configured on a developer's machine).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// Local Ollama server. No cloud egress.
    Ollama,
    /// Anthropic's Claude Code CLI.
    ClaudeCli,
    /// OpenAI Codex CLI.
    Codex,
}

impl Provider {
    /// CLI/identifier string for config files and CLI flags.
    /// Matches `triage-advisor` config values: `none` / `claude-cli`
    /// / `codex` / `ollama`.
    pub const fn slug(self) -> &'static str {
        match self {
            Provider::Ollama => "ollama",
            Provider::ClaudeCli => "claude-cli",
            Provider::Codex => "codex",
        }
    }

    /// Parse a slug; returns `None` for `"none"` and unknown values.
    pub fn from_slug(s: &str) -> Option<Provider> {
        match s {
            "ollama" => Some(Provider::Ollama),
            "claude-cli" => Some(Provider::ClaudeCli),
            "codex" => Some(Provider::Codex),
            _ => None,
        }
    }

    /// Is this provider local-only (no cloud egress for the actual
    /// classification)?  Drives the privacy-disclosure copy in the
    /// wizard — cloud advisors send the script text out; local ones
    /// don't.
    pub const fn is_local(self) -> bool {
        matches!(self, Provider::Ollama)
    }

    /// Canonical iteration order over all providers.
    pub fn all() -> &'static [Provider] {
        &[Provider::Ollama, Provider::ClaudeCli, Provider::Codex]
    }
}

/// Input handed to the advisor: one amber lifecycle-script body plus
/// the surrounding package context the advisor needs to judge safety.
///
/// Borrowed slices on the input side keep the per-classify call
/// allocation-free (the caller already owns the package's name,
/// version, script bodies, and referenced-file content). The struct
/// is **not** serializable — it's purely a transport for borrowed
/// data into the prompt template. A future "audit-replay" path that
/// wants to deserialize amber scripts would use a parallel owned
/// shape; do not add serde derives back here, since `&[T]` cannot
/// be deserialized borrowed-by-default.
#[derive(Debug, Clone)]
pub struct AmberScript<'a> {
    pub package_name: &'a str,
    pub package_version: &'a str,
    pub phase: &'a str,
    pub script_body: &'a str,
    /// Phase 46b Lever #1 — `repository` field from the package
    /// manifest (typically `package.json > repository.url` or the
    /// legacy shorthand string form). When present, the prompt emits
    /// a `Repository:` line and the closing guidance pairs the
    /// repository identity with the "fetch IDENTITY" axis. When
    /// `None`, the prompt omits the line entirely (empirical
    /// measurement on the curated corpus showed `<none>`
    /// pushed verdicts toward MANUAL; absent-by-default is the
    /// safer default for measurement and for real packages that
    /// happen not to declare the field).
    pub repository: Option<&'a str>,
    /// Phase 46b Lever #3 — contents of files the script body
    /// delegates to (e.g. `install.js` when the body is `node
    /// install.js`). The L4 advisor uses these to apply the
    /// "fetch IDENTITY" rule one level deep — the script body
    /// alone may not reveal what's fetched, but the file it
    /// delegates to does.
    ///
    /// Each referenced script is emitted in its own nonced fence
    /// (per-file random nonce) so an attacker who edits one file's
    /// content can't break out of another file's data section.
    /// Empty slice = no delegated content embedded; the prompt
    /// omits the "Referenced files" section entirely.
    ///
    /// Caps (load-bearing, enforced by callers):
    /// - depth = 1 (no recursive `require` following);
    /// - size = ≤ 32 KB per file (truncated mid-line with explicit
    ///   marker);
    /// - paths = explicit safe-relative only (no `..`, no abs, no
    ///   env-var expansion);
    /// - non-text files are NOT embedded (they fall back to
    ///   no-context Amber).
    pub referenced_scripts: &'a [ReferencedScript<'a>],
}

/// Phase 46b Lever #3 — one file the script body delegates to,
/// embedded in the advisor prompt for "fetch IDENTITY" evaluation
/// one level deep.
#[derive(Debug, Clone)]
pub struct ReferencedScript<'a> {
    /// Relative path inside the package root, as it appeared in the
    /// script body (e.g. `./install.js`, `scripts/install.js`).
    pub filename: &'a str,
    /// File contents. May be truncated by the caller — if so the
    /// caller appends the explicit `\n... [truncated for prompt
    /// context]\n` marker so the model knows the embedded view
    /// ends mid-stream.
    pub content: &'a str,
}

/// The advisor's final verdict for one amber script. Only `Approve`
/// converts amber → auto-run; the other two flow into the prompt or
/// hard-block bucket exactly as if no advisor were configured.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AdvisorVerdict {
    /// Confidently safe → auto-run.
    Approve,
    /// Suspicious or risky → human-review prompt.
    Manual,
    /// Could not determine from the script text alone → falls through
    /// to the portable prompt outcome.
    Abstain,
}

/// Distinguishes recoverable setup failures from contract violations.
/// The wizard uses this to decide whether to offer "save anyway":
/// recoverable yes, integration failure no.
#[derive(Debug, Error)]
pub enum AdvisorFailure {
    /// The advisor binary / daemon / model is not ready. Examples:
    /// `claude` not authenticated, `ollama` daemon not running, model
    /// not pulled. The classifier didn't run, but the adapter is
    /// otherwise functional. Wizard may offer save-anyway; install
    /// degrades to advisor=none for that run.
    #[error("environment not ready: {0}")]
    EnvironmentNotReady(String),

    /// The adapter produced an output but couldn't parse a structured
    /// verdict. Indicates a broken invocation contract — prompt
    /// template change, CLI version skew, etc. Wizard blocks save.
    #[error("integration failure: {0}")]
    IntegrationFailure(String),
}

/// Provider adapter. Each provider implements detection (cheap),
/// test invocation (used by the wizard), and per-script
/// classification (used by the audit harness and install-time path).
#[async_trait::async_trait]
pub trait Advisor: Send + Sync {
    /// Which provider this adapter speaks to.
    fn provider(&self) -> Provider;

    /// Quick probe: is this provider available right now? Strict for
    /// Ollama (binary on PATH + HTTP probe to confirm the daemon
    /// answers); `which`-style for the CLI providers.
    async fn detect(&self) -> bool;

    /// Send a known-safe test input and confirm the adapter can
    /// produce a structured verdict end-to-end. Used by the wizard
    /// before persisting `triage-advisor = X`.
    async fn test_invoke(&self) -> Result<AdvisorVerdict, AdvisorFailure>;

    /// Classify one amber lifecycle script.
    async fn classify_amber(
        &self,
        script: &AmberScript<'_>,
    ) -> Result<AdvisorVerdict, AdvisorFailure>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_slug_roundtrip() {
        for p in Provider::all() {
            assert_eq!(Provider::from_slug(p.slug()), Some(*p));
        }
        assert_eq!(Provider::from_slug("none"), None);
        assert_eq!(Provider::from_slug(""), None);
        assert_eq!(Provider::from_slug("openai"), None);
    }

    #[test]
    fn provider_is_local() {
        assert!(Provider::Ollama.is_local());
        assert!(!Provider::ClaudeCli.is_local());
        assert!(!Provider::Codex.is_local());
    }
}
