//! Per-provider adapters.
//!
//! Each adapter knows how to:
//! 1. Detect availability (delegated to [`crate::detection`]).
//! 2. Invoke the provider with our [`crate::build_prompt`] output.
//! 3. Parse stdout / response body into an [`crate::AdvisorVerdict`]
//!    via [`crate::parse_verdict`].
//!
//! The adapter is the only place provider-specific invocation details
//! live; everything above this layer (audit harness, wizard,
//! install-time path) speaks only the [`crate::Advisor`] trait.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::{
    Advisor, AdvisorFailure, AdvisorVerdict, AmberScript, DEFAULT_INVOCATION_TIMEOUT, Provider,
    build_prompt, detection, parse_verdict,
};

const OLLAMA_GENERATE_URL: &str = "http://localhost:11434/api/generate";

/// Default Ollama model. Chosen for ubiquity and small download
/// footprint — users running a different model can override via the
/// `LPM_TRIAGE_OLLAMA_MODEL` env var.
const OLLAMA_DEFAULT_MODEL: &str = "llama3.2";

/// Known-safe test script used by `test_invoke` across all adapters.
/// The expected verdict is `Approve`; an integration failure (no
/// recognised verdict word) indicates a broken adapter, not a
/// disagreement about safety.
const TEST_SCRIPT: AmberScript<'static> = AmberScript {
    package_name: "test-package",
    package_version: "1.0.0",
    phase: "postinstall",
    script_body: "tsc",
};

// ─────────────────────────────────────────────────────────────────────
// claude-cli
// ─────────────────────────────────────────────────────────────────────

/// Adapter for Anthropic's Claude Code CLI.
///
/// Invocation: `claude -p <prompt>` (print mode — one-shot,
/// non-interactive, prints assistant response and exits). Auth is
/// handled by the CLI itself (via `ANTHROPIC_API_KEY` env var or its
/// own login flow).
pub struct ClaudeCliAdapter;

#[async_trait]
impl Advisor for ClaudeCliAdapter {
    fn provider(&self) -> Provider {
        Provider::ClaudeCli
    }

    async fn detect(&self) -> bool {
        detection::detect(Provider::ClaudeCli).await.is_available()
    }

    async fn test_invoke(&self) -> Result<AdvisorVerdict, AdvisorFailure> {
        self.classify_amber(&TEST_SCRIPT).await
    }

    async fn classify_amber(
        &self,
        script: &AmberScript<'_>,
    ) -> Result<AdvisorVerdict, AdvisorFailure> {
        let prompt = build_prompt(script);
        let out = run_with_stdin("claude", &["-p"], &prompt, DEFAULT_INVOCATION_TIMEOUT).await?;
        parse_verdict(&out)
    }
}

// ─────────────────────────────────────────────────────────────────────
// codex
// ─────────────────────────────────────────────────────────────────────

/// Adapter for OpenAI's Codex CLI.
///
/// Invocation: `codex exec <prompt>` reads the prompt from argv and
/// emits assistant output to stdout. Auth via API key or
/// ChatGPT-login that the CLI manages.
pub struct CodexAdapter;

#[async_trait]
impl Advisor for CodexAdapter {
    fn provider(&self) -> Provider {
        Provider::Codex
    }

    async fn detect(&self) -> bool {
        detection::detect(Provider::Codex).await.is_available()
    }

    async fn test_invoke(&self) -> Result<AdvisorVerdict, AdvisorFailure> {
        self.classify_amber(&TEST_SCRIPT).await
    }

    async fn classify_amber(
        &self,
        script: &AmberScript<'_>,
    ) -> Result<AdvisorVerdict, AdvisorFailure> {
        let prompt = build_prompt(script);
        // Codex reads the prompt from stdin in exec mode; passing it
        // via argv risks shell quoting issues with embedded quotes in
        // script bodies. Stdin is robust.
        let out = run_with_stdin("codex", &["exec"], &prompt, DEFAULT_INVOCATION_TIMEOUT).await?;
        parse_verdict(&out)
    }
}

// ─────────────────────────────────────────────────────────────────────
// ollama
// ─────────────────────────────────────────────────────────────────────

/// Adapter for a local Ollama server. Talks the HTTP `/api/generate`
/// endpoint directly — no subprocess. The default model is
/// `llama3.2`; override via `LPM_TRIAGE_OLLAMA_MODEL`.
pub struct OllamaAdapter {
    pub model: String,
    pub url: String,
    pub timeout: Duration,
}

impl Default for OllamaAdapter {
    fn default() -> Self {
        let model = std::env::var("LPM_TRIAGE_OLLAMA_MODEL")
            .unwrap_or_else(|_| OLLAMA_DEFAULT_MODEL.to_string());
        OllamaAdapter {
            model,
            url: OLLAMA_GENERATE_URL.to_string(),
            timeout: DEFAULT_INVOCATION_TIMEOUT,
        }
    }
}

#[derive(Serialize)]
struct OllamaGenerateRequest<'a> {
    model: &'a str,
    prompt: &'a str,
    /// Non-streaming response so we can collect the full output
    /// before parsing.
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaGenerateResponse {
    #[serde(default)]
    response: String,
}

#[async_trait]
impl Advisor for OllamaAdapter {
    fn provider(&self) -> Provider {
        Provider::Ollama
    }

    async fn detect(&self) -> bool {
        detection::detect(Provider::Ollama).await.is_available()
    }

    async fn test_invoke(&self) -> Result<AdvisorVerdict, AdvisorFailure> {
        self.classify_amber(&TEST_SCRIPT).await
    }

    async fn classify_amber(
        &self,
        script: &AmberScript<'_>,
    ) -> Result<AdvisorVerdict, AdvisorFailure> {
        let prompt = build_prompt(script);
        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| AdvisorFailure::IntegrationFailure(format!("ollama client build: {e}")))?;
        let body = OllamaGenerateRequest {
            model: &self.model,
            prompt: &prompt,
            stream: false,
        };
        let resp = client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                // Network-level failure = environment not ready (daemon
                // hung, model still loading, etc.).
                AdvisorFailure::EnvironmentNotReady(format!("ollama request: {e}"))
            })?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            // Ollama returns 404 when the requested model isn't
            // installed — recoverable: user runs `ollama pull <model>`.
            return Err(AdvisorFailure::EnvironmentNotReady(format!(
                "ollama model '{}' not found (try `ollama pull {}`)",
                self.model, self.model,
            )));
        }
        if !status.is_success() {
            return Err(AdvisorFailure::EnvironmentNotReady(format!(
                "ollama returned {status}"
            )));
        }
        let parsed: OllamaGenerateResponse = resp.json().await.map_err(|e| {
            AdvisorFailure::IntegrationFailure(format!("ollama response parse: {e}"))
        })?;
        parse_verdict(&parsed.response)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Shared subprocess helper
// ─────────────────────────────────────────────────────────────────────

/// Spawn `cmd <args> < stdin_input` with a timeout. Returns the
/// child's stdout on success. Maps failure to:
/// - [`AdvisorFailure::EnvironmentNotReady`] when the binary can't be
///   spawned at all (`ENOENT`, permission denied) or when the child
///   exits non-zero (auth failure, model not loaded, etc.). The
///   non-zero exit body is included in the error so the wizard can
///   show it.
/// - [`AdvisorFailure::IntegrationFailure`] when the spawn machinery
///   itself misbehaves (timeout, stdin write failure). Rare; usually
///   indicates a bug or a hung CLI.
async fn run_with_stdin(
    cmd: &str,
    args: &[&str],
    stdin_input: &str,
    timeout: Duration,
) -> Result<String, AdvisorFailure> {
    use std::process::Stdio;

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            AdvisorFailure::EnvironmentNotReady(format!(
                "spawn {cmd}: {e} (is the binary installed and on PATH?)"
            ))
        })?;

    // Write the prompt to stdin, then close so the child sees EOF.
    if let Some(mut stdin) = child.stdin.take() {
        let to_write = stdin_input.to_string();
        let write_handle = tokio::spawn(async move {
            stdin.write_all(to_write.as_bytes()).await?;
            stdin.shutdown().await
        });
        if let Err(e) = write_handle.await {
            return Err(AdvisorFailure::IntegrationFailure(format!(
                "stdin write task join: {e}"
            )));
        }
    }

    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return Err(AdvisorFailure::EnvironmentNotReady(format!(
                "{cmd} wait failed: {e}"
            )));
        }
        Err(_) => {
            return Err(AdvisorFailure::EnvironmentNotReady(format!(
                "{cmd} timed out after {}s",
                timeout.as_secs()
            )));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(AdvisorFailure::EnvironmentNotReady(format!(
            "{cmd} exited with status {}: {}",
            output.status,
            if stderr.is_empty() {
                "<no stderr>"
            } else {
                stderr.as_str()
            }
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Adapters are constructible without side effects.
    #[test]
    fn adapters_construct() {
        let _ = ClaudeCliAdapter;
        let _ = CodexAdapter;
        let _ = OllamaAdapter::default();
    }

    #[test]
    fn ollama_adapter_default_model_from_env() {
        // Default model is overridable via env var; the constructor
        // reads it at instantiation time.
        unsafe {
            std::env::set_var("LPM_TRIAGE_OLLAMA_MODEL", "test-model-xyz");
        }
        let a = OllamaAdapter::default();
        assert_eq!(a.model, "test-model-xyz");
        unsafe {
            std::env::remove_var("LPM_TRIAGE_OLLAMA_MODEL");
        }
    }
}
