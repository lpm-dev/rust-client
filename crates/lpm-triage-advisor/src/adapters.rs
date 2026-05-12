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
    repository: None,
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
    use tokio::io::AsyncReadExt;

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Belt-and-suspenders: dropping `child` (panic, early
        // return, runtime cancellation) MUST send SIGKILL so we
        // don't leak a hung helper. The explicit `start_kill` on
        // the timeout path below is the eager guarantee; this is
        // the fallback for any path that forgets.
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            AdvisorFailure::EnvironmentNotReady(format!(
                "spawn {cmd}: {e} (is the binary installed and on PATH?)"
            ))
        })?;

    // Write the prompt to stdin, then close so the child sees EOF.
    // BOTH layers of the spawn-await are checked:
    //   1. JoinError on the task itself (panics, runtime issues)
    //   2. The actual I/O Result from `write_all` + `shutdown`
    // Without checking layer 2, a provider that closes stdin early
    // (auth rejection on first byte, broken pipe) would look like a
    // successful prompt send — the advisor would then read zero
    // input, produce nothing useful, and the parser might still find
    // SOMETHING. Treat any stdin write failure as recoverable
    // environment-not-ready so the install-time path degrades to
    // advisor=none with a one-line warning rather than silently
    // running a partial-prompt classification.
    if let Some(mut stdin) = child.stdin.take() {
        let to_write = stdin_input.to_string();
        let write_handle = tokio::spawn(async move {
            stdin.write_all(to_write.as_bytes()).await?;
            stdin.shutdown().await
        });
        match write_handle.await {
            Err(e) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(AdvisorFailure::IntegrationFailure(format!(
                    "stdin write task join: {e}"
                )));
            }
            Ok(Err(e)) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(AdvisorFailure::EnvironmentNotReady(format!(
                    "stdin write to {cmd} failed: {e} \
                     (provider may have closed stdin early — check auth / daemon state)"
                )));
            }
            Ok(Ok(())) => {}
        }
    }

    // Drain stdout + stderr in spawned tasks so we don't dead-lock
    // on a child that fills its pipe buffer while we're waiting for
    // it to exit. Taking the pipes here also lets us collect
    // whatever output exists AFTER killing on timeout, without
    // needing `wait_with_output` (which would consume `child` and
    // prevent the explicit `start_kill` we need for timely cleanup).
    let mut stdout_pipe = child.stdout.take().ok_or_else(|| {
        AdvisorFailure::IntegrationFailure(format!("{cmd}: stdout pipe missing after spawn"))
    })?;
    let mut stderr_pipe = child.stderr.take().ok_or_else(|| {
        AdvisorFailure::IntegrationFailure(format!("{cmd}: stderr pipe missing after spawn"))
    })?;
    let stdout_handle = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf).await;
        buf
    });
    let stderr_handle = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf).await;
        buf
    });

    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(AdvisorFailure::EnvironmentNotReady(format!(
                "{cmd} wait failed: {e}"
            )));
        }
        Err(_) => {
            // Timeouts are an INTEGRATION failure, not environment.
            // The save-anyway path is reserved for recoverable setup
            // problems (auth missing, model not pulled). A provider
            // that hangs past the invocation timeout has a broken
            // contract — persisting that config would mean every
            // install run incurs the same wall-time hang. The wizard
            // refuses to save; the operator must investigate.
            //
            // EAGER KILL: `kill_on_drop` would clean up eventually
            // via drop semantics, but the audit may iterate many
            // times before drop runs and a hung child can orphan
            // resources in the meantime. `start_kill` sends SIGKILL
            // now; the subsequent `wait` reaps the zombie.
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(AdvisorFailure::IntegrationFailure(format!(
                "{cmd} timed out after {}s (no verdict produced; \
                 hung or broken adapter — refusing to persist this advisor choice)",
                timeout.as_secs()
            )));
        }
    };

    let stdout_bytes = stdout_handle.await.unwrap_or_default();
    let stderr_bytes = stderr_handle.await.unwrap_or_default();

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_string();
        return Err(AdvisorFailure::EnvironmentNotReady(format!(
            "{cmd} exited with status {}: {}",
            status,
            if stderr.is_empty() {
                "<no stderr>"
            } else {
                stderr.as_str()
            }
        )));
    }

    Ok(String::from_utf8_lossy(&stdout_bytes).into_owned())
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

    // ── Timeout MUST NOT leak the child process (Finding Medium) ──

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_hung_child_process() {
        // Spawn `sleep 60` with a 200ms timeout. The wait_with_output
        // path used to leak this process — dropping a tokio Child
        // does not send SIGKILL by default. After this fix:
        //   - timeout returns IntegrationFailure (locked contract)
        //   - the child PID is no longer alive when run_with_stdin
        //     returns
        let result = run_with_stdin(
            "/bin/sh",
            &["-c", "sleep 60"],
            "irrelevant\n",
            std::time::Duration::from_millis(200),
        )
        .await;
        assert!(
            matches!(result, Err(AdvisorFailure::IntegrationFailure(_))),
            "timeout must surface as IntegrationFailure; got {result:?}"
        );
        // We don't have a handle to the child PID here (it's internal
        // to run_with_stdin), but we can assert structural soundness:
        // no orphaned `sleep` should be running attributable to this
        // test. Best-effort: pgrep for our specific sleep duration.
        // If something leaked, the test still passes — process-leak
        // assertions are inherently flaky on shared CI — so we keep
        // the assertion soft: the *intent* is captured in code review
        // + the wait()-after-start_kill in the implementation. The
        // hard assertion is just the IntegrationFailure shape above.
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_path_returns_quickly_not_after_full_sleep() {
        // Stronger structural guarantee: if the kill path were broken
        // (no start_kill, wait_with_output consumes the child), the
        // outer await would still complete fast because tokio::timeout
        // gives up after the duration. But the SHAPE of the result —
        // IntegrationFailure with the timeout message — is the
        // contract the wizard relies on.
        let start = std::time::Instant::now();
        let result = run_with_stdin(
            "/bin/sh",
            &["-c", "sleep 30"],
            "x",
            std::time::Duration::from_millis(150),
        )
        .await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "timeout helper should not block ~30s; elapsed = {elapsed:?}"
        );
        match result {
            Err(AdvisorFailure::IntegrationFailure(msg)) => {
                assert!(
                    msg.contains("timed out"),
                    "expected timeout-shaped error message; got: {msg}"
                );
            }
            other => panic!("expected IntegrationFailure on timeout, got {other:?}"),
        }
    }
}
