//! Run-metadata helpers — surface adapter identity so an audit
//! consumer can explain non-determinism in advisor uplift numbers
//! ("same data, same advisor, +1 today vs +2 yesterday").
//!
//! Three fields per run, all best-effort:
//! - Provider slug (always known when an advisor is invoked).
//! - Binary path + version string (where applicable; CLI providers
//!   only — Ollama's "version" is the loaded model name, surfaced
//!   separately via the model setting on [`crate::OllamaAdapter`]).
//! - Prompt-template hash: SHA-256 of the canonical prompt rendering
//!   for a fixed test input. The hash changes iff [`crate::build_prompt`]
//!   changes. Lets a future comparative study attribute uplift drift
//!   to template iterations rather than provider behaviour.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::process::Command;

use crate::{AmberScript, Provider, detection, prompt};

/// Canary input for the prompt-template hash. Stable across runs;
/// changing it changes every hash, so don't.
const PROMPT_HASH_CANARY: AmberScript<'static> = AmberScript {
    package_name: "hash-canary",
    package_version: "0.0.0",
    phase: "postinstall",
    script_body: "tsc",
    // Canary uses `None` so the hash captures the "no repository"
    // render path. Live calls supply `Some(...)` per package; that
    // path is exercised by the prompt unit tests, not the hash canary.
    repository: None,
    // Canary uses an empty referenced-scripts slice so the hash
    // captures the "no embedded files" render path. Calls with
    // referenced files supply non-empty slices; that path is
    // exercised by the prompt unit tests.
    referenced_scripts: &[],
};

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// SHA-256 of the canonical prompt rendering for the canary input,
/// hex-encoded. Stable iff the prompt template is unchanged.
///
/// Computed via [`prompt::build_prompt_with_nonce`] passing the
/// fixed [`prompt::HASH_NONCE`] so the hash is deterministic — the
/// live `build_prompt` uses a fresh random nonce per call, which
/// would otherwise rotate the hash on every invocation.
pub fn prompt_template_hash() -> String {
    let body = prompt::build_prompt_with_nonce(&PROMPT_HASH_CANARY, prompt::HASH_NONCE);
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let digest = hasher.finalize();
    format!("sha256-{}", hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Where the binary lives on disk. None if the provider isn't on
/// PATH (e.g. Ollama configured but binary not installed, or the
/// audit reading a sidecar from a different machine).
pub fn binary_path(provider: Provider) -> Option<PathBuf> {
    detection::resolve_binary(provider)
}

/// Best-effort version string. Spawns `<binary> --version`, captures
/// stdout. Returns `None` on spawn / timeout / non-zero exit; the
/// caller treats absence as "version unknown" without failing.
///
/// **Lifecycle invariant.** A `--version` probe that hangs MUST NOT
/// leak the child process. This function guarantees that:
/// - `kill_on_drop(true)` on the spawned `Command` so any panic /
///   early return between spawn and explicit kill still reaps the
///   child via tokio's drop guard.
/// - On the timeout path, [`tokio::process::Child::start_kill`] is
///   called explicitly so we don't wait for drop semantics to take
///   effect — a hung version probe is a hung child until SIGKILL
///   lands, and the audit may iterate many times before the runtime
///   drops anything.
///
/// Ollama: returns the CLI binary version, not the daemon's loaded
/// model. The model setting lives on
/// [`crate::OllamaAdapter::model`].
pub async fn provider_version(provider: Provider) -> Option<String> {
    let binary = binary_path(provider)?;
    let mut child = Command::new(&binary)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Belt-and-suspenders: if any path here misses an explicit
        // kill, dropping the Child handle still triggers SIGKILL.
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    // Take stdout BEFORE the timeout-wait so we can collect partial
    // output after killing the child without needing `wait_with_output`
    // (which would consume the child handle).
    let mut stdout_pipe = child.stdout.take()?;
    let stdout_handle = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut stdout_pipe, &mut buf).await;
        buf
    });

    let status = match tokio::time::timeout(VERSION_PROBE_TIMEOUT, child.wait()).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return None;
        }
        Err(_timeout) => {
            // Eager kill: don't wait for drop. Then reap so we
            // don't leave a zombie.
            let _ = child.start_kill();
            let _ = child.wait().await;
            return None;
        }
    };

    if !status.success() {
        return None;
    }
    let bytes = stdout_handle.await.ok()?;
    let s = String::from_utf8_lossy(&bytes).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_hash_is_stable_and_deterministic() {
        let h1 = prompt_template_hash();
        let h2 = prompt_template_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256-"));
        assert_eq!(h1.len(), 7 + 64); // "sha256-" + 32 bytes hex
    }
}
