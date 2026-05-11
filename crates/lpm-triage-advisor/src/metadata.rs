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

use crate::{AmberScript, Provider, build_prompt, detection};

/// Canary input for the prompt-template hash. Stable across runs;
/// changing it changes every hash, so don't.
const PROMPT_HASH_CANARY: AmberScript<'static> = AmberScript {
    package_name: "hash-canary",
    package_version: "0.0.0",
    phase: "postinstall",
    script_body: "tsc",
};

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// SHA-256 of the canonical [`build_prompt`] output for the canary
/// input, hex-encoded. Stable iff the prompt template is unchanged.
pub fn prompt_template_hash() -> String {
    let body = build_prompt(&PROMPT_HASH_CANARY);
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
/// Ollama: returns the CLI binary version, not the daemon's loaded
/// model. The model setting lives on
/// [`crate::OllamaAdapter::model`].
pub async fn provider_version(provider: Provider) -> Option<String> {
    let binary = binary_path(provider)?;
    let child = Command::new(&binary)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let output = tokio::time::timeout(VERSION_PROBE_TIMEOUT, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
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
