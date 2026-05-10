//! Provider detection. Cheap probes used by both the audit harness
//! and the eventual wizard to decide which providers are available
//! on this machine right now.
//!
//! - CLI providers (`claude-cli`, `codex`): "binary on PATH" via a
//!   `which`-style PATH walk. No subprocess spawn — we only check
//!   that the file exists and is marked executable.
//! - Ollama: PATH walk **plus** an HTTP probe to
//!   `http://localhost:11434/api/tags` (the standard tag-list
//!   endpoint). The binary on PATH is necessary but not sufficient —
//!   the daemon must also be running to answer classification
//!   requests. The strict probe matches the user's recommendation:
//!   "the thing that actually matters is whether a local server is
//!   available to answer."
//!
//! Detection is intentionally non-mutating: it never starts daemons
//! or downloads models. The wizard's `test_invoke` step covers
//! "configured + usable"; this layer answers "could plausibly be
//! configured."

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::Provider;

const OLLAMA_DEFAULT_PROBE_URL: &str = "http://localhost:11434/api/tags";
const OLLAMA_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Per-provider detection result, used for the wizard's "what's
/// already on this machine?" listing.
#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub provider: Provider,
    /// Is the provider's binary on `PATH`?
    pub binary_present: bool,
    /// For Ollama: does the daemon answer the tag-list probe?
    /// `None` for non-Ollama providers (probe not applicable).
    pub daemon_reachable: Option<bool>,
}

impl ProbeReport {
    /// Did the probe pass strict detection for this provider?
    pub fn is_available(&self) -> bool {
        match self.provider {
            Provider::Ollama => self.binary_present && self.daemon_reachable == Some(true),
            Provider::ClaudeCli | Provider::Codex => self.binary_present,
        }
    }
}

/// Probe one provider. Cheap — bounded latency (PATH walk is local;
/// the Ollama HTTP probe has a 500ms timeout).
pub async fn detect(provider: Provider) -> ProbeReport {
    let bin = provider_binary_name(provider);
    let binary_present = binary_on_path(bin);
    let daemon_reachable = match provider {
        Provider::Ollama => Some(ollama_daemon_reachable().await),
        _ => None,
    };
    ProbeReport {
        provider,
        binary_present,
        daemon_reachable,
    }
}

/// Probe every supported provider in parallel and return the reports
/// in canonical order. The wizard uses this to render its menu.
#[allow(dead_code)] // Wizard surface — consumed once `lpm config triage` lands.
pub async fn probe_all() -> Vec<ProbeReport> {
    let mut handles = Vec::new();
    for p in Provider::all() {
        let p = *p;
        handles.push(tokio::spawn(async move { detect(p).await }));
    }
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(r) = h.await {
            out.push(r);
        }
    }
    out
}

fn provider_binary_name(provider: Provider) -> &'static str {
    match provider {
        Provider::Ollama => "ollama",
        Provider::ClaudeCli => "claude",
        Provider::Codex => "codex",
    }
}

/// Standard `which`-style PATH walk. Skipped if PATH is unset (rare
/// but real on minimal CI runners).
fn binary_on_path(name: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| is_executable_file(&dir.join(name)))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        // Windows: we'd need to walk PATHEXT to be strict. For v1, a
        // file existing at `<dir>/<name>` is good enough for the
        // wizard to surface the option and let test_invoke decide.
        let _ = path; // suppress unused-variable warning
        true
    }
}

async fn ollama_daemon_reachable() -> bool {
    // Bounded HTTP probe. Failure = unreachable, regardless of cause
    // (no daemon, port firewalled, daemon hung). We deliberately
    // don't distinguish; the goal is "would classify_amber work right
    // now" and a non-response means no.
    let Ok(client) = reqwest::Client::builder()
        .timeout(OLLAMA_PROBE_TIMEOUT)
        .build()
    else {
        return false;
    };
    client
        .get(OLLAMA_DEFAULT_PROBE_URL)
        .send()
        .await
        .is_ok_and(|r| r.status().is_success())
}

/// Best-effort: locate the binary for a provider. Returns the
/// absolute path of the first PATH entry that contains an executable
/// file matching the provider's canonical name. Used by adapters to
/// invoke the provider without re-walking PATH every call.
#[allow(dead_code)] // Reserved for a future optimisation (avoid PATH re-walk per call).
pub fn resolve_binary(provider: Provider) -> Option<PathBuf> {
    let name = provider_binary_name(provider);
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|p| is_executable_file(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_name_per_provider() {
        assert_eq!(provider_binary_name(Provider::Ollama), "ollama");
        assert_eq!(provider_binary_name(Provider::ClaudeCli), "claude");
        assert_eq!(provider_binary_name(Provider::Codex), "codex");
    }

    #[test]
    fn missing_binary_is_not_on_path() {
        assert!(!binary_on_path(
            "definitely-not-a-real-binary-name-12345abcdef"
        ));
    }

    #[test]
    fn probe_report_is_available_logic() {
        let r = ProbeReport {
            provider: Provider::Ollama,
            binary_present: true,
            daemon_reachable: Some(true),
        };
        assert!(r.is_available());

        let r = ProbeReport {
            provider: Provider::Ollama,
            binary_present: true,
            daemon_reachable: Some(false),
        };
        assert!(!r.is_available()); // strict: binary alone is not enough

        let r = ProbeReport {
            provider: Provider::ClaudeCli,
            binary_present: true,
            daemon_reachable: None,
        };
        assert!(r.is_available());

        let r = ProbeReport {
            provider: Provider::Codex,
            binary_present: false,
            daemon_reachable: None,
        };
        assert!(!r.is_available());
    }
}
