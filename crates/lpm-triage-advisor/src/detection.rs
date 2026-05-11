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
///
/// On Windows the file shipped on PATH is normally `<name>.exe` (or
/// `.cmd`), not the bare `<name>` that `Command::new(name)` will
/// resolve via the loader. This walker mirrors the loader: try the
/// bare name first, then each `PATHEXT` extension. Without this, the
/// wizard would hide all three advisors on Windows even though the
/// install is fully functional via `Command::new("claude")`.
fn binary_on_path(name: &str) -> bool {
    resolve_binary_inner(name).is_some()
}

/// Like `binary_on_path` but returns the resolved path. Shared by
/// `resolve_binary` and the wizard's detection probe so PATH+PATHEXT
/// resolution lives in exactly one place.
fn resolve_binary_inner(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let extensions = path_extensions();
    for dir in std::env::split_paths(&path_var) {
        // Bare name first — covers Unix and the rare Windows tool
        // that ships without a PATHEXT-listed extension.
        let bare = dir.join(name);
        if is_executable_file(&bare) {
            return Some(bare);
        }
        // Windows: try each PATHEXT extension. On Unix `extensions`
        // is empty so this loop is a no-op (zero-cost).
        for ext in &extensions {
            let candidate = dir.join(format!("{name}{ext}"));
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Extensions to append to a bare binary name when searching PATH.
/// Empty on Unix (executables ship without an extension). On Windows,
/// read from `PATHEXT` env var; falls back to the documented default
/// set if unset.
#[cfg(windows)]
fn path_extensions() -> Vec<String> {
    let raw = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    raw.split(';')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

#[cfg(not(windows))]
fn path_extensions() -> Vec<String> {
    Vec::new()
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
        // Windows: a file existing at a PATHEXT-resolved location is
        // considered executable. The PATHEXT walk in
        // `resolve_binary_inner` already filters to the platform's
        // canonical executable extensions.
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
/// file matching the provider's canonical name (or `<name>.<ext>` on
/// Windows via PATHEXT). Used by the audit metadata stamp so the
/// report can record which `claude` (or `codex` / `ollama`) was
/// actually invoked.
pub fn resolve_binary(provider: Provider) -> Option<PathBuf> {
    resolve_binary_inner(provider_binary_name(provider))
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
    #[cfg(unix)]
    fn finds_executable_under_synthetic_path() {
        // Build a temp dir, drop an executable file in it, prepend
        // it to PATH, confirm detection finds it. Exercises the full
        // PATH walk + is-executable check on the platform the test
        // is running on (Unix here; Windows tests below).
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("synthetic-tool-xyz");
        std::fs::write(&bin_path, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&bin_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&bin_path, perms).unwrap();

        let prior = std::env::var_os("PATH");
        let mut paths = vec![dir.path().to_path_buf()];
        if let Some(p) = prior.as_ref() {
            paths.extend(std::env::split_paths(p));
        }
        let joined = std::env::join_paths(paths).unwrap();
        // SAFETY: tests in this binary are single-threaded with
        // respect to PATH mutation; the env-var probe path doesn't
        // race with any other test.
        unsafe { std::env::set_var("PATH", &joined) };

        assert!(binary_on_path("synthetic-tool-xyz"));
        let resolved = resolve_binary_inner("synthetic-tool-xyz").unwrap();
        assert_eq!(resolved, bin_path);

        // Restore PATH.
        unsafe {
            match prior {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_walks_pathext_extensions() {
        // Drop a `synthetic.exe` in a temp dir, prepend to PATH, ask
        // detection to find the bare name. Exercises the Windows
        // PATHEXT walker — without it, `binary_on_path("synthetic")`
        // would miss the `.exe`-suffixed file.
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("synthetic.exe");
        std::fs::write(&bin_path, b"MZ").unwrap();

        let prior_path = std::env::var_os("PATH");
        let prior_pathext = std::env::var_os("PATHEXT");
        let mut paths = vec![dir.path().to_path_buf()];
        if let Some(p) = prior_path.as_ref() {
            paths.extend(std::env::split_paths(p));
        }
        let joined = std::env::join_paths(paths).unwrap();
        unsafe {
            std::env::set_var("PATH", &joined);
            std::env::set_var("PATHEXT", ".COM;.EXE;.BAT;.CMD");
        }

        assert!(binary_on_path("synthetic"));
        let resolved = resolve_binary_inner("synthetic").unwrap();
        assert_eq!(resolved, bin_path);

        unsafe {
            match prior_path {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
            match prior_pathext {
                Some(p) => std::env::set_var("PATHEXT", p),
                None => std::env::remove_var("PATHEXT"),
            }
        }
    }

    #[test]
    fn path_extensions_shape_per_platform() {
        let exts = path_extensions();
        #[cfg(windows)]
        {
            assert!(!exts.is_empty(), "Windows must surface PATHEXT entries");
            assert!(
                exts.iter().any(|e| e.eq_ignore_ascii_case(".exe")),
                "PATHEXT must include .exe; got {exts:?}"
            );
        }
        #[cfg(not(windows))]
        {
            assert!(
                exts.is_empty(),
                "non-Windows platforms must not iterate extensions: {exts:?}"
            );
        }
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
