//! Parent-side wiring for the AppContainer backend.
//!
//! This is the half that lives in the `lpm.exe` process — it builds
//! the helper argv from a [`SandboxedCommand`] and spawns
//! `lpm-sandbox-helper.exe`, which in turn does the AppContainer
//! dance (see [`crate::helper_appcontainer`] for the helper-side
//! mechanism).
//!
//! ## Why a separate module
//!
//! The [`crate::windows::WindowsSandbox`] stays UNTOUCHED
//! () — its `decide_posture` table refuses
//! strict-without-degraded, which is the right answer for the Low
//! IL fallback path. AppContainer's posture is different: it
//! always delivers strict (filesystem + network) when requested.
//! The factory in [`crate`]-side `platform_backend` picks between
//! the two backends based on whether
//! [`locate_sandbox_helper`] finds a helper binary.
//!
//! ## What this module DOES touch in the parent
//!
//! - Builds the argv block that the helper consumes (renders
//!   readable_allow_set + writable_allow_set into `--readable-dir` /
//!   `--writable-dir` flags).
//! - Captures the MSVC build environment once per process via
//!   `vcvarsall.bat` so AppContainer'd `node-gyp rebuild` keeps
//!   working without the COM-denied `vswhere` lookup.
//! - Probes for the helper binary location (npm sibling, env var
//!   override) and falls back gracefully if it's missing.
//!
//! All AppContainer-specific Win32 calls happen INSIDE the helper
//! — this module is plain `Command::spawn` against an argv vector.

#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::OnceLock;

use crate::helper_protocol::{APPCONTAINER_NAME, PROTOCOL_VERSION, StdioMode};
use crate::{
    Sandbox, SandboxError, SandboxMode, SandboxOptions, SandboxPosture, SandboxSpec, SandboxStdio,
    SandboxedCommand,
};

// ── Backend struct ───────────────────────────────────────────────────

/// AppContainer backend. Constructed by
/// the factory in [`crate`]-side `platform_backend` when the helper
/// binary is reachable; otherwise the factory falls back to
/// [`crate::windows::WindowsSandbox`] (the Low IL path).
#[derive(Debug)]
pub(crate) struct AppContainerSandbox {
    spec: SandboxSpec,
    mode: SandboxMode,
    posture: BackendPosture,
    helper_path: PathBuf,
}

/// Internal posture tag for the AppContainer backend. Strict means
/// "no capabilities → full default-deny including outbound network";
/// Default means "InternetClient capability granted → outbound
/// network allowed". Unlike the Low IL backend, there is
/// no `Degraded` variant — AppContainer delivers full strict
/// (filesystem + network) when requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendPosture {
    /// `deny_outbound_network = false`. Capability list contains
    /// `InternetClient`. Public posture: [`SandboxPosture::Default`].
    Default,
    /// `deny_outbound_network = true`. Empty capability list.
    /// Public posture: [`SandboxPosture::Strict`].
    Strict,
}

impl AppContainerSandbox {
    /// Construct the backend. `helper_path` is the absolute path to
    /// `lpm-sandbox-helper.exe` resolved by [`locate_sandbox_helper`].
    pub(crate) fn new(
        spec: SandboxSpec,
        mode: SandboxMode,
        options: SandboxOptions,
        helper_path: PathBuf,
    ) -> Result<Self, SandboxError> {
        match mode {
            SandboxMode::Enforce => {
                let posture = decide_appcontainer_posture(
                    options.deny_outbound_network,
                    options.allow_degraded,
                )?;
                Ok(Self {
                    spec,
                    mode,
                    posture,
                    helper_path,
                })
            }
            // Same shape as the WindowsSandbox backend: no native
            // AppContainer "audit-only" primitive, so LogOnly
            // surfaces with a clear pointer to --no-sandbox.
            SandboxMode::LogOnly => Err(SandboxError::ModeNotSupportedOnPlatform {
                platform: "windows".to_string(),
                mode: SandboxMode::LogOnly,
                remediation: "AppContainer has no native observe-only \
                              primitive. To debug a sandbox \
                              false-positive, re-run with --no-sandbox. \
                              `--sandbox-log` remains available on macOS."
                    .to_string(),
            }),
            // Disabled is short-circuited to NoopSandbox by the
            // factory before reaching here; defensive guard for
            // contract drift.
            SandboxMode::Disabled => Err(SandboxError::InvalidSpec {
                reason: "SandboxMode::Disabled reached AppContainerSandbox — should have been \
                         routed to NoopSandbox by the factory"
                    .to_string(),
            }),
        }
    }
}

/// Posture decision. Pure (inputs in, outcome out).
///
/// Unlike [`crate::windows::decide_posture`], this function never
/// refuses — AppContainer can deliver full strict on every
/// Windows host that has the helper binary. `allow_degraded` is
/// accepted for symmetry with the Low IL backend's signature but
/// unused: there is no "fall back to filesystem-only" arm in the
/// AppContainer path.
///
/// Keeping the two backends' decisions separate (rather than
/// editing the function in place) preserves the Low IL
/// fallback's strict-without-degraded refusal contract — see plan
/// 
pub(crate) fn decide_appcontainer_posture(
    deny_outbound_network: bool,
    _allow_degraded: bool,
) -> Result<BackendPosture, SandboxError> {
    if deny_outbound_network {
        Ok(BackendPosture::Strict)
    } else {
        Ok(BackendPosture::Default)
    }
}

// ── Sandbox trait impl ───────────────────────────────────────────────

impl Sandbox for AppContainerSandbox {
    fn spawn(&self, cmd: SandboxedCommand) -> Result<Child, SandboxError> {
        let mut helper_cmd = Command::new(&self.helper_path);

        // Protocol version + container name come first — the helper
        // refuses argv with a mismatched version before doing any
        // AppContainer work.
        helper_cmd
            .arg("--protocol-version")
            .arg(PROTOCOL_VERSION.to_string());
        helper_cmd.arg("--appcontainer-name").arg(APPCONTAINER_NAME);

        // Broad-read grants (the cross-platform "reads broad"
        // contract). The helper applies DACL R+X ACEs on these.
        for dir in readable_allow_set(&self.spec) {
            helper_cmd.arg("--readable-dir").arg(dir);
        }
        // Tool-dir grants derived
        // from the lifecycle child's PATH, derived at spawn time.
        // `C:\Program Files\nodejs` (and similar third-party
        // installer dirs) ship with an `ALL_APPLICATION_PACKAGES`
        // ACE that AppContainer matches by default — empirically
        // that's wrong: the Node.js installer leaves the dir with
        // a `BUILTIN\Users:(I)(RX)` ACE only, which AppContainer
        // does NOT match. Without explicit grants the lifecycle
        // child's `cmd /c node install.js` fails with `'node' is
        // not recognized as an internal or external command`.
        //
        // Routed through `--readable-dir-best-effort` (NOT
        // `--readable-dir`) because PATH entries are frequently
        // SYSTEM-owned (`C:\Program Files\…`); unprivileged
        // `lpm.exe` can't modify their DACL and a strict grant
        // would fail the spawn entirely. The spec-derived
        // entries above (project_dir, ~/.nvm/versions,
        // writable_allow_set) stay on `--readable-dir` /
        // `--writable-dir` with the strict-root contract; only
        // these PATH-derived entries opt into the WARN-and-continue
        // semantics. See "Other (non-MSVC)
        // COM-dependent lifecycle scripts still break" row.
        for dir in tool_dirs_needing_explicit_grant(&cmd) {
            helper_cmd.arg("--readable-dir-best-effort").arg(dir);
        }
        // Narrow-write grants (mirrors + the macOS/Linux
        // backends' writable-set). DACLs are additive, so an entry
        // appearing in both lists ends up R+W+X — fine.
        for dir in crate::windows::writable_allow_set(&self.spec) {
            helper_cmd.arg("--writable-dir").arg(dir);
        }

        if let Some(dir) = &cmd.current_dir {
            helper_cmd.arg("--working-dir").arg(dir);
        }

        if cmd.env_clear {
            helper_cmd.arg("--env-clear");
        }

        // Lazily-cached MSVC
        // build environment from `vcvarsall.bat` (the parent has
        // full COM access; the AppContainer child does not, and
        // `node-gyp rebuild` relies on the discovery surface
        // `vswhere`/`ISetupConfiguration` provides). The captured
        // env is injected before caller env so caller settings win
        // on overlap.
        //
        // Failure here is non-fatal: packages without native deps
        // don't need it, and native rebuilds without it will fail
        // clearly at `cl.exe`-not-found rather than silently.
        //
        // **Case-insensitive dedup.** Windows env var lookups are
        // case-insensitive (CRT-side `getenv` ignores case), but
        // a Rust `HashSet<OsString>` is exact-match. Without
        // normalization the caller's `Path` and vcvarsall's `PATH`
        // are treated as different keys and BOTH flow into the
        // helper's `--env` list — and on the helper side any env
        // block builder that doesn't also dedup case-insensitively
        // ships both to the child, where override order is then a
        // function of insertion order rather than a documented
        // contract. Matches the [`crate::commands::rebuild`]
        // `find_env_case_insensitive` precedent for the same
        // hazard on the path.
        let caller_keys_lower: std::collections::HashSet<String> = cmd
            .envs
            .iter()
            .map(|(k, _)| k.to_string_lossy().to_ascii_lowercase())
            .collect();
        match capture_msvc_env() {
            Ok(msvc_env) => {
                for (k, v) in msvc_env {
                    if caller_keys_lower.contains(&k.to_ascii_lowercase()) {
                        continue; // caller's explicit env wins
                    }
                    let mut kv = OsString::from(k);
                    kv.push("=");
                    kv.push(v);
                    helper_cmd.arg("--env").arg(kv);
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "lpm_sandbox::windows_appcontainer",
                    "MSVC toolchain env capture failed: {e}. \
                     Native rebuilds inside the AppContainer will fail at \
                     cl.exe-not-found unless the caller supplied the MSVC \
                     env explicitly."
                );
            }
        }
        for (k, v) in &cmd.envs {
            let mut kv = OsString::from(k);
            kv.push("=");
            kv.push(v);
            helper_cmd.arg("--env").arg(kv);
        }

        helper_cmd
            .arg("--stdio-stdin")
            .arg(stdio_for_argv(cmd.stdin).as_str());
        helper_cmd
            .arg("--stdio-stdout")
            .arg(stdio_for_argv(cmd.stdout).as_str());
        helper_cmd
            .arg("--stdio-stderr")
            .arg(stdio_for_argv(cmd.stderr).as_str());

        // Default posture grants InternetClient; Strict omits the
        // flag for an empty capability list.
        if matches!(self.posture, BackendPosture::Default) {
            helper_cmd.arg("--grant-internet-client");
        }

        // Separator + lifecycle child argv.
        helper_cmd.arg("--");
        helper_cmd.arg(&cmd.program);
        for a in &cmd.args {
            helper_cmd.arg(a);
        }

        // The parent connects its own stdio to the helper; the
        // helper inherits + forwards to the lifecycle child. We DO
        // NOT call `env_clear` on the helper command itself —
        // capture_msvc_env's lookup relies on inheriting our env to
        // find the vswhere/cmd-line tools.
        helper_cmd.stdout(std::process::Stdio::from(cmd.stdout));
        helper_cmd.stderr(std::process::Stdio::from(cmd.stderr));
        helper_cmd.stdin(std::process::Stdio::from(cmd.stdin));

        helper_cmd.spawn().map_err(|e| SandboxError::SpawnFailed {
            reason: format!(
                "failed to spawn lpm-sandbox-helper at {}: {e}",
                self.helper_path.display(),
            ),
        })
    }

    fn backend_name(&self) -> &'static str {
        "windows-appcontainer"
    }

    fn mode(&self) -> SandboxMode {
        self.mode
    }

    fn posture(&self) -> SandboxPosture {
        match self.posture {
            BackendPosture::Strict => SandboxPosture::Strict,
            BackendPosture::Default => SandboxPosture::Default,
        }
    }
}

fn stdio_for_argv(s: SandboxStdio) -> StdioMode {
    match s {
        SandboxStdio::Inherit => StdioMode::Inherit,
        SandboxStdio::Piped => StdioMode::Piped,
        SandboxStdio::Null => StdioMode::Null,
    }
}

// ── Allow-set rendering ──────────────────────────────────────────────

/// Directories the lifecycle child needs Read access to. Mirrors
/// the cross-platform "reads broad" contract from
/// [`crate::seatbelt`] / [`crate::landlock_rules::describe_rules`].
///
/// System paths (`C:\Windows`, `C:\Windows\System32`, etc.) are NOT
/// listed — Windows ships them with an `ALL_APPLICATION_PACKAGES`
/// ACE that AppContainer processes match by default, so no extra
/// grant is needed.
///
/// `project_dir` is the broad-tree readable root mentioned in the
/// The narrow writable subset within it
/// (`node_modules`, `.husky`, `.lpm`) lives in
/// [`crate::windows::writable_allow_set`]; DACLs are additive so
/// overlap is fine.
pub(crate) fn readable_allow_set(spec: &SandboxSpec) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(2);
    out.push(spec.project_dir.clone());
    let nvm = spec.home_dir.join(".nvm").join("versions");
    out.push(nvm);
    out
}

/// Enumerate PATH directories from the caller-supplied env that
/// need an explicit DACL grant for the AppContainer SID.
///
/// Skips directories that stock Windows already grants
/// `ALL_APPLICATION_PACKAGES` access on (System32, SysWOW64, the
/// bare Windows dir): re-applying the grant would only add walk
/// time without changing observable behavior.
///
/// Skips empty + non-existent entries silently — invalid PATH
/// entries are the user's bug to report, not ours to fail on.
///
/// Falls back to the parent's own PATH when the caller didn't
/// supply one. This keeps `cmd /c node install.js` working under
/// the install pipeline's typical `env_clear = true; envs =
/// sanitized` shape: the parent's PATH (already filtered through
/// `build_sanitized_env`) is the only PATH source.
fn tool_dirs_needing_explicit_grant(cmd: &SandboxedCommand) -> Vec<PathBuf> {
    let path_value: Option<OsString> = cmd
        .envs
        .iter()
        .find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.clone())
        .or_else(|| std::env::var_os("PATH"));
    let Some(path_raw) = path_value else {
        return Vec::new();
    };

    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));

    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for entry in std::env::split_paths(&path_raw) {
        if entry.as_os_str().is_empty() {
            continue;
        }
        if !entry.exists() {
            continue;
        }
        // Skip dirs already covered by stock Windows ACEs (no
        // perf benefit to re-walking System32). The starts_with
        // check is canonical-path-friendly because Windows PATH
        // entries are typically lowercase normalized in our env.
        if is_under_system_root(&entry, &system_root) {
            continue;
        }
        // Dedup canonicalized paths so case-only variants don't
        // double the DACL walk cost.
        let canon = std::fs::canonicalize(&entry).unwrap_or_else(|_| entry.clone());
        if !seen.insert(canon.clone()) {
            continue;
        }
        out.push(entry);
    }
    out
}

fn is_under_system_root(candidate: &std::path::Path, system_root: &std::path::Path) -> bool {
    let Ok(c) = candidate.canonicalize() else {
        // If canonicalization fails (e.g. permissions on a parent
        // dir), be conservative and assume NOT system-rooted so
        // the caller still grants the path. Better to walk an
        // unnecessary dir than to leave the AppContainer unable
        // to access a tool the user expects in PATH.
        return false;
    };
    let s = system_root
        .canonicalize()
        .unwrap_or_else(|_| system_root.to_path_buf());
    c.starts_with(&s)
}

// ── Helper locator ───────────────────────────────────────────────────

/// Find `lpm-sandbox-helper.exe`. Two-step probe:
///
/// 1. `LPM_SANDBOX_HELPER` env override (used by integration tests
///    and advanced deployments).
/// 2. Sibling of [`std::env::current_exe`] — the npm package
///    layout places `lpm-sandbox-helper.exe` next to `lpm.exe`.
///
/// Returns `None` when neither is reachable; the caller falls back
/// to the Low IL backend.
pub fn locate_sandbox_helper() -> Option<PathBuf> {
    if let Some(raw) = std::env::var_os("LPM_SANDBOX_HELPER") {
        let p = PathBuf::from(raw);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        let candidate = parent.join("lpm-sandbox-helper.exe");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

// ── MSVC toolchain env capture ───────────────────────────────────

/// Why the capture exists: AppContainer denies the COM activation
/// path `vswhere.exe` (and node-gyp's other VS discovery) uses, so
/// every native-rebuild fixture would break under Strict. The
/// parent (Medium IL, full COM) asks Microsoft's own
/// `vcvarsall.bat` to render the build env and we inject the
/// resulting env vars into the AppContainer child via the helper's
/// `--env` argv plumbing. 
/// off vs hand-rolled VS discovery (`vcvarsall.bat` is Microsoft's
/// official setup entry point and rides their cross-version drift
/// surface; hand-rolled discovery would be ~5-10× the ongoing
/// maintenance load).
///
/// Caching: `OnceLock` so the ~50-200 ms vcvarsall invocation
/// fires at most once per `lpm-rs` process. Subsequent
/// `AppContainerSandbox::spawn` calls reuse the cached result.
static MSVC_ENV: OnceLock<Result<HashMap<String, String>, String>> = OnceLock::new();

/// Capture the MSVC build environment lazily. Returns a borrow of
/// the cached `Result` so the spawn path can render it into the
/// helper's `--env` argv without re-running vcvarsall.
fn capture_msvc_env() -> Result<&'static HashMap<String, String>, &'static str> {
    let cached = MSVC_ENV.get_or_init(do_capture_msvc_env);
    cached.as_ref().map_err(|s| s.as_str())
}

fn do_capture_msvc_env() -> Result<HashMap<String, String>, String> {
    // Step 1: locate vswhere.exe. Microsoft has shipped it at this
    // fixed path since VS 2017; an installation without it would
    // also be missing `vcvarsall.bat`, so there's no fallback.
    let vswhere =
        PathBuf::from(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe");
    if !vswhere.exists() {
        return Err("vswhere.exe not found at the standard location; \
             Visual Studio / BuildTools 2017+ doesn't appear to be installed"
            .to_string());
    }

    // Step 2: ask vswhere for ALL VS install paths.
    //
    // Deliberately NO `-latest` and NO `-requires` filter:
    //
    // - `-latest` would return a single install — typically a
    //   newer IDE or Preview SKU. On hosts with side-by-side VS
    //   installs (common on dev machines: VS Preview for IDE +
    //   BuildTools for headless builds), the newest install often
    //   lacks the C++ workload, so `vcvarsall.bat` is absent.
    //   Picking that one and giving up would mask an older
    //   working BuildTools install with the workload present.
    //
    // - `-requires` would mask the cross-arch case:
    //   round-3 fix demonstrated that hardcoding
    //   `Microsoft.VisualStudio.Component.VC.Tools.x86.x64`
    //   wouldn't match an ARM64-only host. Let `vcvarsall.bat`
    //   itself reject if the matching toolchain isn't installed
    //   for the host arch.
    //
    // Strategy: enumerate every install, pick the first one whose
    // `VC/Auxiliary/Build/vcvarsall.bat` exists. vswhere lists
    // installs newest-first by default, so this preserves the
    // "prefer newest" intent while gracefully falling back when
    // the newest install lacks the workload.
    let vs_root_output = Command::new(&vswhere)
        .args([
            "-prerelease",
            "-property",
            "installationPath",
            "-products",
            "*",
        ])
        .output()
        .map_err(|e| format!("vswhere.exe spawn failed: {e}"))?;
    if !vs_root_output.status.success() {
        return Err(format!(
            "vswhere.exe returned {:?}; stderr: {}",
            vs_root_output.status,
            String::from_utf8_lossy(&vs_root_output.stderr),
        ));
    }
    let vs_root_raw = String::from_utf8_lossy(&vs_root_output.stdout).into_owned();
    let candidate_roots: Vec<&str> = vs_root_raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if candidate_roots.is_empty() {
        return Err("vswhere.exe returned no Visual Studio installations; \
             the host has the installer but no VS edition installed"
            .to_string());
    }

    // Step 3: build the full candidate list — every install whose
    // `vcvarsall.bat` exists, in vswhere's newest-first order.
    let candidate_vcvarsall: Vec<PathBuf> = candidate_roots
        .iter()
        .map(|root| {
            PathBuf::from(root)
                .join("VC")
                .join("Auxiliary")
                .join("Build")
                .join("vcvarsall.bat")
        })
        .filter(|c| c.exists())
        .collect();
    if candidate_vcvarsall.is_empty() {
        return Err(format!(
            "none of the {n} Visual Studio install(s) reported by vswhere \
             contain vcvarsall.bat (no C/C++ workload installed)",
            n = candidate_roots.len(),
        ));
    }

    // Step 4: try each install in order. A `vcvarsall.bat` that's
    // PRESENT but produces a runtime error (wrong toolset for the
    // host arch, missing matching SDK, etc.) must NOT block
    // fallback to an older install whose batch file does succeed.
    // The audit's medium-severity finding was that the prior
    // version returned eagerly on the first vcvarsall RUN failure;
    // this loop closes that hole.
    let arch = std::env::var("LPM_MSVC_TARGET")
        .ok()
        .unwrap_or_else(|| host_msvc_arch().to_string());
    let mut errors: Vec<String> = Vec::new();
    for vcvarsall in &candidate_vcvarsall {
        match try_capture_from_vcvarsall(vcvarsall, &arch) {
            Ok(additions) => return Ok(additions),
            Err(e) => {
                errors.push(format!("{}: {e}", vcvarsall.display()));
            }
        }
    }
    Err(format!(
        "tried {n} Visual Studio install(s); none produced a usable MSVC env. \
         Per-install errors:\n  - {detail}",
        n = candidate_vcvarsall.len(),
        detail = errors.join("\n  - "),
    ))
}

/// Run `vcvarsall.bat <arch>` for one install and parse its env
/// dump. Returns the additions/overrides on success; a
/// human-readable failure reason on any error so the caller can
/// aggregate per-install diagnostics.
fn try_capture_from_vcvarsall(
    vcvarsall: &std::path::Path,
    arch: &str,
) -> Result<HashMap<String, String>, String> {
    // Use `raw_arg` to bypass Rust's auto-arg-quoting: with regular
    // `arg`, Rust wraps the argument in quotes because it contains
    // spaces, and cmd ends up seeing the entire `/c "..."` payload
    // as one over-quoted token. The documented pattern for `cmd /c
    // <quoted-command>` is `/S /c "<command>"` so cmd strips the
    // OUTERmost pair of quotes; see Windows command-line docs.
    let raw_cmd_line = format!("/S /c \"\"{}\" {arch} && set\"", vcvarsall.display());
    let output = Command::new("cmd.exe")
        .raw_arg(&raw_cmd_line)
        .output()
        .map_err(|e| format!("cmd.exe spawn for vcvarsall failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "vcvarsall.bat returned {:?}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    // Parse KEY=VALUE lines from stdout. vcvarsall prints banner
    // lines (e.g. `**********************************`,
    // `** Visual Studio ...`) before the `set` dump; skip lines
    // that don't contain `=` or whose key half contains a space
    // (banner-shaped output that snuck through).
    let dump = String::from_utf8_lossy(&output.stdout);
    let new_env: HashMap<String, String> = dump
        .lines()
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            if k.is_empty() || k.contains(' ') {
                return None;
            }
            Some((k.to_string(), v.to_string()))
        })
        .collect();
    if new_env.is_empty() {
        return Err(
            "vcvarsall.bat exited 0 but produced no parseable KEY=VALUE lines; \
             possible Windows-version drift in the banner format"
                .to_string(),
        );
    }

    // Diff against the pre-spawn env. Anything vcvarsall added or
    // changed is what we need to inject into the child; values
    // unchanged from our env don't need to be set (they'd be
    // inherited anyway).
    let pre_env: HashMap<String, String> = std::env::vars().collect();
    let mut additions = HashMap::new();
    for (k, v) in &new_env {
        match pre_env.get(k) {
            Some(prev) if prev == v => {}
            _ => {
                additions.insert(k.clone(), v.clone());
            }
        }
    }
    Ok(additions)
}

/// Best-effort host-arch token for `vcvarsall.bat`. The pattern
/// `vcvarsall.bat <arch>` accepts host-build pairs (`x64`,
/// `arm64`, `x86_x64`, etc.); we default to the host-only build
/// for the running architecture.
fn host_msvc_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        // Other Windows architectures aren't shipped by the lpm
        // release matrix; default to x64 which is the workspace's
        // primary target and let vcvarsall surface a clear error
        // if the host can't run it.
        "x64"
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxSpec;
    use std::path::PathBuf;

    fn make_spec() -> SandboxSpec {
        SandboxSpec {
            package_dir: PathBuf::from("C:/store/pkg@1"),
            project_dir: PathBuf::from("C:/proj"),
            package_name: "pkg".to_string(),
            package_version: "1.0.0".to_string(),
            store_root: PathBuf::from("C:/store"),
            home_dir: PathBuf::from("C:/Users/u"),
            tmpdir: PathBuf::from("C:/Users/u/AppData/Local/Temp"),
            extra_write_dirs: Vec::new(),
        }
    }

    #[test]
    fn decide_appcontainer_posture_strict_when_deny_outbound_set() {
        let p = decide_appcontainer_posture(true, false).expect("strict");
        assert_eq!(p, BackendPosture::Strict);
    }

    #[test]
    fn decide_appcontainer_posture_default_when_deny_outbound_unset() {
        let p = decide_appcontainer_posture(false, false).expect("default");
        assert_eq!(p, BackendPosture::Default);
    }

    #[test]
    fn decide_appcontainer_posture_ignores_allow_degraded() {
        // AppContainer delivers full strict regardless of
        // allow_degraded — the flag only matters for the Low IL
        // fallback path.
        for ag in [false, true] {
            assert_eq!(
                decide_appcontainer_posture(true, ag).expect("strict"),
                BackendPosture::Strict,
                "allow_degraded={ag} should not affect AppContainer posture",
            );
        }
    }

    #[test]
    fn readable_allow_set_contains_project_root_and_nvm_versions() {
        let spec = make_spec();
        let set = readable_allow_set(&spec);
        assert!(
            set.iter().any(|p| p == &spec.project_dir),
            "readable_allow_set must include project_dir; got: {set:?}",
        );
        assert!(
            set.iter()
                .any(|p| p == &spec.home_dir.join(".nvm").join("versions")),
            "readable_allow_set must include ~/.nvm/versions for toolchain probes; got: {set:?}",
        );
    }

    #[test]
    fn locate_sandbox_helper_prefers_env_override() {
        // Create a tempfile that "looks like" the helper, set the
        // override, verify the locator returns it.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_path_buf();
        // SAFETY: tests run with single-threaded `cargo test` by
        // default for this crate; the workspace doesn't `set_var`
        // from concurrent threads.
        unsafe {
            std::env::set_var("LPM_SANDBOX_HELPER", &path);
        }
        let located = locate_sandbox_helper();
        unsafe {
            std::env::remove_var("LPM_SANDBOX_HELPER");
        }
        assert_eq!(
            located,
            Some(path),
            "LPM_SANDBOX_HELPER override must win when the named file exists",
        );
    }

    #[test]
    fn locate_sandbox_helper_falls_back_to_sibling_or_none_when_env_invalid() {
        // Point the env override at a guaranteed-nonexistent path;
        // the locator should ignore it and fall through to the
        // sibling probe. The sibling probe MAY succeed in a `cargo
        // run` context if cargo placed `lpm-sandbox-helper.exe`
        // next to the test binary; we just assert no panic.
        unsafe {
            std::env::set_var(
                "LPM_SANDBOX_HELPER",
                r"C:\does-not-exist\lpm-sandbox-helper.exe",
            );
        }
        let _ = locate_sandbox_helper();
        unsafe {
            std::env::remove_var("LPM_SANDBOX_HELPER");
        }
    }

    #[test]
    fn host_msvc_arch_returns_arm64_or_x64_for_supported_targets() {
        let arch = host_msvc_arch();
        assert!(
            matches!(arch, "arm64" | "x64" | "x86"),
            "unexpected host arch token: {arch}",
        );
    }
}
