//! Parent-side wiring for the Windows backend.
//!
//! This is the half that lives in the `lpm.exe` process — it builds
//! the helper argv from a [`SandboxedCommand`] and spawns
//! `lpm-sandbox-helper.exe`, which in turn does the AppContainer
//! dance (see [`crate::helper_appcontainer`] for the helper-side
//! mechanism). Lifecycle scripts on Windows run only this way: without
//! the helper, [`locate_sandbox_helper`] refuses with
//! [`SandboxError::HelperMissing`] rather than run them less contained.
//!
//! ## What this module DOES touch in the parent
//!
//! - Builds the argv block that the helper consumes (renders
//!   readable_allow_set + writable_allow_set into `--readable-dir` /
//!   `--writable-dir` flags).
//! - Captures the MSVC build environment once per process via
//!   `vcvarsall.bat` so AppContainer'd `node-gyp rebuild` keeps
//!   working without the COM-denied `vswhere` lookup.
//! - Probes for the helper binary location (env var override, then the
//!   directory of the running executable).
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::helper_protocol::{APPCONTAINER_NAME, PROTOCOL_VERSION, StdioMode};
use crate::{
    Sandbox, SandboxError, SandboxMode, SandboxOptions, SandboxPosture, SandboxSpec, SandboxStdio,
    SandboxedCommand,
};

static APPCONTAINER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn appcontainer_name_for_invocation() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let sequence = APPCONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed) as u32;
    format!(
        "{APPCONTAINER_NAME}-{:08x}{timestamp:016x}{sequence:08x}",
        std::process::id()
    )
}

// ── Backend struct ───────────────────────────────────────────────────

/// AppContainer backend, the one Windows backend.
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
/// network allowed". There is no `Degraded` variant — AppContainer
/// delivers full strict (filesystem + network) when requested.
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
    /// Construct the backend, which needs `lpm-sandbox-helper.exe`
    /// ([`locate_sandbox_helper`]).
    pub(crate) fn new(
        spec: SandboxSpec,
        mode: SandboxMode,
        options: SandboxOptions,
    ) -> Result<Self, SandboxError> {
        match mode {
            SandboxMode::Enforce => Ok(Self {
                helper_path: locate_sandbox_helper()?,
                spec,
                mode,
                posture: decide_appcontainer_posture(options.deny_outbound_network),
            }),
            // No native AppContainer "audit-only" primitive, so LogOnly
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

/// Posture decision. Pure (inputs in, outcome out). Never refuses:
/// AppContainer delivers strict on every Windows host the helper runs on,
/// so `allow-degraded` has nothing to fall back to here.
pub(crate) fn decide_appcontainer_posture(deny_outbound_network: bool) -> BackendPosture {
    if deny_outbound_network {
        BackendPosture::Strict
    } else {
        BackendPosture::Default
    }
}

// ── Sandbox trait impl ───────────────────────────────────────────────

impl Sandbox for AppContainerSandbox {
    fn spawn(&self, cmd: SandboxedCommand) -> Result<Child, SandboxError> {
        for (index, path) in self.spec.extra_write_dirs.iter().enumerate() {
            crate::config::revalidate_effective_write_dir(path, index)?;
        }
        let secret_read_denied_paths = if self.spec.read_project_full {
            Vec::new()
        } else {
            crate::linux_secret_overlay::enumerate_project_secrets(
                &self.spec.project_dir,
                &self.spec.secret_read_allow,
            )
            .map_err(|error| SandboxError::InvalidSpec {
                reason: format!("AppContainer secret-read policy preparation failed: {error}"),
            })?
        };

        let mut helper_cmd = Command::new(&self.helper_path);

        // Protocol version + container name come first — the helper
        // refuses argv with a mismatched version before doing any
        // AppContainer work.
        helper_cmd
            .arg("--protocol-version")
            .arg(PROTOCOL_VERSION.to_string());
        helper_cmd
            .arg("--appcontainer-name")
            .arg(appcontainer_name_for_invocation())
            .arg("--delete-appcontainer-profile");

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
        for dir in tool_dirs_needing_explicit_grant(&cmd, &self.spec) {
            helper_cmd.arg("--readable-dir-best-effort").arg(dir);
        }
        // Narrow-write grants mirror the macOS/Linux writable set.
        // The helper applies these after reads so overlaps keep R+W+X.
        for dir in writable_allow_set(&self.spec) {
            helper_cmd.arg("--writable-dir").arg(dir);
        }
        for path in secret_read_denied_paths {
            helper_cmd.arg("--secret-read-deny").arg(path);
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
        if cmd.env_clear && !caller_keys_lower.contains("localappdata") {
            // CreateProcessW requires LOCALAPPDATA for AppContainer startup. Use
            // the writable runtime directory without inheriting the user's profile.
            let mut value = OsString::from("LOCALAPPDATA=");
            value.push(&self.spec.tmpdir);
            helper_cmd.arg("--env").arg(value);
        }
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
/// The writable directories in the project ([`writable_allow_set`]) are
/// granted after these; DACLs are additive, so an overlap keeps write
/// access.
pub(crate) fn readable_allow_set(spec: &SandboxSpec) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(2);
    out.extend(crate::project_reads::allowed_project_reads(spec));
    out.extend(spec.dependency_read_dirs.iter().cloned());
    let nvm = spec.home_dir.join(".nvm").join("versions");
    out.push(nvm);
    out
}

/// The directories the lifecycle child may write, in a fixed order: the
/// package's own directory first, then the project's `node_modules` and
/// `.husky`, the package's layout directory in `.lpm` when it has one
/// ([`crate::package_layout_write_dir`]), the per-user caches, the scratch
/// directory, and `sandboxWriteDirs` last. Matches the macOS Seatbelt
/// `file-write*` block and the Linux landlock read-write rules.
pub(crate) fn writable_allow_set(spec: &SandboxSpec) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(8 + spec.extra_write_dirs.len());
    out.push(spec.package_dir.clone());
    out.push(spec.project_dir.join("node_modules"));
    out.push(spec.project_dir.join(".husky"));
    out.extend(crate::package_layout_write_dir(
        &spec.project_dir,
        &spec.package_dir,
    ));
    out.push(spec.home_dir.join(".cache"));
    out.push(spec.home_dir.join(".node-gyp"));
    out.push(spec.home_dir.join(".npm"));
    out.push(spec.tmpdir.clone());
    out.extend(spec.extra_write_dirs.iter().cloned());
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
/// Skips, with one warning per entry, an existing entry that holds the
/// project, the home directory or the LPM home, or is in the project's
/// `.lpm`, whose grant would reach what the sandbox keeps from scripts
/// there, such as `.lpm` and credentials, and one that isn't absolute,
/// which names a directory under wherever lpm runs rather than the
/// script's own.
///
/// Falls back to the parent's own PATH when the caller didn't
/// supply one. This keeps `cmd /c node install.js` working under
/// the install pipeline's typical `env_clear = true; envs =
/// sanitized` shape: the parent's PATH (already filtered through
/// `build_sanitized_env`) is the only PATH source.
fn tool_dirs_needing_explicit_grant(cmd: &SandboxedCommand, spec: &SandboxSpec) -> Vec<PathBuf> {
    let path_value: Option<OsString> = cmd
        .envs
        .iter()
        .find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.clone())
        .or_else(|| std::env::var_os("PATH"));
    let Some(path_raw) = path_value else {
        return Vec::new();
    };

    let system_root =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);

    // A grant reaches the entry's whole tree.
    let held: Vec<PathBuf> = [
        Some(spec.project_dir.clone()),
        Some(spec.home_dir.clone()),
        lpm_common::LpmRoot::from_env()
            .ok()
            .map(|root| root.root().to_path_buf()),
    ]
    .into_iter()
    .flatten()
    .map(|path| std::fs::canonicalize(&path).unwrap_or(path))
    .collect();

    let state = std::fs::canonicalize(spec.project_dir.join(lpm_common::PROJECT_STATE_DIR)).ok();

    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for entry in std::env::split_paths(&path_raw) {
        if entry.as_os_str().is_empty() || !entry.exists() {
            continue;
        }
        if !entry.is_absolute() {
            warn_once_about_path_entry(&entry, "which isn't an absolute path");
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
        if held.iter().any(|held| held.starts_with(&canon)) {
            warn_once_about_path_entry(
                &entry,
                "which holds the project, the home directory or the LPM home",
            );
            continue;
        }
        if state.as_ref().is_some_and(|state| canon.starts_with(state)) {
            warn_once_about_path_entry(&entry, "which is in the project's .lpm");
            continue;
        }
        if !seen.insert(canon.clone()) {
            continue;
        }
        out.push(entry);
    }
    out
}

/// Warns that `entry` gets no grant, once per entry in this process, as
/// every lifecycle script's spawn reads the same PATH.
fn warn_once_about_path_entry(entry: &std::path::Path, reason: &str) {
    static WARNED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());
    let mut warned = WARNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if warned.iter().any(|known| known == entry) {
        return;
    }
    warned.push(entry.to_path_buf());
    tracing::warn!(
        "lifecycle scripts get no read access to the PATH entry {}, {reason}",
        entry.display()
    );
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

const HELPER_FILE_NAME: &str = "lpm-sandbox-helper.exe";

/// Find `lpm-sandbox-helper.exe`: the file `LPM_SANDBOX_HELPER` names, else
/// the one beside the running executable, where the npm package puts it. A
/// relative override is refused: lpm starts the helper outside the sandbox,
/// and the path would resolve against the directory lpm runs in.
pub(crate) fn locate_sandbox_helper() -> Result<PathBuf, SandboxError> {
    let overridden = std::env::var_os("LPM_SANDBOX_HELPER")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if let Some(value) = overridden.as_ref().filter(|value| !value.is_absolute()) {
        return Err(SandboxError::HelperOverrideNotAbsolute {
            value: value.clone(),
        });
    }
    let beside = std::env::current_exe().ok().and_then(|exe| {
        exe.parent()
            .map(|directory| directory.join(HELPER_FILE_NAME))
    });
    let searched: Vec<PathBuf> = overridden.into_iter().chain(beside).collect();
    match searched.iter().find(|path| path.is_file()) {
        Some(path) => Ok(path.clone()),
        None => Err(SandboxError::HelperMissing { searched }),
    }
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
    // If the first vcvarsall candidate fails at runtime, keep searching instead
    // of returning eagerly.
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
    // An inherited value that is not valid Unicode stays inherited: the
    // decoded dump cannot show whether vcvarsall changed it, and injecting
    // the decoded text would replace the real value.
    let pre_env: HashMap<OsString, OsString> = std::env::vars_os().collect();
    let mut additions = HashMap::new();
    for (k, v) in &new_env {
        match pre_env.get(std::ffi::OsStr::new(k)) {
            Some(prev) if prev.to_str().is_none_or(|prev| prev == v) => {}
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
            read_project_full: false,
            secret_read_allow: Vec::new(),
            dependency_read_dirs: Vec::new(),
            extra_write_dirs: Vec::new(),
        }
    }

    #[test]
    fn path_entries_holding_the_project_or_a_home_or_not_absolute_get_no_grant() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = home.join("proj");
        let tools = root.path().join("tools");
        let bin = project.join("node_modules").join(".bin");
        let lpm_bin = home.join(".lpm").join("bin");
        for directory in [&tools, &bin, &lpm_bin] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let spec = SandboxSpec {
            project_dir: project.clone(),
            home_dir: home.clone(),
            ..make_spec()
        };
        let certs = project.join(".lpm").join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        let path = std::env::join_paths([
            root.path(),
            home.as_path(),
            project.as_path(),
            tools.as_path(),
            bin.as_path(),
            lpm_bin.as_path(),
            certs.as_path(),
            std::path::Path::new("."),
            std::path::Path::new("tools"),
        ])
        .unwrap();
        let cmd = SandboxedCommand::new("cmd").envs_cleared([("PATH", path)]);

        assert_eq!(
            tool_dirs_needing_explicit_grant(&cmd, &spec),
            [tools, bin, lpm_bin]
        );
    }

    #[test]
    fn decide_appcontainer_posture_strict_when_deny_outbound_set() {
        assert_eq!(decide_appcontainer_posture(true), BackendPosture::Strict);
    }

    #[test]
    fn decide_appcontainer_posture_default_when_deny_outbound_unset() {
        assert_eq!(decide_appcontainer_posture(false), BackendPosture::Default);
    }

    #[test]
    fn writable_set_grants_the_package_but_not_project_state() {
        let spec = make_spec();
        let set = writable_allow_set(&spec);
        assert_eq!(
            set,
            vec![
                spec.package_dir.clone(),
                spec.project_dir.join("node_modules"),
                spec.project_dir.join(".husky"),
                spec.home_dir.join(".cache"),
                spec.home_dir.join(".node-gyp"),
                spec.home_dir.join(".npm"),
                spec.tmpdir.clone(),
            ]
        );
    }

    #[test]
    fn writable_set_adds_the_package_s_own_layout_directory_and_extras_last() {
        let mut spec = make_spec();
        spec.package_dir = spec
            .project_dir
            .join(".lpm")
            .join("wrappers")
            .join("pkg@1.0.0")
            .join("node_modules")
            .join("pkg");
        spec.extra_write_dirs = vec![PathBuf::from("C:/extra1"), PathBuf::from("C:/extra2")];
        let set = writable_allow_set(&spec);

        let wrapper = spec
            .project_dir
            .join(".lpm")
            .join("wrappers")
            .join("pkg@1.0.0");
        assert_eq!(set[3], wrapper);
        assert!(!set.contains(&spec.project_dir.join(".lpm")));
        assert!(!set.contains(&spec.project_dir.join(".lpm").join("wrappers")));
        assert_eq!(
            set[set.len() - 2..],
            [PathBuf::from("C:/extra1"), PathBuf::from("C:/extra2")]
        );
    }

    #[test]
    fn appcontainer_profile_names_are_unique_and_within_windows_limit() {
        let first = appcontainer_name_for_invocation();
        let second = appcontainer_name_for_invocation();

        assert_ne!(first, second);
        assert!(first.starts_with(APPCONTAINER_NAME));
        assert!(first.len() <= 64, "AppContainer profile name was {first:?}");
    }

    #[test]
    fn narrow_readable_set_excludes_project_root_but_keeps_toolchains() {
        let spec = make_spec();
        let set = readable_allow_set(&spec);
        assert!(
            !set.iter().any(|p| p == &spec.project_dir),
            "narrow reads must exclude the project root; got: {set:?}",
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
            located.ok(),
            Some(path),
            "LPM_SANDBOX_HELPER override must win when the named file exists",
        );
    }

    #[test]
    fn a_relative_helper_override_is_refused_before_anything_is_looked_up() {
        for value in [
            r"tools\lpm-sandbox-helper.exe",
            r"C:tools\lpm-sandbox-helper.exe",
            r"\tools\lpm-sandbox-helper.exe",
        ] {
            unsafe {
                std::env::set_var("LPM_SANDBOX_HELPER", value);
            }
            let located = locate_sandbox_helper();
            unsafe {
                std::env::remove_var("LPM_SANDBOX_HELPER");
            }
            match located {
                Err(error @ SandboxError::HelperOverrideNotAbsolute { .. }) => {
                    assert!(
                        error.to_string().contains("isn't an absolute path"),
                        "{error}"
                    );
                }
                other => panic!("{value}: expected a refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_missing_helper_is_refused_naming_every_place_looked() {
        let overridden = PathBuf::from(r"C:\does-not-exist\lpm-sandbox-helper.exe");
        unsafe {
            std::env::set_var("LPM_SANDBOX_HELPER", &overridden);
        }
        let located = locate_sandbox_helper();
        unsafe {
            std::env::remove_var("LPM_SANDBOX_HELPER");
        }
        let beside = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join(HELPER_FILE_NAME);
        match located {
            Ok(path) => assert_eq!(path, beside, "only the file beside the test may be found"),
            Err(SandboxError::HelperMissing { searched }) => {
                assert_eq!(searched, vec![overridden, beside]);
            }
            Err(other) => panic!("expected HelperMissing, got {other:?}"),
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
