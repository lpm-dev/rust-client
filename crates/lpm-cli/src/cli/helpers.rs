use crate::{commands, output, update_check};

use super::args::{Commands, InstallOmitCli};

pub(super) fn maybe_emit_network_fs_warning(root: &lpm_common::LpmRoot) {
    let marker = root.network_fs_notice_marker();
    if marker.exists() {
        return;
    }
    let kind = lpm_common::is_local_fs(root.root());
    if !matches!(kind, lpm_common::FsKind::Network) {
        return;
    }
    output::warn(&format!(
        "{} appears to be on a network filesystem.\n  \
         Global install concurrency guarantees require local storage — set\n  \
         LPM_HOME=/local/path to override, or expect occasional install\n  \
         serialization failures under heavy concurrent use.\n  \
         (This warning is shown once; delete {} to see it again.)",
        root.root().display(),
        marker.display(),
    ));
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::File::create(&marker);
}

/// Print `lpm <version>` followed (when applicable) by the cached
/// "update available" notice. Replaces clap's auto `--version` handler.
///
/// The notice is read from the same on-disk cache that the once-a-day
/// background refresh writes via the hidden `internal-update-check`
/// subcommand — no network call here. When the cache is missing,
/// stale-but-empty, or shows the user is already on the latest, only
/// the version line is printed (zero noise).
pub(super) fn print_version_with_notice() {
    println!("lpm {}", env!("CARGO_PKG_VERSION"));
    if let Some(notice) = update_check::read_cached_notice() {
        // `read_cached_notice` already wraps the message with leading +
        // trailing newlines and colour, so we can print it as-is.
        print!("{notice}");
    }
}

pub(super) fn argv_requests_top_level_version<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(flag) = args.next() else {
        return false;
    };

    if args.next().is_some() {
        return false;
    }

    flag.as_ref() == std::ffi::OsStr::new("--version")
}

pub(super) fn args_for_cli_parse<I>(args: I) -> Vec<std::ffi::OsString>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut args: Vec<std::ffi::OsString> = args.into_iter().collect();
    let Some(program) = args.first() else {
        return args;
    };
    let Some(stem) = std::path::Path::new(program).file_stem() else {
        return args;
    };
    if stem == std::ffi::OsStr::new("lpx") {
        args.insert(1, std::ffi::OsString::from("dlx"));
        return args;
    }
    move_leading_recursive_flag_after_install(&mut args);
    insert_run_file_command_for_naked_source(&mut args);
    args
}

fn move_leading_recursive_flag_after_install(args: &mut Vec<std::ffi::OsString>) {
    let mut index = 1;
    let mut recursive_indices = Vec::new();

    while index < args.len() {
        let arg = args[index].as_os_str();
        if arg == std::ffi::OsStr::new("--") {
            return;
        }
        if matches!(arg.to_str(), Some("-r" | "--recursive")) {
            recursive_indices.push(index);
            index += 1;
            continue;
        }
        if let Some(skip) = top_level_global_flag_width(arg) {
            index += skip;
            continue;
        }
        if !matches!(arg.to_str(), Some("install" | "i")) {
            return;
        }

        for recursive_index in recursive_indices.into_iter().rev() {
            let flag = args.remove(recursive_index);
            index -= 1;
            args.insert(index + 1, flag);
        }
        return;
    }
}

fn insert_run_file_command_for_naked_source(args: &mut Vec<std::ffi::OsString>) {
    let mut index = 1;
    let mut insert_at = None;

    while index < args.len() {
        let arg = args[index].as_os_str();
        if arg == std::ffi::OsStr::new("--") {
            return;
        }

        if let Some(skip) = top_level_global_flag_width(arg) {
            index += skip;
            continue;
        }

        if let Some(skip) = run_file_flag_width(arg) {
            insert_at.get_or_insert(index);
            index += skip;
            continue;
        }

        if is_naked_source_target(arg) {
            args.insert(
                insert_at.unwrap_or(index),
                std::ffi::OsString::from("__run-file"),
            );
        }
        return;
    }
}

fn top_level_global_flag_width(arg: &std::ffi::OsStr) -> Option<usize> {
    match arg.to_str()? {
        "--json" | "--verbose" | "--insecure" | "-V" | "-v" => Some(1),
        "--registry" | "--token" | "--color" => Some(2),
        value
            if value.starts_with("--registry=")
                || value.starts_with("--token=")
                || value.starts_with("--color=") =>
        {
            Some(1)
        }
        _ => None,
    }
}

fn run_file_flag_width(arg: &std::ffi::OsStr) -> Option<usize> {
    match arg.to_str()? {
        "--watch" | "--no-env-check" | "--plain-node" | "--no-augment" => Some(1),
        "--env" => Some(2),
        value if value.starts_with("--env=") => Some(1),
        _ => None,
    }
}

fn is_naked_source_target(arg: &std::ffi::OsStr) -> bool {
    let path = std::path::Path::new(arg);
    has_supported_source_extension(path) || is_path_like(arg)
}

fn has_supported_source_extension(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts")
    )
}

fn is_path_like(arg: &std::ffi::OsStr) -> bool {
    let Some(value) = arg.to_str() else {
        return false;
    };
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.contains('/')
        || value.contains('\\')
}

pub(super) fn argv_requests_json(args: &[std::ffi::OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|arg| arg.as_os_str() != std::ffi::OsStr::new("--"))
        .any(|arg| arg.as_os_str() == std::ffi::OsStr::new("--json"))
}

pub(super) fn clap_help_hint_from_argv(args: &[std::ffi::OsString]) -> Option<String> {
    let mut skip_next = false;
    for arg in args
        .iter()
        .skip(1)
        .take_while(|arg| arg.as_os_str() != std::ffi::OsStr::new("--"))
    {
        let Some(value) = arg.to_str() else {
            continue;
        };

        if skip_next {
            skip_next = false;
            continue;
        }

        match value {
            "--json" | "--recursive" | "-r" | "--verbose" | "--insecure" | "-V" | "-v" => {
                continue;
            }
            "--registry" | "--token" | "--color" => {
                skip_next = true;
                continue;
            }
            _ if value.starts_with("--registry=")
                || value.starts_with("--token=")
                || value.starts_with("--color=") =>
            {
                continue;
            }
            _ if value.starts_with('-') => continue,
            command => {
                return Some(format!("Run `lpm {command} --help` for command usage."));
            }
        }
    }
    None
}

pub(super) fn command_needs_global_state(cmd: &Commands) -> bool {
    match cmd {
        // `install -g` (the actual install pipeline is wired; the
        // dispatcher errors loudly for multi-package invocations, but recovery still runs so
        // a prior crashed install gets reconciled before the user
        // retries).
        Commands::Install(args) if args.global => true,
        // `uninstall -g`: same reasoning as `install -g` —
        // recovery must run first so an orphaned `[pending.<pkg>]` from
        // a crashed install gets cleaned up before uninstall sees it
        // and bails with the in-flight-install error message.
        Commands::Uninstall(args) if args.global => true,
        // Every `lpm global *` subcommand reads at minimum the manifest.
        Commands::Global(_) => true,
        // `store verify` needs the manifest settled so the walker sees
        // the right per-package state. `cache prune` covers the
        // reachability-aware union (which is itself listed below).
        Commands::Store(args) if args.action == "verify" => true,
        // `cache prune --apply` walks every globally-installed package's
        // lockfile + sweeps deferred tombstones — the manifest must be
        // settled before either step runs.
        Commands::Cache(args) if args.action == "prune" => true,
        // Any `cache clean` invocation, regardless of subcategory.
        // Bare `cache clean` cleans metadata + tasks + dlx, so the dlx
        // dir is always in scope; the per-subcategory form trivially is
        // too.
        Commands::Cache(args) => args.action == "clean",
        // `doctor` reports on global state and may surface mid-tx
        // anomalies that recovery would have already cleaned up.
        Commands::Doctor(_) => true,
        // `approve-scripts --global` reads the global
        // manifest + aggregates per-install build-state files, both
        // of which need recovery to settle first.
        Commands::ApproveScripts(args) if args.global => true,
        _ => false,
    }
}

pub(super) fn install_omit_policy_from_cli(
    omit: &[InstallOmitCli],
    prod: bool,
) -> commands::install::InstallOmitPolicy {
    let mut policy = commands::install::InstallOmitPolicy {
        dev: prod,
        optional: false,
    };
    for kind in omit {
        match kind {
            InstallOmitCli::Dev => policy.dev = true,
            InstallOmitCli::Optional => policy.optional = true,
        }
    }
    policy
}

/// assemble the per-invocation security overrides forwarded
/// from `lpm install -g` into the global install pipeline.
///
/// Centralizes three steps that previously lived inline in the
/// dispatcher arm:
///   1. Collapse the three mutually-exclusive policy aliases
///      (`--policy=<v>` / `--yolo` / `--triage`) into a single
///      `Option<ScriptPolicy>` via [`crate::script_policy_config::collapse_policy_flags`].
///   2. Resolve the effective policy through [`crate::script_policy_config::resolve_script_policy`]
///      with `ScriptPolicyConfig::default()` so the user-config tier
///      (`~/.lpm/config.toml`) and `force-security-floor` semantics
///      still fire — only the project-config tier (which doesn't apply
///      to `-g`, since the synthetic package.json never carries
///      `lpm.scriptPolicy`) is collapsed.
///   3. Parse `--min-release-age=<DUR>` and canonicalize the drift
///      flags via [`crate::provenance_fetch::DriftIgnorePolicy::from_cli`].
///
/// Extracted to make the wiring unit-testable: a regression that drops
/// any of the five overrides on the way to `install_global::run` is
/// caught by the tests in this module.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(super) fn build_install_global_overrides(
    allow_new: bool,
    auto_build: bool,
    policy: Option<&str>,
    yolo: bool,
    triage_alias: bool,
    min_release_age: Option<&str>,
    ignore_provenance_drift: Vec<String>,
    ignore_provenance_drift_all: bool,
    unverified_provenance: Vec<String>,
    unverified_provenance_all: bool,
) -> Result<commands::install_global::InstallGlobalOverrides, lpm_common::LpmError> {
    build_install_global_overrides_with_excludes(
        allow_new,
        auto_build,
        policy,
        yolo,
        triage_alias,
        min_release_age,
        Vec::new(),
        ignore_provenance_drift,
        ignore_provenance_drift_all,
        unverified_provenance,
        unverified_provenance_all,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_install_global_overrides_with_excludes(
    allow_new: bool,
    auto_build: bool,
    policy: Option<&str>,
    yolo: bool,
    triage_alias: bool,
    min_release_age: Option<&str>,
    min_release_age_exclude: Vec<String>,
    ignore_provenance_drift: Vec<String>,
    ignore_provenance_drift_all: bool,
    unverified_provenance: Vec<String>,
    unverified_provenance_all: bool,
) -> Result<commands::install_global::InstallGlobalOverrides, lpm_common::LpmError> {
    let cli_policy_override =
        crate::script_policy_config::collapse_policy_flags(policy, yolo, triage_alias)
            .map_err(lpm_common::LpmError::Script)?;
    let global_policy_cfg = crate::script_policy_config::ScriptPolicyConfig::default();
    let resolved_policy =
        crate::script_policy_config::resolve_script_policy(cli_policy_override, &global_policy_cfg);
    let min_release_age_override = match min_release_age {
        Some(s) => Some(crate::release_age_config::parse_duration(s)?),
        None => None,
    };
    let min_release_age_exclude = crate::release_age_config::validate_release_age_excludes(
        "--min-release-age-exclude",
        &min_release_age_exclude,
    )?;
    let drift_ignore_policy = crate::provenance_fetch::DriftIgnorePolicy::from_cli(
        ignore_provenance_drift,
        ignore_provenance_drift_all,
    );
    let verify_policy = crate::provenance_fetch::VerifyPolicy::from_cli(
        unverified_provenance,
        unverified_provenance_all,
    );
    Ok(commands::install_global::InstallGlobalOverrides {
        allow_new,
        strict_peer_dependencies_override: None,
        no_engine_strict: false,
        min_release_age_override,
        min_release_age_exclude,
        drift_ignore_policy,
        verify_policy,
        // Forward the resolved policy as `Some(p)` so the inner
        // pipeline's resolver doesn't double-resolve against its own
        // (project-shape) chain.
        script_policy_override: Some(resolved_policy),
        auto_build,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_global_install_project_scoped_flags(
    save_dev: bool,
    filter: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    workspace_root: bool,
    fail_if_no_match: bool,
    yes: bool,
    catalog: bool,
    omit: bool,
) -> Result<(), lpm_common::LpmError> {
    // `--allow-new`, `--min-release-age`, and
    // `--ignore-provenance-drift[-all]` are now forwarded into the
    // global install pipeline (their gates fire end-to-end against the
    // synthetic project's package.json), so they are no longer rejected
    // here. The flags below remain genuinely project-scoped and have no
    // meaningful semantics on `-g`.
    if save_dev
        || !filter.is_empty()
        || !filter_prod.is_empty()
        || !changed_files_ignore_pattern.is_empty()
        || !test_pattern.is_empty()
        || workspace_root
        || fail_if_no_match
        || yes
        || catalog
        || omit
    {
        return Err(lpm_common::LpmError::Script(
            "`-g` is mutually exclusive with `-D` / `--filter` / `--filter-prod` / \
             `--changed-files-ignore-pattern` / `--test-pattern` / `-w` / \
             `--fail-if-no-match` / `-y` / `--catalog` / `--omit` / `--prod` \
             (those are project-scoped)."
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_global_uninstall_project_scoped_flags(
    filter: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    workspace_root: bool,
    fail_if_no_match: bool,
    yes: bool,
) -> Result<(), lpm_common::LpmError> {
    if !filter.is_empty()
        || !filter_prod.is_empty()
        || !changed_files_ignore_pattern.is_empty()
        || !test_pattern.is_empty()
        || workspace_root
        || fail_if_no_match
        || yes
    {
        return Err(lpm_common::LpmError::Script(
            "`-g` is mutually exclusive with `--filter` / `--filter-prod` / \
             `--changed-files-ignore-pattern` / `--test-pattern` / `-w` / \
             `--fail-if-no-match` / `-y` (those are project-scoped)."
                .into(),
        ));
    }

    Ok(())
}

/// Resolve the directory that the install dispatcher should treat as
/// the project root for this invocation. Three outcomes:
///
/// 1. `cwd/package.json` exists → return `cwd`.
/// 2. An ancestor `package.json` exists → return that ancestor's
///    directory. Mirrors npm / pnpm / yarn / bun: running `lpm install`
///    or `lpm i <pkg>` from a project subdirectory walks up to the
///    manifest instead of failing.
/// 3. No manifest anywhere → if `adding_packages` (the `lpm i <pkg>`
///    surface), create a minimal `{ "dependencies": {} }` manifest in
///    `cwd` and return `cwd`. Otherwise return `cwd` unchanged and let
///    the bare-install path emit its existing "no package.json found"
///    error downstream.
pub(super) fn resolve_install_project_dir(
    cwd: &std::path::Path,
    adding_packages: bool,
    json_output: bool,
) -> Result<std::path::PathBuf, lpm_common::LpmError> {
    if cwd.join("package.json").is_file() {
        return Ok(cwd.to_path_buf());
    }
    if let Some(ancestor) = lpm_workspace::find_project_root(cwd) {
        if !json_output {
            crate::install_ui::phase_untrusted(&format!(
                "No package.json in {}; using {} (nearest ancestor manifest).",
                cwd.display(),
                ancestor.display(),
            ));
        }
        return Ok(ancestor);
    }
    if !adding_packages {
        return Ok(cwd.to_path_buf());
    }
    // Auto-create a minimal manifest so `lpm i <pkg>` mirrors
    // `npm i <pkg>` in a fresh directory. `create_new` guards against
    // a TOCTOU race with a parallel writer — if someone else won the
    // race, we treat the file as already-present.
    let pkg_json_path = cwd.join("package.json");
    const MINIMAL_PACKAGE_JSON: &str = "{\n  \"dependencies\": {}\n}\n";
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pkg_json_path)
    {
        Ok(mut f) => {
            use std::io::Write;
            f.write_all(MINIMAL_PACKAGE_JSON.as_bytes())
                .map_err(lpm_common::LpmError::Io)?;
            if !json_output {
                crate::install_ui::phase_untrusted(&format!(
                    "No package.json found in {}. Created a new one.",
                    cwd.display(),
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost the race — fall through and use the existing file.
        }
        Err(e) => return Err(lpm_common::LpmError::Io(e)),
    }
    Ok(cwd.to_path_buf())
}

/// Whether the trailing "update available" banner should be suppressed
/// for this invocation.
///
/// The banner is suppressed for every `lpm self-update` invocation,
/// regardless of outcome:
///
/// - Failure (cooldown, rate limit, transport error): the user already
///   saw the failure message; "run lpm self-update" sends them back
///   into the same loop they're trying to escape.
/// - Success: the running process is still the old version (the new
///   binary lives on disk but doesn't replace this PID), and the
///   on-disk cache now has the just-upgraded version stamped. The
///   banner predicate (`cache.latest > current`) therefore fires —
///   so the user would see `Updated to 0.38.0` immediately followed
///   by `Update available: 0.37.0 → 0.38.0 — run lpm self-update`.
///   That contradicts itself.
///
/// Suppression is per-invocation; the on-disk cache is unchanged, so
/// any other command still surfaces the banner on the next run.
pub(super) fn should_suppress_update_banner(is_self_update_command: bool) -> bool {
    is_self_update_command
}

/// spawn a detached child process to refresh the update cache.
///
/// The child re-execs the current binary with `internal-update-check`.
/// The parent never waits — the child is fully detached (setsid on Unix)
/// so it survives the parent's exit and terminal signals don't propagate.
///
/// Silent on all failure paths: if `current_exe()` fails, if spawn fails,
/// etc. — the update check simply doesn't happen this time. The 24h
/// staleness gate limits spawns to at most ~1/day.
pub(super) fn spawn_background_update_check() {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return,
    };

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("internal-update-check");
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.stdin(std::process::Stdio::null());

    // Detach from parent process group on Unix so terminal signals
    // (SIGINT, SIGHUP) don't propagate to the child.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid() is async-signal-safe and has no preconditions
        // beyond being called in a child process (guaranteed by pre_exec).
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    let _ = cmd.spawn(); // fire-and-forget
}

pub(super) fn tunnel_action_requires_session(action: &str) -> bool {
    !matches!(action, "inspect" | "replay" | "log" | "logs")
}

fn relay_url_host_is_loopback(relay_url: &str) -> bool {
    let Some((scheme, rest)) = relay_url.split_once("://") else {
        return false;
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "ws" | "wss") {
        return false;
    }

    let host_port = rest.split('/').next().unwrap_or("");
    let host = if host_port.starts_with('[') {
        host_port
            .split(']')
            .next()
            .unwrap_or("")
            .trim_start_matches('[')
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|addr| addr.is_loopback())
}

pub(super) async fn resolve_tunnel_bearer(
    session: Option<&lpm_auth::SessionManager>,
    relay_url: &str,
) -> Result<Option<String>, lpm_common::LpmError> {
    let Some(session) = session else {
        return Ok(None);
    };

    let auth_requirement = if relay_url_host_is_loopback(relay_url) {
        lpm_auth::AuthRequirement::TokenRequired
    } else {
        lpm_auth::AuthRequirement::SessionRequired
    };

    session
        .bearer_string_for(auth_requirement)
        .await
        .map(Some)
        .map_err(|_| {
            if auth_requirement == lpm_auth::AuthRequirement::TokenRequired {
                lpm_common::LpmError::Tunnel(
                    "authentication required for tunnel. Run `lpm login` first.".into(),
                )
            } else {
                lpm_common::LpmError::Tunnel(
                    "tunnel requires a refresh-backed `lpm login` session.\n  \
                     `--token` / `LPM_TOKEN` / CI tokens are not accepted."
                        .into(),
                )
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{Cli, Commands};
    use crate::provenance_fetch::DriftIgnorePolicy;
    use crate::script_policy_config::ScriptPolicy;
    use clap::Parser;

    fn parse(args: &[&str]) -> Commands {
        Cli::try_parse_from(args)
            .unwrap()
            .command
            .expect("test parse missing subcommand")
    }

    /// Banner suppression: every `lpm self-update` invocation
    /// suppresses the trailing banner; everything else lets it through.
    ///
    /// Failure case: re-emitting "run lpm self-update" right after the
    /// command itself failed loops the user.
    ///
    /// Success case: the running PID is still the old binary while the
    /// on-disk cache has been stamped with the just-upgraded `latest`,
    /// so the banner predicate fires and produces the contradictory
    /// `Updated to X` + `Update available: <old> → X` pair.
    ///
    /// Other commands must NOT suppress: a transient failure on
    /// `lpm install` would otherwise swallow the user's "you're behind
    /// on releases" signal.
    #[test]
    fn should_suppress_update_banner_only_on_self_update() {
        assert!(
            should_suppress_update_banner(true),
            "self-update → suppress (covers both failure-loop and success-contradiction)"
        );
        assert!(
            !should_suppress_update_banner(false),
            "any other command → show banner"
        );
    }

    #[test]
    fn top_level_long_version_is_handled_before_clap() {
        assert!(argv_requests_top_level_version(["lpm", "--version"]));
        assert!(!argv_requests_top_level_version(["lpm", "info", "react"]));
        assert!(!argv_requests_top_level_version([
            "lpm",
            "info",
            "react",
            "--version",
            "1.0.0"
        ]));
    }

    #[test]
    fn args_for_cli_parse_maps_lpx_executable_to_dlx_command() {
        let args = args_for_cli_parse(
            ["lpx", "cowsay", "--version"]
                .into_iter()
                .map(std::ffi::OsString::from),
        );
        let cli = Cli::try_parse_from(args).unwrap();
        let Some(Commands::Dlx(args)) = cli.command else {
            panic!("lpx executable alias must parse as the dlx command");
        };

        assert_eq!(args.package, "cowsay");
        assert_eq!(args.args, vec!["--version"]);
    }

    #[test]
    fn args_for_cli_parse_moves_leading_recursive_flag_to_install() {
        for raw in [
            &["lpm", "-r", "install"][..],
            &["lpm", "--recursive", "i"][..],
            &["lpm", "--json", "-r", "install"][..],
        ] {
            let args = args_for_cli_parse(raw.iter().map(std::ffi::OsString::from));
            let cli = Cli::try_parse_from(args).expect("leading recursive flag should parse");
            let Some(Commands::Install(args)) = cli.command else {
                panic!("leading recursive flag should select install for {raw:?}");
            };
            assert!(args.recursive, "recursive flag should be set for {raw:?}");
        }
    }

    #[test]
    fn args_for_cli_parse_maps_naked_source_file_to_hidden_run_file_command() {
        let args = args_for_cli_parse(
            ["lpm", "scripts/seed.ts", "--", "--flag"]
                .into_iter()
                .map(std::ffi::OsString::from),
        );
        let cli = Cli::try_parse_from(args).unwrap();
        let Some(Commands::RunFile(args)) = cli.command else {
            panic!("naked source file must parse as hidden run-file command");
        };

        assert_eq!(args.file, "scripts/seed.ts");
        assert_eq!(args.args, vec!["--flag"]);
    }

    #[test]
    fn args_for_cli_parse_maps_leading_run_file_flags_to_hidden_run_file_command() {
        let args = args_for_cli_parse(
            ["lpm", "--watch", "--env", "staging", "scripts/seed.ts"]
                .into_iter()
                .map(std::ffi::OsString::from),
        );
        let cli = Cli::try_parse_from(args).unwrap();
        let Some(Commands::RunFile(args)) = cli.command else {
            panic!("leading source-file flags must parse as hidden run-file command");
        };

        assert_eq!(args.file, "scripts/seed.ts");
        assert_eq!(args.env.as_deref(), Some("staging"));
        assert!(args.watch);
    }

    #[test]
    fn args_for_cli_parse_maps_trailing_run_file_flags_to_hidden_run_file_command() {
        let args = args_for_cli_parse(
            ["lpm", "scripts/seed.ts", "--env", "staging", "--plain-node"]
                .into_iter()
                .map(std::ffi::OsString::from),
        );
        let cli = Cli::try_parse_from(args).unwrap();
        let Some(Commands::RunFile(args)) = cli.command else {
            panic!("trailing source-file flags must parse as hidden run-file command");
        };

        assert_eq!(args.file, "scripts/seed.ts");
        assert_eq!(args.env.as_deref(), Some("staging"));
        assert!(args.plain_node);
    }

    #[test]
    fn args_for_cli_parse_leaves_script_shortcuts_as_external_commands() {
        let args = args_for_cli_parse(
            ["lpm", "storybook"]
                .into_iter()
                .map(std::ffi::OsString::from),
        );
        let cli = Cli::try_parse_from(args).unwrap();
        let Some(Commands::External(args)) = cli.command else {
            panic!("bare script shortcut must stay an external command");
        };

        assert_eq!(args, vec!["storybook"]);
    }

    #[test]
    fn args_for_cli_parse_does_not_rewrite_explicit_run_command() {
        let args = args_for_cli_parse(
            ["lpm", "run", "scripts/seed.ts"]
                .into_iter()
                .map(std::ffi::OsString::from),
        );
        let cli = Cli::try_parse_from(args).unwrap();
        let Some(Commands::Run(args)) = cli.command else {
            panic!("explicit run command must stay a script invocation");
        };

        assert_eq!(args.scripts, vec!["scripts/seed.ts"]);
    }

    #[test]
    fn args_for_cli_parse_leaves_lpm_invocations_unchanged() {
        let args = args_for_cli_parse(
            ["lpm", "dlx", "cowsay"]
                .into_iter()
                .map(std::ffi::OsString::from),
        );
        assert_eq!(
            args,
            vec![
                std::ffi::OsString::from("lpm"),
                std::ffi::OsString::from("dlx"),
                std::ffi::OsString::from("cowsay"),
            ],
        );
    }

    #[test]
    fn print_version_with_notice_does_not_panic() {
        // Smoke test: the version printer works even when no cache
        // file exists (the notice helper returns None silently).
        // We can't easily assert on stdout from a unit test without
        // a writer abstraction, but the smoke test catches obvious
        // breakage.
        print_version_with_notice();
    }

    #[test]
    fn predicate_true_for_install_global() {
        let cmd = parse(&["lpm", "install", "-g", "eslint"]);
        assert!(command_needs_global_state(&cmd));
    }

    #[test]
    fn predicate_false_for_install_without_global() {
        let cmd = parse(&["lpm", "install", "eslint"]);
        assert!(!command_needs_global_state(&cmd));
    }

    #[test]
    fn predicate_true_for_uninstall_global() {
        let cmd = parse(&["lpm", "uninstall", "-g", "eslint"]);
        assert!(command_needs_global_state(&cmd));
    }

    #[test]
    fn predicate_false_for_uninstall_without_global() {
        let cmd = parse(&["lpm", "uninstall", "eslint"]);
        assert!(!command_needs_global_state(&cmd));
    }

    #[test]
    fn predicate_true_for_every_global_subcommand() {
        for args in [
            &["lpm", "global", "list"][..],
            &["lpm", "global", "bin"][..],
            &["lpm", "global", "path", "eslint"][..],
        ] {
            assert!(
                command_needs_global_state(&parse(args)),
                "expected true for {args:?}"
            );
        }
    }

    #[test]
    fn predicate_true_for_store_verify_and_cache_prune() {
        // `store verify` reads per-package state from the manifest;
        // `cache prune --apply` walks every globally-installed package's
        // lockfile + sweeps deferred tombstones. Both need the manifest
        // settled before they run.
        assert!(command_needs_global_state(&parse(&[
            "lpm", "store", "verify"
        ])));
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "prune"
        ])));
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "prune", "--apply"
        ])));
    }

    #[test]
    fn predicate_false_for_store_clean_and_path() {
        // Destructive `store clean` doesn't read the global manifest;
        // `store path` is read-only print. Neither needs recovery.
        assert!(!command_needs_global_state(&parse(&[
            "lpm", "store", "clean"
        ])));
        assert!(!command_needs_global_state(&parse(&[
            "lpm", "store", "path"
        ])));
    }

    #[test]
    fn predicate_true_for_every_cache_clean_form() {
        // Any `cache clean` invocation can touch the shared dlx dir
        // because the bare form cleans all three subcategories, so all
        // forms gate on recovery.
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "clean"
        ])));
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "clean", "dlx"
        ])));
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "clean", "metadata"
        ])));
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "clean", "tasks"
        ])));
        // Read-only `cache path` does not.
        assert!(!command_needs_global_state(&parse(&[
            "lpm", "cache", "path"
        ])));
    }

    #[test]
    fn predicate_true_for_doctor() {
        assert!(command_needs_global_state(&parse(&["lpm", "doctor"])));
    }

    #[test]
    fn predicate_false_for_help_and_pure_project_commands() {
        // Plain `lpm install` / `lpm run build` / `lpm version` should
        // never trigger recovery — common-case startup must stay zero
        // overhead.
        assert!(!command_needs_global_state(&parse(&["lpm", "install"])));
        assert!(!command_needs_global_state(&parse(&[
            "lpm", "run", "build"
        ])));
    }

    #[test]
    fn install_prod_and_omit_flags_parse() {
        let cli = Cli::try_parse_from(["lpm", "install", "--prod"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Install(args) => {
                assert!(args.omit.is_empty());
                assert!(args.prod);
                let policy = install_omit_policy_from_cli(&args.omit, args.prod);
                assert!(policy.dev);
                assert!(!policy.optional);
            }
            _ => panic!("expected Install command"),
        }

        let cli = Cli::try_parse_from(["lpm", "install", "--omit=dev,optional", "--omit", "dev"])
            .unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Install(args) => {
                assert!(!args.prod);
                let policy = install_omit_policy_from_cli(&args.omit, args.prod);
                assert!(policy.dev);
                assert!(policy.optional);
            }
            _ => panic!("expected Install command"),
        }

        let cli = Cli::try_parse_from(["lpm", "install", "--production"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Install(args) => {
                assert!(args.prod);
            }
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn install_global_rejects_project_scoped_yes_flag() {
        let cli = Cli::try_parse_from(["lpm", "install", "-g", "eslint", "-y"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Install(args) => {
                assert!(args.global);
                assert!(args.yes);

                let err = validate_global_install_project_scoped_flags(
                    args.save_dev,
                    &args.filter,
                    &[],
                    &[],
                    &[],
                    args.workspace_root,
                    args.fail_if_no_match,
                    args.yes,
                    false,
                    false,
                )
                .unwrap_err();

                match err {
                    lpm_common::LpmError::Script(message) => {
                        assert!(message.contains("`-y`"));
                        assert!(message.contains("project-scoped"));
                    }
                    other => panic!("expected Script error, got {other:?}"),
                }
            }
            _ => panic!("expected Install command"),
        }
    }

    /// Confirm the contract on the validator's surface area:
    /// the four flags previously rejected on `-g` are now accepted by
    /// the validator, and `-y` remains the project-only flag it
    /// rejects.
    #[test]
    fn install_global_validator_only_rejects_project_scoped_grouping_flags() {
        // Genuine project-only flag: still rejected.
        let err = validate_global_install_project_scoped_flags(
            true,
            &[],
            &[],
            &[],
            &[],
            false,
            false,
            false,
            false,
            false,
        )
        .unwrap_err();
        match err {
            lpm_common::LpmError::Script(message) => {
                assert!(message.contains("project-scoped"));
            }
            other => panic!("expected Script error, got {other:?}"),
        }

        let err = validate_global_install_project_scoped_flags(
            false,
            &[],
            &[],
            &[],
            &[],
            false,
            false,
            false,
            true,
            false,
        )
        .unwrap_err();
        match err {
            lpm_common::LpmError::Script(message) => {
                assert!(message.contains("`--catalog`"));
                assert!(message.contains("project-scoped"));
            }
            other => panic!("expected Script error, got {other:?}"),
        }

        // No project-only flags set → accept.
        validate_global_install_project_scoped_flags(
            false,
            &[],
            &[],
            &[],
            &[],
            false,
            false,
            false,
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn build_install_global_overrides_threads_allow_new_and_auto_build_bools() {
        let o = build_install_global_overrides(
            true,
            true,
            None,
            false,
            false,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert!(
            o.allow_new,
            "allow_new must reach the bundle so the cooldown gate is bypassed"
        );
        assert!(
            o.auto_build,
            "auto_build must reach the bundle so triage greens auto-execute"
        );

        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert!(!o.allow_new);
        assert!(!o.auto_build);
    }

    #[test]
    fn build_install_global_overrides_parses_min_release_age_duration() {
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            Some("72h"),
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(
            o.min_release_age_override,
            Some(72 * 3600),
            "72h must parse to 259_200 seconds and reach the bundle"
        );

        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            Some("0"),
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(
            o.min_release_age_override,
            Some(0),
            "explicit zero must reach the bundle (disables cooldown for this invocation)"
        );

        // No override → None reaches the bundle (fallback to chain default).
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert!(o.min_release_age_override.is_none());
    }

    #[test]
    fn build_install_global_overrides_rejects_garbage_min_release_age() {
        let err = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            Some("garbage"),
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap_err();
        // Don't pin the exact wording (owned by release_age_config),
        // but the parser MUST surface an error rather than silently
        // dropping the override.
        assert!(
            err.to_string().contains("garbage"),
            "garbage min-release-age must surface a parser error: {err}"
        );
    }

    #[test]
    fn build_install_global_overrides_parses_min_release_age_exclude() {
        let o = build_install_global_overrides_with_excludes(
            false,
            false,
            None,
            false,
            false,
            None,
            vec!["react".to_string(), "@scope/pkg".to_string()],
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(
            o.min_release_age_exclude,
            vec!["react".to_string(), "@scope/pkg".to_string()]
        );

        let err = build_install_global_overrides_with_excludes(
            false,
            false,
            None,
            false,
            false,
            None,
            vec!["@scope/*".to_string()],
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("exact package names"),
            "glob exclude must surface a parser error: {err}"
        );
    }

    #[test]
    fn build_install_global_overrides_canonicalizes_drift_ignore_policy() {
        // Per-package list → IgnoreNames.
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec!["axios".to_string(), "lodash".to_string()],
            false,
            vec![],
            false,
        )
        .unwrap();
        match o.drift_ignore_policy {
            DriftIgnorePolicy::IgnoreNames(set) => {
                assert!(set.contains("axios") && set.contains("lodash"));
            }
            other => panic!("expected IgnoreNames, got {other:?}"),
        }

        // -all wins over per-package list.
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec!["axios".to_string()],
            true,
            vec![],
            false,
        )
        .unwrap();
        assert!(matches!(
            o.drift_ignore_policy,
            DriftIgnorePolicy::IgnoreAll
        ));

        // Empty + false → EnforceAll.
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert!(matches!(
            o.drift_ignore_policy,
            DriftIgnorePolicy::EnforceAll
        ));
    }

    #[test]
    fn build_install_global_overrides_resolves_script_policy_aliases() {
        // --policy=allow → resolved Allow.
        let o = build_install_global_overrides(
            false,
            false,
            Some("allow"),
            false,
            false,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(o.script_policy_override, Some(ScriptPolicy::Allow));

        // --yolo → Allow.
        let o = build_install_global_overrides(
            false,
            false,
            None,
            true,
            false,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(o.script_policy_override, Some(ScriptPolicy::Allow));

        // --triage → Triage.
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            true,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(o.script_policy_override, Some(ScriptPolicy::Triage));

        // --policy=deny → Deny (explicit; not ambient default).
        let o = build_install_global_overrides(
            false,
            false,
            Some("deny"),
            false,
            false,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(o.script_policy_override, Some(ScriptPolicy::Deny));

        // No flag → resolves to the default (Deny) via the resolver.
        // Use a scoped HOME so the developer's ~/.lpm/config.toml
        // doesn't leak into the test (the resolver consults the
        // user-config tier).
        let _env = crate::test_env::ScopedEnv::set([(
            "HOME",
            std::ffi::OsString::from(std::env::temp_dir().to_str().unwrap()),
        )]);
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        // The resolver returns the default — Some(Deny). We forward
        // it as `Some` so the inner pipeline's resolver doesn't
        // double-resolve.
        assert!(o.script_policy_override.is_some());
    }

    #[test]
    fn build_install_global_overrides_rejects_unknown_policy_value() {
        let err = build_install_global_overrides(
            false,
            false,
            Some("yolo"), // Not a canonical --policy value (the alias is `--yolo`, not `--policy=yolo`).
            false,
            false,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("yolo"),
            "unknown policy value must surface a parser error: {err}"
        );
    }

    #[test]
    fn uninstall_global_rejects_project_scoped_yes_flag() {
        let cli = Cli::try_parse_from(["lpm", "uninstall", "-g", "eslint", "-y"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Uninstall(args) => {
                assert!(args.global);
                assert!(args.yes);

                let err = validate_global_uninstall_project_scoped_flags(
                    &args.filter,
                    &[],
                    &[],
                    &[],
                    args.workspace_root,
                    args.fail_if_no_match,
                    args.yes,
                )
                .unwrap_err();

                match err {
                    lpm_common::LpmError::Script(message) => {
                        assert!(message.contains("`-y`"));
                        assert!(message.contains("project-scoped"));
                    }
                    other => panic!("expected Script error, got {other:?}"),
                }
            }
            _ => panic!("expected Uninstall command"),
        }
    }

    #[test]
    fn build_install_global_overrides_canonicalizes_verify_policy() {
        use crate::provenance_fetch::SkipPolicy;

        // Per-package list → `SkipPolicy::Names`.
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec![],
            false,
            vec!["axios".to_string(), "lodash".to_string()],
            false,
        )
        .unwrap();
        match o.verify_policy.skip {
            SkipPolicy::Names(set) => {
                assert!(set.contains("axios") && set.contains("lodash"));
            }
            other => panic!("expected SkipPolicy::Names, got {other:?}"),
        }

        // Blanket flag wins over per-package list (mirrors
        // DriftIgnorePolicy semantics).
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec![],
            false,
            vec!["axios".to_string()],
            true,
        )
        .unwrap();
        assert!(matches!(o.verify_policy.skip, SkipPolicy::All));

        // Empty + false → `SkipPolicy::None`.
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec![],
            false,
            vec![],
            false,
        )
        .unwrap();
        assert!(matches!(o.verify_policy.skip, SkipPolicy::None));
    }

    #[test]
    fn tunnel_local_actions_do_not_require_session() {
        for action in ["inspect", "replay", "log", "logs"] {
            assert!(
                !tunnel_action_requires_session(action),
                "expected {action} to stay local-only"
            );
        }
        for action in ["start", "claim", "unclaim", "list", "domains"] {
            assert!(
                tunnel_action_requires_session(action),
                "expected {action} to require a relay-backed session"
            );
        }
    }

    #[tokio::test]
    async fn tunnel_bearer_accepts_env_token_for_loopback_relay() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("HOME", home.path().as_os_str().to_owned()),
            ("LPM_TOKEN", "loopback-smoke-token".into()),
            ("LPM_FORCE_FILE_AUTH", "1".into()),
        ]);
        let session = lpm_auth::SessionManager::new("http://127.0.0.1:4873", None);

        let bearer =
            resolve_tunnel_bearer(Some(&session), "ws://127.0.0.1:54321/connect?port=3000")
                .await
                .expect("loopback relay should accept an env token");

        assert_eq!(bearer.as_deref(), Some("loopback-smoke-token"));
    }

    #[tokio::test]
    async fn tunnel_bearer_rejects_env_token_for_non_loopback_relay() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("HOME", home.path().as_os_str().to_owned()),
            ("LPM_TOKEN", "production-token".into()),
            ("LPM_FORCE_FILE_AUTH", "1".into()),
        ]);
        let session = lpm_auth::SessionManager::new("https://registry.lpm.dev", None);

        let err = resolve_tunnel_bearer(Some(&session), "wss://relay.lpm.fyi/connect")
            .await
            .expect_err("production relay should still require a stored session");

        assert!(
            err.to_string()
                .contains("requires a refresh-backed `lpm login` session"),
            "unexpected error: {err}"
        );
    }
}
