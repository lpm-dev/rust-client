use miette::Result;

use super::{
    Commands, SyncDispatch, async_main, install_state, parse_cli_or_exit, try_run_sync_command,
};

/// The directory the command started in, until its project's and the LPM
/// home's state is kept ignored as it ends.
static STARTED_IN: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// Has the command keep its state ignored as it ends, on whichever path it
/// exits.
pub(crate) fn keep_state_ignored_at_exit_from(started_in: &std::path::Path) {
    if let Ok(mut slot) = STARTED_IN.lock() {
        *slot = Some(started_in.to_path_buf());
    }
}

/// A helper that writes nothing of a project's or the LPM home's, so the
/// exit hook isn't set up to write for it on any path, an early error
/// included: one that reads stdin and writes stdout and nothing else, and
/// the elevated helpers, which would otherwise write, as the administrator
/// who approved them, in whatever directory they were started from (from
/// review); and the proxy's sign-in task, which starts in the system
/// directory and has the proxy it starts run in the project.
fn writes_nothing(command: Option<&Commands>) -> bool {
    matches!(
        command,
        Some(
            Commands::InternalPackageSignals(_)
                | Commands::InternalHostsFile(_)
                | Commands::InternalSecurityPolicy(_)
                | Commands::InternalCertStore(_)
                | Commands::InternalProxyService(_)
        )
    )
}

/// Keeps the project's `.lpm` and the LPM home out of git as the command
/// ends, once.
pub(crate) fn keep_state_ignored_at_exit() {
    let Some(cwd) = STARTED_IN.lock().ok().and_then(|mut slot| slot.take()) else {
        return;
    };
    let home = dirs::home_dir();
    let project_dir = lpm_workspace::find_project_config_root(&cwd, home.as_deref()).unwrap_or(cwd);
    keep_project_state_ignored(&project_dir);
}

pub(super) fn run_async_main() -> Result<()> {
    crate::open_file_limit::raise();
    let cli = parse_cli_or_exit();
    let project_dir = std::env::current_dir().ok();
    if let Some(cwd) = project_dir.as_deref()
        && !writes_nothing(cli.command.as_ref())
    {
        keep_state_ignored_at_exit_from(cwd);
    }

    let cli = match try_run_sync_command(cli) {
        SyncDispatch::Handled(result) => {
            keep_state_ignored_at_exit();
            return result;
        }
        SyncDispatch::ContinueAsync(cli) => *cli,
    };

    // Standalone and recursive installs poll large futures on different threads.
    // Debug frames are unoptimized and need 64 MiB; release frames are smaller
    // so 32 MiB retains deep-workspace recursion headroom over the 16 MiB baseline.
    #[cfg(debug_assertions)]
    const ASYNC_STACK_BYTES: usize = 64 * 1024 * 1024;
    #[cfg(not(debug_assertions))]
    const ASYNC_STACK_BYTES: usize = 32 * 1024 * 1024;

    let cpus = lpm_common::resources::effective_cpu_count();
    let workers = runtime_worker_threads(
        cli.command.as_ref(),
        std::env::var_os("TOKIO_WORKER_THREADS").is_some(),
        cpus,
        project_dir.as_deref(),
    );
    std::thread::Builder::new()
        .name("lpm-async-main".into())
        .stack_size(ASYNC_STACK_BYTES)
        .spawn(move || {
            let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
            runtime_builder.enable_all();
            runtime_builder.thread_stack_size(ASYNC_STACK_BYTES);
            if let Some(workers) = workers {
                runtime_builder.worker_threads(workers);
            }
            if let Some(max_blocking_threads) = std::env::var("LPM_MAX_BLOCKING_THREADS")
                .ok()
                .and_then(|s| s.parse::<std::num::NonZeroUsize>().ok())
                .map(std::num::NonZeroUsize::get)
            {
                runtime_builder.max_blocking_threads(max_blocking_threads);
            }
            let result = runtime_builder
                .build()
                .expect("failed to create tokio runtime")
                .block_on(async_main(cli));
            keep_state_ignored_at_exit();
            result
        })
        .expect("failed to spawn async main thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// Keeps the project's `.lpm` and the LPM home out of git after any
/// command, whichever path wrote state there. A project `.lpm` that is the
/// LPM home is kept as the LPM home.
pub(super) fn keep_project_state_ignored(project_dir: &std::path::Path) {
    let state_dir = lpm_common::project_state_dir(project_dir);
    let home = lpm_common::LpmRoot::from_env().ok();
    let is_lpm_home = home.as_ref().is_some_and(|root| {
        match (state_dir.canonicalize(), root.root().canonicalize()) {
            (Ok(state), Ok(home)) => state == home,
            _ => false,
        }
    });
    if !is_lpm_home {
        lpm_common::keep_existing_project_state_ignored(project_dir);
    }
    if let Some(root) = home {
        lpm_common::keep_existing_lpm_home_ignored(root.root());
    }
}

enum WorkerPoolClass {
    /// Commands whose async work stays bounded and benefits from avoiding a
    /// CPU-count Tokio thread pool at startup.
    TwoWorkers,
    /// Install-like commands that run on two workers for a single-package
    /// project and retain the full CPU-count pool for workspaces or uncertain
    /// layouts.
    SingleProjectOrFull,
    /// Commands that run workspace-wide fan-out, watchers, servers, or heavy
    /// multi-stream install/resolve pipelines.
    FullPool,
}

fn classify_worker_pool(command: Option<&Commands>) -> WorkerPoolClass {
    match command {
        Some(Commands::Install(args)) => {
            if !args.global
                && args.packages.is_empty()
                && !args.recursive
                && args.workspace_concurrency.is_none()
                && args.filter.is_empty()
                && args.filter_prod.is_empty()
                && !args.workspace_root
                && !args.fail_if_no_match
                && args.changed_files_ignore_pattern.is_empty()
                && args.test_pattern.is_empty()
            {
                WorkerPoolClass::SingleProjectOrFull
            } else {
                WorkerPoolClass::FullPool
            }
        }
        Some(Commands::Migrate(args)) => {
            if args.no_install || args.dry_run {
                WorkerPoolClass::TwoWorkers
            } else {
                WorkerPoolClass::SingleProjectOrFull
            }
        }
        Some(
            Commands::Ci(_)
            | Commands::Upgrade(_)
            | Commands::Tidy(_)
            | Commands::Uninstall(_)
            | Commands::ApproveScripts(_)
            | Commands::PatchCommit(_),
        ) => WorkerPoolClass::SingleProjectOrFull,
        Some(
            Commands::Add(_)
            | Commands::Fetch(_)
            | Commands::Resolve(_)
            | Commands::Deploy(_)
            | Commands::Rebuild(_)
            | Commands::Dev(_)
            | Commands::Tunnel(_)
            | Commands::Release(_)
            | Commands::Dlx(_)
            | Commands::Create(_)
            | Commands::Publish(_)
            | Commands::Proxy(_)
            | Commands::Skills(_),
        ) => WorkerPoolClass::FullPool,
        Some(Commands::Mcp(args)) => {
            if matches!(args.action, crate::commands::mcp::McpAction::Serve) {
                WorkerPoolClass::FullPool
            } else {
                WorkerPoolClass::TwoWorkers
            }
        }
        Some(Commands::Global(args)) => {
            if matches!(
                args.action,
                crate::commands::global::GlobalCmd::Update { .. }
            ) {
                WorkerPoolClass::FullPool
            } else {
                WorkerPoolClass::TwoWorkers
            }
        }
        Some(Commands::Run(args)) => {
            if args.scripts.len() > 1
                || args.parallel
                || args.workspace_concurrency.is_some()
                || args.all
                || !args.filter.is_empty()
                || !args.filter_prod.is_empty()
                || args.affected
                || args.watch
            {
                WorkerPoolClass::FullPool
            } else {
                WorkerPoolClass::TwoWorkers
            }
        }
        Some(Commands::RunFile(args)) => {
            if args.watch {
                WorkerPoolClass::FullPool
            } else {
                WorkerPoolClass::TwoWorkers
            }
        }
        Some(Commands::Lint(args)) => {
            workspace_tool_pool_class(args.all, args.affected, &args.filter, &args.filter_prod)
        }
        Some(Commands::Fmt(args)) => {
            workspace_tool_pool_class(args.all, args.affected, &args.filter, &args.filter_prod)
        }
        Some(Commands::Check(args)) => {
            workspace_tool_pool_class(args.all, args.affected, &args.filter, &args.filter_prod)
        }
        Some(Commands::Bundle(args)) => {
            workspace_tool_pool_class(args.all, args.affected, &args.filter, &args.filter_prod)
        }
        Some(Commands::Pack(args)) => {
            workspace_tool_pool_class(args.all, args.affected, &args.filter, &args.filter_prod)
        }
        Some(Commands::Test(args)) => {
            workspace_tool_pool_class(args.all, args.affected, &args.filter, &args.filter_prod)
        }
        Some(Commands::Bench(args)) => {
            workspace_tool_pool_class(args.all, args.affected, &args.filter, &args.filter_prod)
        }
        _ => WorkerPoolClass::TwoWorkers,
    }
}

fn workspace_tool_pool_class(
    all: bool,
    affected: bool,
    filter: &[String],
    filter_prod: &[String],
) -> WorkerPoolClass {
    if all || affected || !filter.is_empty() || !filter_prod.is_empty() {
        WorkerPoolClass::FullPool
    } else {
        WorkerPoolClass::TwoWorkers
    }
}

fn runtime_worker_threads(
    command: Option<&Commands>,
    explicit_worker_count: bool,
    available_parallelism: usize,
    project_dir: Option<&std::path::Path>,
) -> Option<usize> {
    if explicit_worker_count {
        return None;
    }
    match classify_worker_pool(command) {
        WorkerPoolClass::TwoWorkers => return Some(available_parallelism.clamp(1, 2)),
        WorkerPoolClass::FullPool => return None,
        WorkerPoolClass::SingleProjectOrFull => {}
    }
    let project_dir = project_dir?;
    let (content, _) = lpm_common::read_text_regular_file_capped_with_metadata(
        &project_dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .ok()?;
    if !install_state::is_non_workspace_package_json_object(&content)
        || project_dir.join("Package.swift").exists()
        || install_state::has_pnpm_workspace_yaml(project_dir)
        || lpm_workspace::find_workspace_root(project_dir)
            .ok()?
            .is_some()
    {
        return None;
    }
    Some(available_parallelism.clamp(1, 2))
}

#[cfg(test)]
mod tests {
    use super::super::Cli;
    use super::{runtime_worker_threads, writes_nothing};
    use clap::Parser;

    /// The elevated helpers keep what the exit hook would write, a
    /// project's `.lpm` and its `.gitignore`, as they found it.
    #[test]
    fn the_elevated_helpers_leave_project_state_alone_as_they_end() {
        for argv in [
            &["lpm", "internal-package-signals"][..],
            &["lpm", "internal-hosts-file", "clean"][..],
            &["lpm", "internal-security-policy", "enable-enforce"][..],
            &["lpm", "internal-cert-store", "remove", "--sha1", "AB"][..],
            &[
                "lpm",
                "internal-proxy-service",
                "--home",
                "h",
                "--project",
                "p",
                "--stdout",
                "o",
                "--stderr",
                "e",
                "--",
                "proxy",
                "start",
            ][..],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert!(writes_nothing(cli.command.as_ref()), "{argv:?}");
        }
        let cli = Cli::try_parse_from(["lpm", "install"]).unwrap();
        assert!(!writes_nothing(cli.command.as_ref()));
    }

    #[test]
    fn install_runtime_limits_default_workers_to_available_cpus_or_two() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "{}").unwrap();
        for args in [vec!["lpm", "install"], vec!["lpm", "i"], vec!["lpm", "ci"]] {
            let cli = Cli::try_parse_from(args).unwrap();
            for available in [1, 2, 18] {
                assert_eq!(
                    runtime_worker_threads(
                        cli.command.as_ref(),
                        false,
                        available,
                        Some(project.path())
                    ),
                    Some(available.min(2)),
                );
            }
        }
    }

    #[test]
    fn install_runtime_reads_a_package_json_with_a_byte_order_mark() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "\u{FEFF}{}").unwrap();
        let cli = Cli::try_parse_from(["lpm", "install"]).unwrap();
        assert_eq!(
            runtime_worker_threads(cli.command.as_ref(), false, 18, Some(project.path())),
            Some(2),
        );
    }

    #[test]
    fn install_runtime_leaves_explicit_worker_counts_to_tokio() {
        let cli = Cli::try_parse_from(["lpm", "install"]).unwrap();
        assert_eq!(
            runtime_worker_threads(cli.command.as_ref(), true, 18, None),
            None,
        );
    }

    #[test]
    fn single_script_and_local_state_commands_run_on_two_workers() {
        for args in [
            vec!["lpm", "run", "test"],
            vec!["lpm", "run", "test", "--", "--watch"],
            vec!["lpm", "__run-file", "scripts/seed.ts"],
            vec!["lpm", "exec", "tsc"],
            vec!["lpm", "why", "react"],
            vec!["lpm", "graph"],
            vec!["lpm", "audit"],
            vec!["lpm", "outdated"],
            vec!["lpm", "info", "react"],
            vec!["lpm", "doctor"],
            vec!["lpm", "pack"],
            vec!["lpm", "migrate", "--no-install"],
            vec!["lpm", "env", "ls"],
            vec!["lpm", "serve"],
            vec!["lpm", "config"],
            vec!["lpm", "self-update"],
            vec!["lpm", "whoami"],
            vec!["lpm", "lint"],
            vec!["lpm", "test"],
            vec!["lpm", "mcp", "status"],
            vec!["lpm", "global", "list"],
        ] {
            let cli = Cli::try_parse_from(&args).unwrap();
            for available in [1, 2, 18] {
                assert_eq!(
                    runtime_worker_threads(cli.command.as_ref(), false, available, None),
                    Some(available.min(2)),
                    "{args:?}",
                );
            }
            assert_eq!(
                runtime_worker_threads(cli.command.as_ref(), true, 18, None),
                None,
                "{args:?} with TOKIO_WORKER_THREADS",
            );
        }
    }

    #[test]
    fn non_install_commands_retain_tokio_worker_defaults() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "{}").unwrap();
        for args in [
            vec!["lpm", "install", "react"],
            vec!["lpm", "install", "--global", "react"],
            vec!["lpm", "install", "--global"],
            vec!["lpm", "install", "--recursive"],
            vec!["lpm", "install", "--workspace-concurrency", "4"],
            vec!["lpm", "install", "--filter", "app"],
            vec!["lpm", "install", "--filter-prod", "app"],
            vec!["lpm", "install", "--workspace-root"],
            vec!["lpm", "add", "react"],
            vec!["lpm", "dev"],
            vec!["lpm", "run", "build", "test"],
            vec!["lpm", "run", "test", "--parallel"],
            vec!["lpm", "run", "test", "--all"],
            vec!["lpm", "run", "test", "--filter", "app"],
            vec!["lpm", "run", "test", "--affected"],
            vec!["lpm", "run", "test", "--watch"],
            vec!["lpm", "__run-file", "scripts/seed.ts", "--watch"],
            vec!["lpm", "lint", "--all"],
            vec!["lpm", "test", "--filter", "app"],
            vec!["lpm", "pack", "--affected"],
            vec!["lpm", "tunnel", "3000"],
            vec!["lpm", "dlx", "cowsay"],
            vec!["lpm", "create", "vite"],
            vec!["lpm", "publish"],
            vec!["lpm", "proxy", "status"],
            vec!["lpm", "mcp", "serve"],
            vec!["lpm", "global", "update"],
            vec!["lpm", "skills", "list"],
        ] {
            let cli = Cli::try_parse_from(&args).unwrap();
            assert_eq!(
                runtime_worker_threads(cli.command.as_ref(), false, 18, Some(project.path())),
                None,
                "{args:?}",
            );
        }
    }

    #[test]
    fn workspace_installs_retain_cpu_count_runtime_workers() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("package.json"),
            r#"{"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        let member = project.path().join("packages/app");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("package.json"), r#"{"name":"app"}"#).unwrap();
        for args in [
            vec!["lpm", "install"],
            vec!["lpm", "ci"],
            vec!["lpm", "migrate"],
            vec!["lpm", "upgrade"],
            vec!["lpm", "tidy"],
            vec!["lpm", "uninstall", "react"],
            vec!["lpm", "approve-scripts"],
            vec!["lpm", "patch-commit", "staging"],
        ] {
            let cli = Cli::try_parse_from(&args).unwrap();
            for path in [project.path(), member.as_path()] {
                assert_eq!(
                    runtime_worker_threads(cli.command.as_ref(), false, 18, Some(path)),
                    None,
                    "{args:?} at {}",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn uncertain_project_context_keeps_runtime_defaults() {
        let cli = Cli::try_parse_from(["lpm", "install"]).unwrap();
        let project = tempfile::tempdir().unwrap();
        assert_eq!(
            runtime_worker_threads(cli.command.as_ref(), false, 18, None),
            None
        );
        assert_eq!(
            runtime_worker_threads(cli.command.as_ref(), false, 18, Some(project.path())),
            None
        );
        for manifest in [
            "invalid JSON",
            "[]",
            r#"{"workspaces":[]}"#,
            r#"{"\u0077orkspaces":[]}"#,
        ] {
            std::fs::write(project.path().join("package.json"), manifest).unwrap();
            assert_eq!(
                runtime_worker_threads(cli.command.as_ref(), false, 18, Some(project.path())),
                None,
                "manifest: {manifest}"
            );
        }
        assert!(crate::install_state::is_non_workspace_package_json_object(
            "\u{FEFF}{\"name\":\"app\",\"scripts\":{\"build\":\"echo workspaces\"}}"
        ));
        assert!(!crate::install_state::is_non_workspace_package_json_object(
            r#"{"\u0077orkspaces":["packages/*"]}"#
        ));
        assert!(!crate::install_state::is_non_workspace_package_json_object(
            r#"{"name":"app""#
        ));
    }

    #[test]
    fn ancestor_pnpm_workspace_marker_keeps_runtime_defaults() {
        let cli = Cli::try_parse_from(["lpm", "install", "--no-recursive"]).unwrap();
        let project = tempfile::tempdir().unwrap();
        let member = project.path().join("app");
        std::fs::create_dir(&member).unwrap();
        std::fs::write(member.join("package.json"), "{}").unwrap();
        std::fs::write(project.path().join("pnpm-workspace.yaml"), "packages: []\n").unwrap();
        assert_eq!(
            runtime_worker_threads(cli.command.as_ref(), false, 18, Some(&member)),
            None
        );
    }

    #[test]
    fn mixed_swift_project_keeps_runtime_defaults() {
        let cli = Cli::try_parse_from(["lpm", "install"]).unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "{}").unwrap();
        std::fs::write(project.path().join("Package.swift"), "").unwrap();
        assert_eq!(
            runtime_worker_threads(cli.command.as_ref(), false, 18, Some(project.path())),
            None
        );
    }
}
