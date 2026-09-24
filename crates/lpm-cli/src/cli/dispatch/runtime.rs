use miette::Result;

use super::{Commands, async_main, install_state, parse_cli_or_exit};

pub(super) fn run_async_main() -> Result<()> {
    // Standalone and recursive installs poll large futures on different threads.
    // Both need this stack budget for debug builds and large workspaces.
    const ASYNC_STACK_BYTES: usize = 64 * 1024 * 1024;
    std::thread::Builder::new()
        .name("lpm-async-main".into())
        .stack_size(ASYNC_STACK_BYTES)
        .spawn(move || {
            let cli = parse_cli_or_exit();
            let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
            runtime_builder.enable_all();
            runtime_builder.thread_stack_size(ASYNC_STACK_BYTES);
            let project_dir = std::env::current_dir().ok();
            if let Some(workers) = install_runtime_worker_threads(
                cli.command.as_ref(),
                std::env::var_os("TOKIO_WORKER_THREADS").is_some(),
                std::thread::available_parallelism().map_or(1, |count| count.get()),
                project_dir.as_deref(),
            ) {
                runtime_builder.worker_threads(workers);
            }
            if let Some(cap) = std::env::var("LPM_MAX_BLOCKING_THREADS")
                .ok()
                .and_then(|s| s.parse::<std::num::NonZeroUsize>().ok())
            {
                runtime_builder.max_blocking_threads(cap.get());
            }
            runtime_builder
                .build()
                .expect("failed to create tokio runtime")
                .block_on(async_main(cli))
        })
        .expect("failed to spawn async main thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

fn install_runtime_worker_threads(
    command: Option<&Commands>,
    explicit_worker_count: bool,
    available_parallelism: usize,
    project_dir: Option<&std::path::Path>,
) -> Option<usize> {
    if explicit_worker_count {
        return None;
    }
    let install = match command {
        Some(Commands::Install(args)) => {
            !args.global
                && args.packages.is_empty()
                && !args.recursive
                && args.workspace_concurrency.is_none()
                && args.filter.is_empty()
                && args.filter_prod.is_empty()
                && !args.workspace_root
                && !args.fail_if_no_match
                && args.changed_files_ignore_pattern.is_empty()
                && args.test_pattern.is_empty()
        }
        Some(Commands::Ci(_)) => true,
        _ => false,
    };
    if !install {
        return None;
    }
    let project_dir = project_dir?;
    let content = lpm_common::read_text_file_capped(
        &project_dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .ok()?;
    let package: serde_json::Value = serde_json::from_str(&content).ok()?;
    if !package.is_object()
        || package.get("workspaces").is_some()
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
    use super::install_runtime_worker_threads;
    use clap::Parser;

    #[test]
    fn install_runtime_limits_default_workers_to_available_cpus_or_two() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "{}").unwrap();
        for args in [vec!["lpm", "install"], vec!["lpm", "i"], vec!["lpm", "ci"]] {
            let cli = Cli::try_parse_from(args).unwrap();
            for available in [1, 2, 18] {
                assert_eq!(
                    install_runtime_worker_threads(
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
    fn install_runtime_leaves_explicit_worker_counts_to_tokio() {
        let cli = Cli::try_parse_from(["lpm", "install"]).unwrap();
        assert_eq!(
            install_runtime_worker_threads(cli.command.as_ref(), true, 18, None),
            None,
        );
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
            vec!["lpm", "run", "test"],
            vec!["lpm", "serve"],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert_eq!(
                install_runtime_worker_threads(
                    cli.command.as_ref(),
                    false,
                    18,
                    Some(project.path())
                ),
                None,
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
        for command in ["install", "ci"] {
            let cli = Cli::try_parse_from(["lpm", command]).unwrap();
            for path in [project.path(), member.as_path()] {
                assert_eq!(
                    install_runtime_worker_threads(cli.command.as_ref(), false, 18, Some(path)),
                    None,
                );
            }
        }
    }

    #[test]
    fn uncertain_project_context_keeps_runtime_defaults() {
        let cli = Cli::try_parse_from(["lpm", "install"]).unwrap();
        let project = tempfile::tempdir().unwrap();
        assert_eq!(
            install_runtime_worker_threads(cli.command.as_ref(), false, 18, None),
            None
        );
        assert_eq!(
            install_runtime_worker_threads(cli.command.as_ref(), false, 18, Some(project.path())),
            None
        );
        for manifest in ["invalid JSON", "[]", r#"{"workspaces":[]}"#] {
            std::fs::write(project.path().join("package.json"), manifest).unwrap();
            assert_eq!(
                install_runtime_worker_threads(
                    cli.command.as_ref(),
                    false,
                    18,
                    Some(project.path())
                ),
                None
            );
        }
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
            install_runtime_worker_threads(cli.command.as_ref(), false, 18, Some(&member)),
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
            install_runtime_worker_threads(cli.command.as_ref(), false, 18, Some(project.path())),
            None
        );
    }
}
