use super::parsers::parse_advisor_slug;
use super::*;
use clap::Parser;
use std::num::NonZeroUsize;

use crate::commands;
// Version flag parser contract.
//
// Pins the user-visible contract:
// - `-v`, `-V`, `--version` all set `cli.version` (no missing-
//   subcommand error).
// - `--verbose` long form survives.
// - `-v` is NO LONGER the short for `--verbose` — it was reclaimed
//   for `--version` to match npm/pnpm/yarn convention.

/// User-facing help for `lpm self-update --help` must NOT promise
/// "probes GitHub directly" any more — that wording was tied to
/// the old single-source design and would mislead users into
/// thinking they need a `GITHUB_TOKEN` for the common case. Lock
/// the new wording so a future doc edit doesn't silently regress.
#[test]
fn self_update_help_text_does_not_promise_github_probe() {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let mut buf = Vec::new();
    cmd.find_subcommand_mut("self-update")
        .expect("self-update subcommand registered")
        .write_long_help(&mut buf)
        .unwrap();
    let help = String::from_utf8(buf).unwrap();
    assert!(
        !help.contains("probe GitHub directly"),
        "stale wording still in help: {help}"
    );
    // Affirmative anchor: help must mention the npm-first probe so
    // users know the GITHUB_TOKEN hint in error messages is rare,
    // not the default path.
    assert!(
        help.contains("npm registry"),
        "help should mention npm registry as the primary probe: {help}"
    );
}

#[test]
fn capital_v_sets_version_flag_with_no_subcommand() {
    let cli = Cli::try_parse_from(["lpm", "-V"]).unwrap();
    assert!(cli.version_flag, "-V must set version flag");
    assert!(cli.command.is_none(), "no subcommand expected");
}

#[test]
fn lowercase_v_sets_version_flag_with_no_subcommand() {
    let cli = Cli::try_parse_from(["lpm", "-v"]).unwrap();
    assert!(cli.version_flag, "-v must set version flag");
    assert!(cli.command.is_none(), "no subcommand expected");
}

#[test]
fn verbose_long_form_survives() {
    let cli = Cli::try_parse_from(["lpm", "--verbose", "whoami"]).unwrap();
    assert!(cli.verbose, "--verbose must still parse");
    assert!(
        !cli.version_flag,
        "--verbose must not trigger version output"
    );
    assert!(matches!(cli.command, Some(Commands::Whoami)));
}

#[test]
fn audit_level_rejects_unknown_severity() {
    let error = match Cli::try_parse_from(["lpm", "audit", "--level", "severe"]) {
        Ok(_) => panic!("unknown audit severity must fail during argument parsing"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
}

#[test]
fn audit_level_accepts_critical_severity() {
    let cli = Cli::try_parse_from(["lpm", "audit", "--level", "critical"])
        .expect("documented critical audit severity should parse");
    let Some(Commands::Audit(security::AuditArgs { level, .. })) = cli.command else {
        panic!("expected Audit command");
    };
    assert_eq!(level, Some(commands::audit::AuditLevel::Critical));
}

#[test]
fn audit_level_accepts_documented_severity_aliases() {
    let low = Cli::try_parse_from(["lpm", "audit", "--level", "low"])
        .expect("documented low audit severity alias should parse");
    let medium = Cli::try_parse_from(["lpm", "audit", "--level", "medium"])
        .expect("documented medium audit severity alias should parse");

    let Some(Commands::Audit(security::AuditArgs {
        level: low_level, ..
    })) = low.command
    else {
        panic!("expected Audit command for low alias");
    };
    let Some(Commands::Audit(security::AuditArgs {
        level: medium_level,
        ..
    })) = medium.command
    else {
        panic!("expected Audit command for medium alias");
    };
    assert_eq!(low_level, Some(commands::audit::AuditLevel::Info));
    assert_eq!(medium_level, Some(commands::audit::AuditLevel::Moderate));
}

#[test]
fn config_without_action_parses_to_guided_editor() {
    let cli = Cli::try_parse_from(["lpm", "config"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Config(security::ConfigArgs {
            action,
            key,
            value,
            set,
        }) => {
            assert!(action.is_none());
            assert!(key.is_none());
            assert!(value.is_none());
            assert!(set.is_none());
        }
        _ => panic!("expected Config command"),
    }
}

#[test]
fn security_protect_enable_defaults_to_enforced_firewall() {
    let cli = Cli::try_parse_from(["lpm", "security", "protect", "enable"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Security(security::SecurityArgs {
            action:
                commands::security::SecurityCmd::Protect {
                    action:
                        commands::security::ProtectCmd::Enable {
                            firewall: commands::security::ProtectFirewallMode::Enforce,
                        },
                },
        }) => {}
        _ => panic!("expected security protect enable command"),
    }
}

#[test]
fn security_protect_enable_accepts_monitor_firewall() {
    let cli = Cli::try_parse_from([
        "lpm",
        "security",
        "protect",
        "enable",
        "--firewall",
        "monitor",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Security(security::SecurityArgs {
            action:
                commands::security::SecurityCmd::Protect {
                    action:
                        commands::security::ProtectCmd::Enable {
                            firewall: commands::security::ProtectFirewallMode::Monitor,
                        },
                },
        }) => {}
        _ => panic!("expected security protect enable --firewall monitor command"),
    }
}

#[test]
fn lowercase_v_after_subcommand_is_version_not_verbose() {
    // `-v` is reserved for `--version`, matching npm/pnpm/yarn.
    // Verbose output remains long-form only.
    let cli = Cli::try_parse_from(["lpm", "whoami", "-v"]).unwrap();
    assert!(
        cli.version_flag,
        "-v after subcommand must set version flag"
    );
    assert!(
        !cli.verbose,
        "-v must NOT set verbose (long --verbose only)"
    );
}

#[test]
fn info_subcommand_long_version_parses_as_package_version() {
    let cli = Cli::try_parse_from(["lpm", "info", "react", "--version", "1.0.0"]).unwrap();
    match cli.command {
        Some(Commands::Info(registry::InfoArgs {
            package,
            package_version,
        })) => {
            assert_eq!(package, "react");
            assert_eq!(package_version.as_deref(), Some("1.0.0"));
        }
        _ => panic!("expected info command"),
    }
}

#[test]
fn download_subcommand_long_version_parses_as_package_version() {
    let cli = Cli::try_parse_from(["lpm", "download", "react", "--version", "1.0.0"]).unwrap();
    match cli.command {
        Some(Commands::Download(registry::DownloadArgs {
            package,
            package_version,
            output,
            allow_unverified,
        })) => {
            assert_eq!(package, "react");
            assert_eq!(package_version.as_deref(), Some("1.0.0"));
            assert!(output.is_none());
            assert!(
                !allow_unverified,
                "allow_unverified must default to false — refuse-by-default audit posture",
            );
        }
        _ => panic!("expected download command"),
    }
}

/// `--allow-unverified` is opt-in and must be plumbed through the
/// parser so a user who explicitly accepts the risk of an
/// integrity-less tarball can do so without the parser swallowing
/// the flag.
#[test]
fn download_subcommand_parses_allow_unverified_flag() {
    let cli = Cli::try_parse_from(["lpm", "download", "react", "--allow-unverified"]).unwrap();
    match cli.command {
        Some(Commands::Download(registry::DownloadArgs {
            allow_unverified, ..
        })) => assert!(allow_unverified, "flag must surface as true"),
        _ => panic!("expected download command"),
    }
}

#[test]
fn publish_provenance_file_flag_parses_for_npm_target() {
    let cli = Cli::try_parse_from([
        "lpm",
        "publish",
        "--npm",
        "--provenance-file",
        "bundle.json",
    ])
    .unwrap();
    match cli.command {
        Some(Commands::Publish(registry::PublishArgs {
            npm,
            provenance,
            no_provenance,
            provenance_file,
            ..
        })) => {
            assert!(npm);
            assert!(!provenance);
            assert!(!no_provenance);
            assert_eq!(
                provenance_file.as_deref(),
                Some(std::path::Path::new("bundle.json"))
            );
        }
        _ => panic!("expected publish command"),
    }
}

#[test]
fn publish_provenance_modes_are_mutually_exclusive() {
    assert!(
        Cli::try_parse_from([
            "lpm",
            "publish",
            "--provenance",
            "--provenance-file",
            "b.json"
        ])
        .is_err()
    );
    assert!(Cli::try_parse_from(["lpm", "publish", "--provenance", "--no-provenance"]).is_err());
    assert!(
        Cli::try_parse_from([
            "lpm",
            "publish",
            "--no-provenance",
            "--provenance-file",
            "b.json"
        ])
        .is_err()
    );
}

#[test]
fn stage_publish_provenance_file_flag_parses() {
    let cli = Cli::try_parse_from([
        "lpm",
        "stage",
        "publish",
        "--provenance-file",
        "bundle.json",
    ])
    .unwrap();
    match cli.command {
        Some(Commands::Stage(registry::StageArgs {
            command:
                StageCommands::Publish {
                    provenance,
                    no_provenance,
                    provenance_file,
                    ..
                },
        })) => {
            assert!(!provenance);
            assert!(!no_provenance);
            assert_eq!(
                provenance_file.as_deref(),
                Some(std::path::Path::new("bundle.json"))
            );
        }
        _ => panic!("expected stage publish command"),
    }
}

#[test]
fn stage_publish_provenance_modes_are_mutually_exclusive() {
    assert!(
        Cli::try_parse_from([
            "lpm",
            "stage",
            "publish",
            "--provenance",
            "--provenance-file",
            "b.json"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from(["lpm", "stage", "publish", "--provenance", "--no-provenance"])
            .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "lpm",
            "stage",
            "publish",
            "--no-provenance",
            "--provenance-file",
            "b.json"
        ])
        .is_err()
    );
}

// ─── command_needs_global_state predicate ─────

// -- CLI parser must handle `lpm run build` without `--` --

#[test]
fn run_single_script_parses() {
    let cli = Cli::try_parse_from(["lpm", "run", "build"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs { scripts, args, .. }) => {
            assert_eq!(scripts, vec!["build"]);
            assert!(args.is_empty(), "args should be empty without --");
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_multiple_scripts_parses() {
    let cli = Cli::try_parse_from(["lpm", "run", "build", "test", "lint"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs { scripts, args, .. }) => {
            assert_eq!(scripts, vec!["build", "test", "lint"]);
            assert!(args.is_empty());
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_script_with_extra_args_after_separator() {
    let cli = Cli::try_parse_from(["lpm", "run", "build", "--", "--verbose", "--force"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs { scripts, args, .. }) => {
            assert_eq!(scripts, vec!["build"]);
            assert_eq!(args, vec!["--verbose", "--force"]);
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_script_with_flags_parses() {
    let cli = Cli::try_parse_from(["lpm", "run", "build", "--all", "--no-cache"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs {
            scripts,
            all,
            no_cache,
            args,
            ..
        }) => {
            assert_eq!(scripts, vec!["build"]);
            assert!(all);
            assert!(no_cache);
            assert!(args.is_empty());
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_script_with_flags_and_extra_args() {
    let cli =
        Cli::try_parse_from(["lpm", "run", "test", "--parallel", "--", "--coverage"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs {
            scripts,
            parallel,
            args,
            ..
        }) => {
            assert_eq!(scripts, vec!["test"]);
            assert!(parallel);
            assert_eq!(args, vec!["--coverage"]);
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_watch_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "run", "dev", "--watch"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs { scripts, watch, .. }) => {
            assert_eq!(scripts, vec!["dev"]);
            assert!(watch);
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn exec_env_flag_selects_env_mode_for_local_binary() {
    let cli = Cli::try_parse_from(["lpm", "exec", "--env", "staging", "eslint"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Exec(network::ExecArgs { env, command, .. }) => {
            assert_eq!(env.as_deref(), Some("staging"));
            assert_eq!(command, "eslint");
        }
        _ => panic!("expected Exec command"),
    }
}

#[test]
fn exec_hyphenated_args_are_forwarded_to_local_binary() {
    let cli = Cli::try_parse_from(["lpm", "exec", "eslint", "--fix", "src/index.ts"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Exec(network::ExecArgs { command, args, .. }) => {
            assert_eq!(command, "eslint");
            assert_eq!(args, vec!["--fix", "src/index.ts"]);
        }
        _ => panic!("expected Exec command"),
    }
}

#[test]
fn exec_extra_args_after_separator_are_forwarded_to_local_binary() {
    let cli =
        Cli::try_parse_from(["lpm", "exec", "eslint", "--", "--fix", "src/index.ts"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Exec(network::ExecArgs { command, args, .. }) => {
            assert_eq!(command, "eslint");
            assert_eq!(args, vec!["--fix", "src/index.ts"]);
        }
        _ => panic!("expected Exec command"),
    }
}

#[test]
fn run_file_env_flag_selects_env_mode() {
    let cli =
        Cli::try_parse_from(["lpm", "__run-file", "--env", "staging", "scripts/seed.ts"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::RunFile(network::RunFileArgs { env, file, .. }) => {
            assert_eq!(env.as_deref(), Some("staging"));
            assert_eq!(file, "scripts/seed.ts");
        }
        _ => panic!("expected RunFile command"),
    }
}

#[test]
fn run_file_watch_flag_parses_after_file() {
    let cli = Cli::try_parse_from(["lpm", "__run-file", "scripts/seed.ts", "--watch"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::RunFile(network::RunFileArgs {
            file, watch, args, ..
        }) => {
            assert_eq!(file, "scripts/seed.ts");
            assert!(watch);
            assert!(args.is_empty());
        }
        _ => panic!("expected RunFile command"),
    }
}

#[test]
fn run_file_plain_node_flag_disables_augmentation() {
    let cli =
        Cli::try_parse_from(["lpm", "__run-file", "--plain-node", "scripts/seed.ts"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::RunFile(network::RunFileArgs { plain_node, .. }) => {
            assert!(plain_node);
        }
        _ => panic!("expected RunFile command"),
    }
}

#[test]
fn run_file_extra_args_after_separator_are_forwarded() {
    let cli = Cli::try_parse_from([
        "lpm",
        "__run-file",
        "scripts/seed.ts",
        "--",
        "--flag",
        "value",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::RunFile(network::RunFileArgs { args, .. }) => {
            assert_eq!(args, vec!["--flag", "value"]);
        }
        _ => panic!("expected RunFile command"),
    }
}

// ── --filter as Vec<String> + --fail-if-no-match ──

#[test]
fn run_filter_flag_collects_into_vec() {
    let cli = Cli::try_parse_from([
        "lpm", "run", "build", "--filter", "foo", "--filter", "@ui/*",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs { filter, .. }) => {
            assert_eq!(filter, vec!["foo".to_string(), "@ui/*".to_string()]);
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_filter_prod_flag_collects_into_vec() {
    let cli = Cli::try_parse_from([
        "lpm",
        "run",
        "build",
        "--filter-prod",
        "...app",
        "--filter-prod",
        "core...",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs { filter_prod, .. }) => {
            assert_eq!(
                filter_prod,
                vec!["...app".to_string(), "core...".to_string()]
            );
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_changed_files_ignore_pattern_flag_collects_into_vec() {
    let cli = Cli::try_parse_from([
        "lpm",
        "run",
        "build",
        "--filter",
        "[main]",
        "--changed-files-ignore-pattern",
        "**/README.md",
        "--changed-files-ignore-pattern",
        "docs/**",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs {
            changed_files_ignore_pattern,
            ..
        }) => {
            assert_eq!(
                changed_files_ignore_pattern,
                vec!["**/README.md".to_string(), "docs/**".to_string()]
            );
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_test_pattern_flag_collects_into_vec() {
    let cli = Cli::try_parse_from([
        "lpm",
        "run",
        "build",
        "--affected",
        "--test-pattern",
        "**/*.test.js",
        "--test-pattern",
        "**/*.spec.js",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs { test_pattern, .. }) => {
            assert_eq!(
                test_pattern,
                vec!["**/*.test.js".to_string(), "**/*.spec.js".to_string()]
            );
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_fail_if_no_match_flag_parses() {
    let cli = Cli::try_parse_from([
        "lpm",
        "run",
        "build",
        "--filter",
        "foo",
        "--fail-if-no-match",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs {
            filter,
            fail_if_no_match,
            ..
        }) => {
            assert_eq!(filter, vec!["foo".to_string()]);
            assert!(fail_if_no_match);
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_no_bail_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "run", "build", "--no-bail"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs {
            continue_on_error, ..
        }) => {
            assert!(continue_on_error);
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_continue_on_error_flag_is_not_accepted() {
    let result = Cli::try_parse_from(["lpm", "run", "build", "--continue-on-error"]);
    assert!(
        result.is_err(),
        "--continue-on-error must not remain as a legacy alias for --no-bail"
    );
}

#[test]
fn run_workspace_concurrency_flag_parses() {
    let cli = Cli::try_parse_from([
        "lpm",
        "run",
        "build",
        "--filter",
        "@test/*",
        "--workspace-concurrency",
        "2",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs {
            workspace_concurrency,
            ..
        }) => {
            assert_eq!(workspace_concurrency.map(NonZeroUsize::get), Some(2));
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn run_workspace_concurrency_rejects_zero() {
    let result = Cli::try_parse_from([
        "lpm",
        "run",
        "build",
        "--filter",
        "@test/*",
        "--workspace-concurrency",
        "0",
    ]);
    assert!(result.is_err(), "--workspace-concurrency must reject zero");
}

#[test]
fn test_workspace_concurrency_flag_parses() {
    let cli = Cli::try_parse_from([
        "lpm",
        "test",
        "--filter",
        "@test/*",
        "--workspace-concurrency",
        "3",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Test(build::TestArgs {
            workspace_concurrency,
            ..
        }) => {
            assert_eq!(workspace_concurrency.map(NonZeroUsize::get), Some(3));
        }
        _ => panic!("expected Test command"),
    }
}

#[test]
fn bench_workspace_concurrency_flag_parses() {
    let cli = Cli::try_parse_from([
        "lpm",
        "bench",
        "--filter",
        "@test/*",
        "--workspace-concurrency",
        "4",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Bench(build::BenchArgs {
            workspace_concurrency,
            ..
        }) => {
            assert_eq!(workspace_concurrency.map(NonZeroUsize::get), Some(4));
        }
        _ => panic!("expected Bench command"),
    }
}

#[test]
fn run_all_and_filter_conflict() {
    let result = Cli::try_parse_from(["lpm", "run", "build", "--all", "--filter", "web"]);
    assert!(result.is_err(), "--all and --filter must conflict");
}

#[test]
fn run_all_and_affected_conflict() {
    let result = Cli::try_parse_from(["lpm", "run", "build", "--all", "--affected"]);
    assert!(result.is_err(), "--all and --affected must conflict");
}

#[test]
fn release_plan_all_and_filter_conflict() {
    let result = Cli::try_parse_from([
        "lpm", "release", "plan", "--all", "--filter", "core", "--bump", "patch",
    ]);
    assert!(result.is_err(), "--all and --filter must conflict");
}

#[test]
fn release_plan_all_and_filter_prod_conflict() {
    let result = Cli::try_parse_from([
        "lpm",
        "release",
        "plan",
        "--all",
        "--filter-prod",
        "core",
        "--bump",
        "patch",
    ]);
    assert!(result.is_err(), "--all and --filter-prod must conflict");
}

#[test]
fn release_plan_all_and_affected_conflict() {
    let result = Cli::try_parse_from([
        "lpm",
        "release",
        "plan",
        "--all",
        "--affected",
        "--bump",
        "patch",
    ]);
    assert!(result.is_err(), "--all and --affected must conflict");
}

// ── lpm filter subcommand ────────────────────────

#[test]
fn filter_command_parses_positional_exprs() {
    let cli = Cli::try_parse_from(["lpm", "filter", "@ui/*", "core"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Filter(lifecycle::FilterArgs {
            exprs,
            filter_prod,
            explain,
            fail_if_no_match,
            ..
        }) => {
            assert_eq!(exprs, vec!["@ui/*".to_string(), "core".to_string()]);
            assert!(filter_prod.is_empty());
            assert!(!explain, "default mode is terse, not explain");
            assert!(!fail_if_no_match);
        }
        _ => panic!("expected Filter command"),
    }
}

#[test]
fn filter_command_explain_flag_parses() {
    // `--explain` must be a real flag, not only documented and then
    // rejected at runtime.
    let cli = Cli::try_parse_from(["lpm", "filter", "--explain", "foo"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Filter(lifecycle::FilterArgs { exprs, explain, .. }) => {
            assert_eq!(exprs, vec!["foo".to_string()]);
            assert!(explain, "--explain must enable explain mode");
        }
        _ => panic!("expected Filter command"),
    }
}

#[test]
fn filter_command_explain_and_fail_if_no_match_compose() {
    let cli =
        Cli::try_parse_from(["lpm", "filter", "core", "--explain", "--fail-if-no-match"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Filter(lifecycle::FilterArgs {
            exprs,
            filter_prod: _,
            explain,
            fail_if_no_match,
            ..
        }) => {
            assert_eq!(exprs, vec!["core".to_string()]);
            assert!(explain);
            assert!(fail_if_no_match);
        }
        _ => panic!("expected Filter command"),
    }
}

#[test]
fn filter_command_allows_filter_prod_without_positional_exprs() {
    let cli = Cli::try_parse_from(["lpm", "filter", "--filter-prod", "...app"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Filter(lifecycle::FilterArgs {
            exprs, filter_prod, ..
        }) => {
            assert!(exprs.is_empty());
            assert_eq!(filter_prod, vec!["...app".to_string()]);
        }
        _ => panic!("expected Filter command"),
    }
}

#[test]
fn filter_command_changed_files_ignore_pattern_flag_collects_into_vec() {
    let cli = Cli::try_parse_from([
        "lpm",
        "filter",
        "[main]",
        "--changed-files-ignore-pattern",
        "**/README.md",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Filter(lifecycle::FilterArgs {
            changed_files_ignore_pattern,
            ..
        }) => {
            assert_eq!(
                changed_files_ignore_pattern,
                vec!["**/README.md".to_string()]
            );
        }
        _ => panic!("expected Filter command"),
    }
}

#[test]
fn filter_command_test_pattern_flag_collects_into_vec() {
    let cli = Cli::try_parse_from([
        "lpm",
        "filter",
        "...[main]",
        "--test-pattern",
        "**/*.test.js",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Filter(lifecycle::FilterArgs { test_pattern, .. }) => {
            assert_eq!(test_pattern, vec!["**/*.test.js".to_string()]);
        }
        _ => panic!("expected Filter command"),
    }
}

// ── install --filter / -w / --fail-if-no-match ──

#[test]
fn install_filter_flag_collects_into_vec() {
    let cli = Cli::try_parse_from([
        "lpm", "install", "react", "--filter", "web", "--filter", "@ui/*",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            packages,
            filter,
            workspace_root,
            fail_if_no_match,
            ..
        }) => {
            assert_eq!(packages, vec!["react".to_string()]);
            assert_eq!(filter, vec!["web".to_string(), "@ui/*".to_string()]);
            assert!(!workspace_root);
            assert!(!fail_if_no_match);
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_workspace_root_short_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "install", "typescript", "-w"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            packages,
            workspace_root,
            filter,
            ..
        }) => {
            assert_eq!(packages, vec!["typescript".to_string()]);
            assert!(workspace_root, "-w must enable workspace_root");
            assert!(filter.is_empty());
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_workspace_root_long_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "install", "typescript", "--workspace-root"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs { workspace_root, .. }) => {
            assert!(workspace_root, "--workspace-root must enable the flag");
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_timing_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "install", "--json", "--timing"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs { timing, .. }) => {
            assert!(timing, "--timing must enable install timing diagnostics");
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn snapshotless_lockfile_compatibility_requires_offline_for_install_and_ci() {
    assert!(Cli::try_parse_from(["lpm", "install", "--allow-snapshotless-lockfile"]).is_err());
    assert!(Cli::try_parse_from(["lpm", "ci", "--allow-snapshotless-lockfile"]).is_err());

    let install = Cli::try_parse_from([
        "lpm",
        "install",
        "--offline",
        "--allow-snapshotless-lockfile",
    ])
    .unwrap();
    match install.command.expect("install command") {
        Commands::Install(lifecycle::InstallArgs {
            offline,
            allow_snapshotless_lockfile,
            ..
        }) => {
            assert!(offline);
            assert!(allow_snapshotless_lockfile);
        }
        _ => panic!("expected Install command"),
    }

    let ci =
        Cli::try_parse_from(["lpm", "ci", "--offline", "--allow-snapshotless-lockfile"]).unwrap();
    match ci.command.expect("ci command") {
        Commands::Ci(build::CiArgs {
            offline,
            allow_snapshotless_lockfile,
            ..
        }) => {
            assert!(offline);
            assert!(allow_snapshotless_lockfile);
        }
        _ => panic!("expected Ci command"),
    }
}

#[test]
fn install_fail_if_no_match_flag_parses() {
    let cli = Cli::try_parse_from([
        "lpm",
        "install",
        "react",
        "--filter",
        "web",
        "--fail-if-no-match",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            fail_if_no_match, ..
        }) => {
            assert!(fail_if_no_match);
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_yes_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "install", "react", "-y"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs { packages, yes, .. }) => {
            assert_eq!(packages, vec!["react".to_string()]);
            assert!(yes, "-y must set the install confirmation bypass flag");
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_catalog_flag_parses_without_consuming_package() {
    let cli = Cli::try_parse_from(["lpm", "install", "--catalog", "react"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            packages, catalog, ..
        }) => {
            assert_eq!(packages, vec!["react".to_string()]);
            assert_eq!(catalog.as_deref(), Some("default"));
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_named_catalog_flag_parses_with_equals() {
    let cli = Cli::try_parse_from(["lpm", "install", "--catalog=testing", "react"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            packages, catalog, ..
        }) => {
            assert_eq!(packages, vec!["react".to_string()]);
            assert_eq!(catalog.as_deref(), Some("testing"));
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_catalog_flag_conflicts_with_direct_save_policy_flags() {
    assert!(Cli::try_parse_from(["lpm", "install", "--catalog", "--exact", "react"]).is_err());
    assert!(Cli::try_parse_from(["lpm", "install", "--catalog", "--tilde", "react"]).is_err());
    assert!(
        Cli::try_parse_from(["lpm", "install", "--catalog", "--save-prefix", "~", "react"])
            .is_err()
    );
}

#[test]
fn install_save_dev_with_filter_composes() {
    let cli =
        Cli::try_parse_from(["lpm", "install", "-D", "vitest", "--filter", "./apps/*"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            packages,
            save_dev,
            filter,
            ..
        }) => {
            assert_eq!(packages, vec!["vitest".to_string()]);
            assert!(save_dev);
            assert_eq!(filter, vec!["./apps/*".to_string()]);
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_bare_with_no_packages_and_no_filters_parses() {
    // Sanity: `lpm install` with no flags must still parse so this
    // does not break the bare-refresh path.
    let cli = Cli::try_parse_from(["lpm", "install"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            packages,
            filter,
            workspace_root,
            fail_if_no_match,
            ..
        }) => {
            assert!(packages.is_empty());
            assert!(filter.is_empty());
            assert!(!workspace_root);
            assert!(!fail_if_no_match);
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_strict_peer_dependencies_flags_parse_and_conflict() {
    let cli = Cli::try_parse_from(["lpm", "install", "--strict-peer-dependencies"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            strict_peer_dependencies,
            no_strict_peer_dependencies,
            ..
        }) => {
            assert!(strict_peer_dependencies);
            assert!(!no_strict_peer_dependencies);
        }
        _ => panic!("expected Install command"),
    }

    let cli = Cli::try_parse_from(["lpm", "install", "--no-strict-peer-dependencies"])
        .expect("`lpm install --no-strict-peer-dependencies` should parse");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            strict_peer_dependencies,
            no_strict_peer_dependencies,
            ..
        }) => {
            assert!(!strict_peer_dependencies);
            assert!(no_strict_peer_dependencies);
        }
        _ => panic!("expected Install command"),
    }

    let cli = Cli::try_parse_from([
        "lpm",
        "install",
        "-g",
        "eslint",
        "--strict-peer-dependencies",
    ])
    .expect("`lpm install -g --strict-peer-dependencies` should parse");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            global,
            strict_peer_dependencies,
            no_strict_peer_dependencies,
            ..
        }) => {
            assert!(global);
            assert!(strict_peer_dependencies);
            assert!(!no_strict_peer_dependencies);
        }
        _ => panic!("expected Install command"),
    }

    assert!(
        Cli::try_parse_from([
            "lpm",
            "install",
            "--strict-peer-dependencies",
            "--no-strict-peer-dependencies",
        ])
        .is_err()
    );
}

// ── `--advisor` clap validator ────
//
// Locks the parser contract for the CLI flag wired in this slice:
// every known provider slug + the explicit `"none"` opt-out are
// accepted; anything else fails before the install pipeline can
// touch state. The session-level precedence test lives next to
// the resolver (`triage_advisor_session::tests`); this pair pins
// the CLI surface itself.
#[test]
fn parse_advisor_slug_accepts_known_providers_and_none() {
    for s in ["none", "claude-cli", "codex", "ollama"] {
        assert_eq!(
            parse_advisor_slug(s).as_deref(),
            Ok(s),
            "must accept known slug {s:?}",
        );
    }
}

#[test]
fn parse_advisor_slug_rejects_unknown_with_actionable_message() {
    let err = parse_advisor_slug("anthropic-api").unwrap_err();
    assert!(
        err.contains("anthropic-api"),
        "error message must echo the offending input; got: {err}",
    );
    assert!(
        err.contains("none") && err.contains("claude-cli"),
        "error message must list the accepted set; got: {err}",
    );
}

#[test]
fn parse_advisor_slug_rejects_empty_string() {
    // `Option<String>` from clap distinguishes "flag absent"
    // (`None`) from "flag with empty value" (`Some("")`). The
    // empty form is a typo, not an opt-out — reject it so the
    // user sees the actionable error rather than getting silent
    // fall-through to package.json.
    assert!(parse_advisor_slug("").is_err());
}

// ── uninstall --filter / -w / --fail-if-no-match ──

#[test]
fn uninstall_filter_flag_collects_into_vec() {
    let cli = Cli::try_parse_from([
        "lpm",
        "uninstall",
        "lodash",
        "--filter",
        "web",
        "--filter",
        "@ui/*",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Uninstall(lifecycle::UninstallArgs {
            packages,
            filter,
            workspace_root,
            fail_if_no_match,
            ..
        }) => {
            assert_eq!(packages, vec!["lodash".to_string()]);
            assert_eq!(filter, vec!["web".to_string(), "@ui/*".to_string()]);
            assert!(!workspace_root);
            assert!(!fail_if_no_match);
        }
        _ => panic!("expected Uninstall command"),
    }
}

#[test]
fn uninstall_workspace_root_short_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "uninstall", "shared", "-w"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Uninstall(lifecycle::UninstallArgs { workspace_root, .. }) => {
            assert!(workspace_root);
        }
        _ => panic!("expected Uninstall command"),
    }
}

#[test]
fn uninstall_workspace_root_long_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "uninstall", "shared", "--workspace-root"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Uninstall(lifecycle::UninstallArgs { workspace_root, .. }) => {
            assert!(workspace_root);
        }
        _ => panic!("expected Uninstall command"),
    }
}

#[test]
fn uninstall_fail_if_no_match_flag_parses() {
    let cli = Cli::try_parse_from([
        "lpm",
        "uninstall",
        "foo",
        "--filter",
        "web",
        "--fail-if-no-match",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Uninstall(lifecycle::UninstallArgs {
            fail_if_no_match, ..
        }) => {
            assert!(fail_if_no_match);
        }
        _ => panic!("expected Uninstall command"),
    }
}

#[test]
fn uninstall_yes_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "uninstall", "lodash", "-y"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Uninstall(lifecycle::UninstallArgs { packages, yes, .. }) => {
            assert_eq!(packages, vec!["lodash".to_string()]);
            assert!(yes, "-y must set the uninstall confirmation bypass flag");
        }
        _ => panic!("expected Uninstall command"),
    }
}

#[test]
fn uninstall_visible_alias_un_still_works() {
    // The pre-existing visible alias `un` must continue to parse with
    // the new flags.
    let cli = Cli::try_parse_from(["lpm", "un", "foo", "-w"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Uninstall(lifecycle::UninstallArgs {
            packages,
            workspace_root,
            ..
        }) => {
            assert_eq!(packages, vec!["foo".to_string()]);
            assert!(workspace_root);
        }
        _ => panic!("expected Uninstall command via `un` alias"),
    }
}

// ── lpm deploy ────────────────────────────────────

#[test]
fn deploy_command_parses_required_output_and_filter() {
    let cli = Cli::try_parse_from(["lpm", "deploy", "/prod/api", "--filter", "api"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Deploy(lifecycle::DeployArgs {
            output,
            filter,
            force,
            dry_run,
            ..
        }) => {
            assert_eq!(output, "/prod/api");
            assert_eq!(filter, vec!["api".to_string()]);
            assert!(!force);
            assert!(!dry_run);
        }
        _ => panic!("expected Deploy command"),
    }
}

#[test]
fn deploy_command_filter_can_be_glob_or_path() {
    // The filter expression supports the full grammar.
    let cli =
        Cli::try_parse_from(["lpm", "deploy", "/prod/web", "--filter", "@scope/web"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Deploy(lifecycle::DeployArgs { filter, .. }) => {
            assert_eq!(filter, vec!["@scope/web".to_string()]);
        }
        _ => panic!("expected Deploy command"),
    }
}

#[test]
fn deploy_command_force_flag_parses() {
    let cli =
        Cli::try_parse_from(["lpm", "deploy", "/prod/api", "--filter", "api", "--force"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Deploy(lifecycle::DeployArgs { force, .. }) => assert!(force),
        _ => panic!("expected Deploy command"),
    }
}

#[test]
fn deploy_command_dry_run_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "deploy", "/prod/api", "--filter", "api", "--dry-run"])
        .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Deploy(lifecycle::DeployArgs { dry_run, .. }) => assert!(dry_run),
        _ => panic!("expected Deploy command"),
    }
}

#[test]
fn deploy_command_dependency_mode_flags_parse() {
    let cli =
        Cli::try_parse_from(["lpm", "deploy", "/prod/api", "--filter", "api", "--prod"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Deploy(lifecycle::DeployArgs { prod, dev, .. }) => {
            assert!(prod);
            assert!(!dev);
        }
        _ => panic!("expected Deploy command"),
    }

    let cli =
        Cli::try_parse_from(["lpm", "deploy", "/prod/api", "--filter", "api", "--dev"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Deploy(lifecycle::DeployArgs { prod, dev, .. }) => {
            assert!(!prod);
            assert!(dev);
        }
        _ => panic!("expected Deploy command"),
    }
}

#[test]
fn deploy_command_prod_and_dev_conflict() {
    let result = Cli::try_parse_from([
        "lpm",
        "deploy",
        "/prod/api",
        "--filter",
        "api",
        "--prod",
        "--dev",
    ]);
    assert!(
        result.is_err(),
        "deploy --prod and --dev must be mutually exclusive"
    );
}

#[test]
fn deploy_command_no_optional_flag_parses() {
    let cli = Cli::try_parse_from([
        "lpm",
        "deploy",
        "/prod/api",
        "--filter",
        "api",
        "--no-optional",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Deploy(lifecycle::DeployArgs { no_optional, .. }) => assert!(no_optional),
        _ => panic!("expected Deploy command"),
    }
}

#[test]
fn deploy_command_without_filter_parses_for_runtime_validation() {
    let cli = Cli::try_parse_from(["lpm", "deploy", "/prod/api"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Deploy(lifecycle::DeployArgs {
            filter,
            filter_prod,
            ..
        }) => {
            assert!(filter.is_empty());
            assert!(filter_prod.is_empty());
        }
        _ => panic!("expected Deploy command"),
    }
}

#[test]
fn deploy_command_filter_prod_flag_parses() {
    let cli =
        Cli::try_parse_from(["lpm", "deploy", "/prod/api", "--filter-prod", "...api"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Deploy(lifecycle::DeployArgs { filter_prod, .. }) => {
            assert_eq!(filter_prod, vec!["...api".to_string()]);
        }
        _ => panic!("expected Deploy command"),
    }
}

#[test]
fn deploy_command_requires_output_argument() {
    let result = Cli::try_parse_from(["lpm", "deploy", "--filter", "api"]);
    assert!(
        result.is_err(),
        "deploy without an output dir must be a parse error"
    );
}

#[test]
fn deploy_command_filter_can_be_passed_multiple_times() {
    // Even though deploy will hard-error at runtime if more than one
    // member matches, the CLI parser must accept multiple --filter
    // flags. The single-member assertion happens in `resolve_deploy_target`, not at parse time.
    let cli = Cli::try_parse_from([
        "lpm",
        "deploy",
        "/prod/api",
        "--filter",
        "api",
        "--filter",
        "@scope/api",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Deploy(lifecycle::DeployArgs { filter, .. }) => {
            assert_eq!(filter.len(), 2);
        }
        _ => panic!("expected Deploy command"),
    }
}

// ── ApproveScripts command flag parsing ──

#[test]
fn approve_scripts_no_args_parses_to_interactive_default() {
    let cli = Cli::try_parse_from(["lpm", "approve-scripts"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::ApproveScripts(security::ApproveScriptsArgs {
            package,
            yes,
            list,
            global,
            group,
            dry_run,
        }) => {
            assert!(package.is_none());
            assert!(!yes);
            assert!(!list);
            assert!(!global);
            assert!(!group);
            assert!(!dry_run);
        }
        _ => panic!("expected ApproveScripts command"),
    }
}

#[test]
fn approve_scripts_with_pkg_argument_parses() {
    let cli = Cli::try_parse_from(["lpm", "approve-scripts", "esbuild"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::ApproveScripts(security::ApproveScriptsArgs { package, .. }) => {
            assert_eq!(package, Some("esbuild".to_string()));
        }
        _ => panic!("expected ApproveScripts command"),
    }
}

#[test]
fn approve_scripts_with_versioned_pkg_argument_parses() {
    let cli = Cli::try_parse_from(["lpm", "approve-scripts", "esbuild@0.25.1"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::ApproveScripts(security::ApproveScriptsArgs { package, .. }) => {
            assert_eq!(package, Some("esbuild@0.25.1".to_string()));
        }
        _ => panic!("expected ApproveScripts command"),
    }
}

#[test]
fn approve_scripts_yes_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "approve-scripts", "--yes"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::ApproveScripts(security::ApproveScriptsArgs { yes, .. }) => {
            assert!(yes);
        }
        _ => panic!("expected ApproveScripts command"),
    }
}

#[test]
fn approve_scripts_list_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "approve-scripts", "--list"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::ApproveScripts(security::ApproveScriptsArgs { list, .. }) => {
            assert!(list);
        }
        _ => panic!("expected ApproveScripts command"),
    }
}

#[test]
fn approve_scripts_yes_and_list_together_is_a_parse_error() {
    // The clap `conflicts_with` declaration on the field should make
    // this a parse-time error rather than a runtime error. Belt-and-
    // suspenders with the runtime check in approve_scripts::run.
    let result = Cli::try_parse_from(["lpm", "approve-scripts", "--yes", "--list"]);
    assert!(
        result.is_err(),
        "--yes and --list together must be a parse error"
    );
}

#[test]
fn approve_scripts_json_with_list_parses() {
    // --json is a top-level Cli flag, not on the subcommand. Verify
    // it composes with `--list` cleanly.
    let cli = Cli::try_parse_from(["lpm", "--json", "approve-scripts", "--list"]).unwrap();
    assert!(cli.json);
    match cli.command.expect("test parse missing subcommand") {
        Commands::ApproveScripts(security::ApproveScriptsArgs { list, .. }) => assert!(list),
        _ => panic!("expected ApproveScripts command"),
    }
}

#[test]
fn approve_scripts_global_group_list_parses() {
    let cli =
        Cli::try_parse_from(["lpm", "approve-scripts", "--global", "--group", "--list"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::ApproveScripts(security::ApproveScriptsArgs {
            global,
            group,
            list,
            ..
        }) => {
            assert!(global);
            assert!(group);
            assert!(list);
        }
        _ => panic!("expected ApproveScripts command"),
    }
}

#[test]
fn rebuild_force_flag_parses() {
    // `--force` re-runs lifecycle scripts even for already-built
    // packages; assert it propagates as the `force` field on Rebuild.
    let cli = Cli::try_parse_from(["lpm", "rebuild", "--force", "esbuild"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Rebuild(lifecycle::RebuildArgs {
            force, packages, ..
        }) => {
            assert!(force, "--force should set force=true");
            assert_eq!(packages, vec!["esbuild".to_string()]);
        }
        _ => panic!("expected Rebuild command"),
    }
}

#[test]
fn rebuild_legacy_long_flag_is_rejected() {
    // `--rebuild` is not a flag; the rebuild command's force-rerun
    // switch is `--force`. Old invocations must fail at parse time
    // so users see an explicit error rather than a silent no-op.
    let result = Cli::try_parse_from(["lpm", "rebuild", "--rebuild"]);
    assert!(
        result.is_err(),
        "--rebuild should be rejected; the correct flag is --force"
    );
}

#[test]
fn rebuild_no_sandbox_is_single_flag() {
    // `--no-sandbox` collapsed the
    // legacy `--unsafe-full-env` partner — single flag drops
    // BOTH containment AND env scrubbing. No deprecation alias per
    // beta-cleanup policy.
    let cli = Cli::try_parse_from(["lpm", "rebuild", "--no-sandbox"])
        .expect("`--no-sandbox` should parse standalone");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Rebuild(lifecycle::RebuildArgs { no_sandbox, .. }) => {
            assert!(no_sandbox, "--no-sandbox should set no_sandbox=true");
        }
        _ => panic!("expected Rebuild command"),
    }

    // `--unsafe-full-env` is fully removed — clap rejects it.
    let result = Cli::try_parse_from(["lpm", "rebuild", "--unsafe-full-env"]);
    assert!(
        result.is_err(),
        "`--unsafe-full-env` must be removed entirely"
    );
}

#[test]
fn rebuild_strict_sandbox_and_no_sandbox_are_mutually_exclusive() {
    // opting INTO containment (`--strict-sandbox`
    // / `--paranoid`) and opting OUT entirely (`--no-sandbox`)
    // cannot coexist on the same command.
    let result = Cli::try_parse_from(["lpm", "rebuild", "--strict-sandbox", "--no-sandbox"]);
    assert!(
        result.is_err(),
        "`--strict-sandbox` + `--no-sandbox` must conflict at parse"
    );

    let result = Cli::try_parse_from(["lpm", "rebuild", "--paranoid", "--no-sandbox"]);
    assert!(
        result.is_err(),
        "`--paranoid` + `--no-sandbox` must conflict at parse"
    );

    let result = Cli::try_parse_from(["lpm", "rebuild", "--strict-sandbox", "--paranoid"]);
    assert!(
        result.is_err(),
        "`--strict-sandbox` + `--paranoid` (same intent) must conflict at parse"
    );
}

#[test]
fn rebuild_strict_sandbox_alias_paranoid_parses() {
    let cli = Cli::try_parse_from(["lpm", "rebuild", "--strict-sandbox"])
        .expect("--strict-sandbox should parse");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Rebuild(lifecycle::RebuildArgs {
            strict_sandbox,
            paranoid,
            ..
        }) => {
            assert!(strict_sandbox);
            assert!(!paranoid);
        }
        _ => panic!("expected Rebuild command"),
    }

    let cli = Cli::try_parse_from(["lpm", "rebuild", "--paranoid"])
        .expect("--paranoid (alias) should parse");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Rebuild(lifecycle::RebuildArgs {
            strict_sandbox,
            paranoid,
            ..
        }) => {
            assert!(!strict_sandbox);
            assert!(paranoid);
        }
        _ => panic!("expected Rebuild command"),
    }
}

#[test]
fn install_sandbox_mode_flags_parse() {
    // install gains the same trio. Strict and
    // paranoid are aliases; both conflict with --no-sandbox.
    let cli = Cli::try_parse_from(["lpm", "install", "--strict-sandbox"])
        .expect("`lpm install --strict-sandbox` should parse");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            strict_sandbox,
            paranoid,
            no_sandbox,
            ..
        }) => {
            assert!(strict_sandbox);
            assert!(!paranoid);
            assert!(!no_sandbox);
        }
        _ => panic!("expected Install command"),
    }

    let cli = Cli::try_parse_from(["lpm", "install", "--paranoid"])
        .expect("`lpm install --paranoid` should parse");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            strict_sandbox,
            paranoid,
            ..
        }) => {
            assert!(!strict_sandbox);
            assert!(paranoid);
        }
        _ => panic!("expected Install command"),
    }

    let cli = Cli::try_parse_from(["lpm", "install", "--no-sandbox"])
        .expect("`lpm install --no-sandbox` should parse standalone");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs { no_sandbox, .. }) => {
            assert!(no_sandbox);
        }
        _ => panic!("expected Install command"),
    }

    // Conflicts at parse.
    assert!(Cli::try_parse_from(["lpm", "install", "--strict-sandbox", "--no-sandbox"]).is_err());
    assert!(Cli::try_parse_from(["lpm", "install", "--paranoid", "--no-sandbox"]).is_err());
    assert!(Cli::try_parse_from(["lpm", "install", "--strict-sandbox", "--paranoid"]).is_err());
}

#[test]
fn install_unverified_provenance_flag_parses_repeatable_and_blanket() {
    // Per-package `--unverified-provenance <name>` is
    // repeatable; `--unverified-provenance-all` is a blanket
    // flag. Both must parse and reach the `Install` variant
    // fields.
    let cli = Cli::try_parse_from([
        "lpm",
        "install",
        "--unverified-provenance",
        "axios",
        "--unverified-provenance",
        "lodash",
    ])
    .expect("repeatable --unverified-provenance should parse");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            unverified_provenance,
            unverified_provenance_all,
            ..
        }) => {
            assert_eq!(
                unverified_provenance,
                vec!["axios".to_string(), "lodash".to_string()],
            );
            assert!(
                !unverified_provenance_all,
                "blanket flag MUST remain false when only the per-package flag was passed",
            );
        }
        _ => panic!("expected Install command"),
    }

    let cli = Cli::try_parse_from(["lpm", "install", "--unverified-provenance-all"])
        .expect("--unverified-provenance-all should parse standalone");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            unverified_provenance,
            unverified_provenance_all,
            ..
        }) => {
            assert!(unverified_provenance.is_empty());
            assert!(unverified_provenance_all);
        }
        _ => panic!("expected Install command"),
    }

    // Composition: per-package list AND blanket flag in the same
    // invocation. NOT a parse error (no clap mutex) — the
    // canonicalization in `VerifyPolicy::from_cli` collapses to
    // `SkipPolicy::All`. This mirrors the existing
    // `--ignore-provenance-drift` shape.
    let cli = Cli::try_parse_from([
        "lpm",
        "install",
        "--unverified-provenance",
        "axios",
        "--unverified-provenance-all",
    ])
    .expect("composing per-package + blanket flag must NOT be a clap error");
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            unverified_provenance,
            unverified_provenance_all,
            ..
        }) => {
            assert_eq!(unverified_provenance, vec!["axios".to_string()]);
            assert!(unverified_provenance_all);
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn graph_no_open_flag_parses() {
    // --no-open suppresses the auto-open browser side effect on
    // `--format html` for headless / CI use.
    let cli = Cli::try_parse_from(["lpm", "graph", "--format", "html", "--no-open"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Graph(lifecycle::GraphArgs {
            no_open, format, ..
        }) => {
            assert!(no_open, "--no-open should set no_open=true");
            assert_eq!(format, "html");
        }
        _ => panic!("expected Graph command"),
    }
}

#[test]
fn graph_ls_alias_parses_as_graph_command() {
    let cli = Cli::try_parse_from(["lpm", "ls", "--depth", "2"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Graph(lifecycle::GraphArgs { depth, .. }) => {
            assert_eq!(depth, Some(2));
        }
        _ => panic!("expected Graph command"),
    }
}

#[test]
fn why_top_level_command_parses_package_name() {
    let cli = Cli::try_parse_from(["lpm", "--json", "why", "zod"]).unwrap();
    assert!(cli.json);
    match cli.command.expect("test parse missing subcommand") {
        Commands::Why(lifecycle::WhyArgs { package }) => {
            assert_eq!(package, "zod");
        }
        _ => panic!("expected Why command"),
    }
}

#[test]
fn upgrade_package_arguments_parse_before_flags() {
    let cli = Cli::try_parse_from(["lpm", "upgrade", "zod", "react", "--dry-run", "-y"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Upgrade(lifecycle::UpgradeArgs {
            packages,
            dry_run,
            yes,
            ..
        }) => {
            assert_eq!(packages, vec!["zod".to_string(), "react".to_string()]);
            assert!(dry_run);
            assert!(yes);
        }
        _ => panic!("expected Upgrade command"),
    }
}

#[test]
fn licenses_policy_flags_parse() {
    let cli = Cli::try_parse_from([
        "lpm",
        "licenses",
        "--fail-on",
        "copyleft,missing",
        "--deny",
        "GPL-3.0",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Licenses(security::LicensesArgs { fail_on, deny }) => {
            assert_eq!(
                fail_on,
                vec![
                    commands::licenses::LicenseFailOn::Copyleft,
                    commands::licenses::LicenseFailOn::Missing,
                ]
            );
            assert_eq!(deny, vec!["GPL-3.0".to_string()]);
        }
        _ => panic!("expected Licenses command"),
    }
}

#[test]
fn completions_subcommand_parses_for_every_supported_shell() {
    // `lpm completions <shell>` emits a clap-generated completion
    // script. Every shell `clap_complete::Shell` accepts must parse
    // into the `Completions` variant.
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let cli = Cli::try_parse_from(["lpm", "completions", shell])
            .unwrap_or_else(|e| panic!("`lpm completions {shell}` failed to parse: {e}"));
        match cli.command.expect("test parse missing subcommand") {
            Commands::Completions(build::CompletionsArgs { .. }) => {}
            _ => panic!("expected Completions command for shell '{shell}'"),
        }
    }
}

// ── Dev command flag parsing ──

#[test]
fn dev_dashboard_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "dev", "--dashboard"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs { dashboard, .. }) => {
            assert!(dashboard);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_quiet_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "dev", "-q"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs { quiet, .. }) => {
            assert!(quiet);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_quiet_long_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "dev", "--quiet"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs { quiet, .. }) => {
            assert!(quiet);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_dashboard_and_tunnel_flags_parse() {
    let cli = Cli::try_parse_from(["lpm", "dev", "--dashboard", "--tunnel"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs {
            dashboard, tunnel, ..
        }) => {
            assert!(dashboard);
            assert!(tunnel);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_defaults_dashboard_false() {
    let cli = Cli::try_parse_from(["lpm", "dev"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs {
            dashboard, quiet, ..
        }) => {
            assert!(!dashboard);
            assert!(!quiet);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_no_dashboard_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "dev", "--no-dashboard"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs {
            dashboard,
            no_dashboard,
            ..
        }) => {
            assert!(!dashboard);
            assert!(no_dashboard);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_dashboard_and_no_dashboard_conflict() {
    // --dashboard and --no-dashboard should conflict
    let result = Cli::try_parse_from(["lpm", "dev", "--dashboard", "--no-dashboard"]);
    assert!(
        result.is_err(),
        "--dashboard and --no-dashboard should conflict"
    );
}

#[test]
fn dev_no_https_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "dev", "--https", "--no-https"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs {
            https, no_https, ..
        }) => {
            assert!(https);
            assert!(no_https);
            // Effective value: https && !no_https = false
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_no_tunnel_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "dev", "--tunnel", "--no-tunnel"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs {
            tunnel, no_tunnel, ..
        }) => {
            assert!(tunnel);
            assert!(no_tunnel);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_tunnel_auth_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "dev", "--tunnel", "--tunnel-auth"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs {
            tunnel,
            tunnel_auth,
            ..
        }) => {
            assert!(tunnel);
            assert!(tunnel_auth);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_tunnel_auth_defaults_false() {
    let cli = Cli::try_parse_from(["lpm", "dev"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs { tunnel_auth, .. }) => {
            assert!(!tunnel_auth);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn tunnel_tunnel_auth_flag_parses() {
    let cli = Cli::try_parse_from(["lpm", "tunnel", "start", "--tunnel-auth"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Tunnel(network::TunnelArgs { tunnel_auth, .. }) => {
            assert!(tunnel_auth);
        }
        _ => panic!("expected Tunnel command"),
    }
}

#[test]
fn tunnel_inspect_port_default_is_none() {
    // No `--inspect-port` → `None` → call site auto-picks via bind(0).
    // Distinguishing "user didn't pass" from "user passed 4400" is the
    // contract this test protects.
    let cli = Cli::try_parse_from(["lpm", "tunnel", "3000"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Tunnel(network::TunnelArgs { inspect_port, .. }) => {
            assert_eq!(inspect_port, None);
        }
        _ => panic!("expected Tunnel command"),
    }
}

#[test]
fn tunnel_inspect_port_explicit_is_some() {
    let cli = Cli::try_parse_from(["lpm", "tunnel", "3000", "--inspect-port", "4500"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Tunnel(network::TunnelArgs { inspect_port, .. }) => {
            assert_eq!(inspect_port, Some(4500));
        }
        _ => panic!("expected Tunnel command"),
    }
}

#[test]
fn dev_inspect_port_default_is_none() {
    let cli = Cli::try_parse_from(["lpm", "dev"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs {
            inspect_port,
            no_inspect,
            ..
        }) => {
            assert_eq!(inspect_port, None);
            assert!(!no_inspect);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn dev_inspect_flags_parse() {
    let cli = Cli::try_parse_from([
        "lpm",
        "dev",
        "--tunnel",
        "--inspect-port",
        "4500",
        "--no-inspect",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Dev(build::DevArgs {
            inspect_port,
            no_inspect,
            ..
        }) => {
            assert_eq!(inspect_port, Some(4500));
            assert!(no_inspect);
        }
        _ => panic!("expected Dev command"),
    }
}

#[test]
fn run_affected_with_base_parses() {
    let cli =
        Cli::try_parse_from(["lpm", "run", "build", "--affected", "--base", "develop"]).unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Run(network::RunArgs {
            scripts,
            affected,
            base,
            ..
        }) => {
            assert_eq!(scripts, vec!["build"]);
            assert!(affected);
            assert_eq!(base, "develop");
        }
        _ => panic!("expected Run command"),
    }
}

#[test]
fn env_global_json_before_command_sets_global_json_flag() {
    let cli = Cli::try_parse_from(["lpm", "--json", "env", "oidc", "list"]).unwrap();

    assert!(
        cli.json,
        "expected global --json to be parsed before env command"
    );

    match cli.command.expect("test parse missing subcommand") {
        Commands::Env(network::EnvArgs { extra }) => {
            assert_eq!(extra, vec!["oidc", "list"]);
        }
        _ => panic!("expected Env command"),
    }
}

#[test]
fn env_trailing_json_is_captured_as_raw_extra_arg() {
    let cli = Cli::try_parse_from(["lpm", "env", "oidc", "list", "--json"]).unwrap();

    assert!(
        !cli.json,
        "trailing --json after env should not be parsed as the global flag"
    );

    match cli.command.expect("test parse missing subcommand") {
        Commands::Env(network::EnvArgs { extra }) => {
            assert_eq!(extra, vec!["oidc", "list", "--json"]);
        }
        _ => panic!("expected Env command"),
    }
}

// ── install -g collision-resolution flags ───────────

#[test]
fn install_global_replace_bin_flag_collects_to_vec() {
    let cli = Cli::try_parse_from([
        "lpm",
        "install",
        "-g",
        "foo",
        "--replace-bin",
        "serve",
        "--replace-bin",
        "lint",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            global,
            replace_bin,
            alias,
            ..
        }) => {
            assert!(global);
            assert_eq!(replace_bin, vec!["serve".to_string(), "lint".to_string()]);
            assert!(alias.is_empty());
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_global_alias_flag_accepts_comma_and_repeated_forms() {
    let cli = Cli::try_parse_from([
        "lpm",
        "install",
        "-g",
        "foo",
        "--alias",
        "serve=foo-serve,lint=foo-lint",
        "--alias",
        "test=foo-test",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            global,
            alias,
            replace_bin,
            ..
        }) => {
            assert!(global);
            assert!(replace_bin.is_empty());
            assert_eq!(
                alias,
                vec![
                    "serve=foo-serve,lint=foo-lint".to_string(),
                    "test=foo-test".to_string()
                ]
            );
        }
        _ => panic!("expected Install command"),
    }
}

#[test]
fn install_global_collision_flags_coexist_with_g_short_flag() {
    let cli = Cli::try_parse_from([
        "lpm",
        "install",
        "-g",
        "foo",
        "--replace-bin",
        "serve",
        "--alias",
        "lint=foo-lint",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            global,
            replace_bin,
            alias,
            ..
        }) => {
            assert!(global);
            assert_eq!(replace_bin, vec!["serve".to_string()]);
            assert_eq!(alias, vec!["lint=foo-lint".to_string()]);
        }
        _ => panic!("expected Install command"),
    }
}

/// Clap must still accept the flags on the non-global path because
/// the dispatcher, not the parser, owns that contextual rejection.
/// This pins the parse-layer surface so a future change to clap's
/// constraints doesn't accidentally reject at parse time (which
/// would change the error message shape).
#[test]
fn install_non_global_with_collision_flags_parses_at_clap_layer() {
    let cli = Cli::try_parse_from([
        "lpm",
        "install",
        "foo",
        "--replace-bin",
        "serve",
        "--alias",
        "lint=foo-lint",
    ])
    .unwrap();
    match cli.command.expect("test parse missing subcommand") {
        Commands::Install(lifecycle::InstallArgs {
            global,
            replace_bin,
            alias,
            ..
        }) => {
            assert!(!global, "no -g → global should be false");
            assert_eq!(replace_bin, vec!["serve".to_string()]);
            assert_eq!(alias, vec!["lint=foo-lint".to_string()]);
        }
        _ => panic!("expected Install command"),
    }
}
