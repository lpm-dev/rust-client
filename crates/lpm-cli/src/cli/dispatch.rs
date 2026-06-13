use miette::Result;

use crate::{
    auth, auth_storage_notice, color_policy, commands, engine_check, install_state, output,
    provenance_fetch, release_age_config, save_spec, script_policy_config, tool_pin_validation,
    update_check,
};

use super::args::{
    Cli, Commands, DoctorAction, LinkerCli, OutdatedRegistryScope, SetupAction, StageCommands,
};
use super::format::{argv_has_global_registry_flag, exit_with_lpm_error, parse_cli_or_exit};
use super::helpers::{
    argv_requests_top_level_version, build_install_global_overrides, command_needs_global_state,
    install_omit_policy_from_cli, maybe_emit_network_fs_warning, print_version_with_notice,
    resolve_install_project_dir, should_suppress_update_banner, spawn_background_update_check,
    tunnel_action_requires_session, validate_global_install_project_scoped_flags,
    validate_global_uninstall_project_scoped_flags,
};

pub(crate) fn run() -> Result<()> {
    // Color policy must initialize BEFORE any styled output, including
    // the `--version` fast path (which prints an `update_check` notice)
    // and the bare-`lpm install` fast lane below (which prints a header
    // and a success line). Both run pre-clap, so we pre-scan argv for
    // `--color=<v>` to honor the flag without waiting for `Cli::parse`.
    // `clap` will validate the value later under its `value_enum`
    // contract; an unknown value here just falls back to env + TTY
    // detection until clap surfaces the typo.
    color_policy::init(color_policy::peek_color_choice_from_argv(
        std::env::args_os(),
    ));

    if argv_requests_top_level_version(std::env::args_os()) {
        print_version_with_notice();
        return Ok(());
    }

    // ── sync fast lane ──────────────────────────────────
    // If this is a bare `lpm install` (or `lpm i`) with no disqualifying
    // flags and the project is already up to date, exit immediately
    // without starting tokio, clap, tracing, or auth.
    //
    // package.json is read at most ONCE on the fast lane —
    // shared between the workspace-root check and the install-state
    // check. The install-state check also tries an mtime short-circuit
    // first, which skips both the lpm.lock read and the SHA-256 pass
    // when the manifest/lockfile mtimes are unchanged.
    if let Some(json_mode) = install_state::argv_qualifies_for_fast_lane()
        && let Ok(cwd) = std::env::current_dir()
    {
        // Start timing BEFORE any disk work, matching install.rs which
        // captures `start` at function entry before `check_install_state`.
        let start = std::time::Instant::now();

        let pkg_content_opt = std::fs::read_to_string(cwd.join("package.json")).ok();
        let is_workspace = pkg_content_opt
            .as_deref()
            .is_some_and(install_state::is_workspace_root_content)
            || install_state::has_pnpm_workspace_yaml(&cwd);

        if !is_workspace && let Some(pkg_content) = pkg_content_opt.as_deref() {
            let state = install_state::check_install_state_with_content(&cwd, pkg_content);
            if state.up_to_date {
                let elapsed_ms = start.elapsed().as_millis();
                if json_mode {
                    // Hand-formatted to match `serde_json::to_string_pretty`
                    // output for the `install.rs` up-to-date object —
                    // avoids constructing a `serde_json::Value` on the
                    // hot path. Shape pinned by the up-to-date fast-path
                    // branch in `install.rs` (`success + up_to_date +
                    // duration_ms + timing{resolve/fetch/link/total}`).
                    println!(
                        "{{\n  \"success\": true,\n  \"up_to_date\": true,\n  \
                         \"duration_ms\": {elapsed_ms},\n  \"timing\": {{\n    \
                         \"resolve_ms\": 0,\n    \"fetch_ms\": 0,\n    \
                         \"link_ms\": 0,\n    \"total_ms\": {elapsed_ms}\n  \
                         }}\n}}"
                    );
                } else {
                    output::success(&format!("up to date ({elapsed_ms}ms)"));
                }
                std::process::exit(0);
            }
        }
    }

    // ── Normal async path ───────────────────────────────────────────
    // `LPM_MAX_BLOCKING_THREADS=<N>` is an opt-in diagnostic hook for
    // A/B benching the tokio blocking-pool size without a rebuild —
    // same pattern used for `LPM_SKIP_SECURITY=1`.     // measured this lever (n=20 paired, 3 cells) and found capping has
    // **no measurable wall-clock effect** on `bench/fixture-large`:
    // the parked-worker `__psynch_cvwait` samples in the close-out
    // flamegraph are off the critical path. Default behavior preserves
    // tokio's unbounded blocking pool. See the close-out doc
    // for methodology and the negative result.
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.enable_all();
    if let Some(cap) = std::env::var("LPM_MAX_BLOCKING_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    {
        runtime_builder.max_blocking_threads(cap);
    }
    let runtime = runtime_builder
        .build()
        .expect("failed to create tokio runtime");

    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let cli = parse_cli_or_exit();

    // Color policy is already initialized at the top of `fn main()` via
    // the argv pre-scan. Re-run init here so any difference between the
    // pre-scan's flag detection and clap's parsed value (e.g., the user
    // wrote `--color always` and the pre-scan failed for an unrelated
    // reason) is resolved in clap's favor. `set_enabled` is idempotent.
    color_policy::init(Some(cli.color));

    // Version flag short-circuit. Replaces clap's auto `-V` handler so we
    // can both (a) honour `-v` as an alias and (b) append the cached
    // "update available" notice. Runs before tracing setup / subcommand
    // dispatch — there is nothing to log and nothing to do beyond
    // printing the version line.
    if cli.version_flag {
        print_version_with_notice();
        return Ok(());
    }

    // No subcommand and no version request → print help and exit 2 (clap's
    // standard "missing required argument" semantics). We can't lean on
    // clap's automatic `arg_required_else_help` because the global short
    // version flag still defaults to `false`; the user-typed `lpm` (no
    // args, no flags) needs explicit handling.
    let Some(command) = cli.command else {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let _ = cmd.print_help();
        std::process::exit(2);
    };

    // Set up tracing based on verbosity. Tracing is pinned to stderr so
    // stdout stays reserved for command output and `--json` remains a
    // single parseable document.
    let filter = if cli.verbose {
        "lpm=debug,reqwest=debug"
    } else {
        "lpm=warn"
    };
    // With `--features tracy`, layer a `TracyLayer` alongside the stderr
    // fmt layer so install-pipeline spans land in the Tracy GUI without
    // changing the stderr logging contract.
    {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;

        let env_filter =
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into());
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_target(false)
            .without_time();

        #[cfg(feature = "tracy")]
        let registry = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(tracing_tracy::TracyLayer::default());
        #[cfg(not(feature = "tracy"))]
        let registry = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer);

        registry.init();
    }

    // Startup gate for `LPM_PROVENANCE_ENFORCE`: an unknown value
    // (typo, stale spelling from an older release) must hard-fail
    // here rather than silently downgrading to the default `Deny`.
    // Otherwise an operator who set `LPM_PROVENANCE_ENFORCE=warm`
    // thinking it means `warn` would get the fail-closed posture
    // they did NOT ask for, with no signal that their intent
    // didn't take effect.
    let registry_url = cli
        .registry
        .as_deref()
        .unwrap_or(lpm_common::DEFAULT_REGISTRY_URL);

    if let Err(error) = provenance_fetch::EnforceMode::validate_from_env() {
        exit_with_lpm_error(&error, cli.json, registry_url);
    }

    // lazy auth. Build the SessionManager from purely local
    // state — no network calls. Refresh is deferred to the first
    // auth-required operation, handled inside `RegistryClient` request
    // methods (Step 4). The eager `try_silent_refresh` + 24h `whoami`
    // block that lived here pre-existing is gone.
    //
    // `cli.token` carries either an explicit `--token` value or the
    // `LPM_TOKEN` env (clap merges them). When the value matches
    // `LPM_TOKEN` exactly, treat it as env-sourced so SessionManager
    // can classify it correctly; otherwise it's an explicit flag value.
    let explicit_flag_token = cli
        .token
        .clone()
        .filter(|t| std::env::var("LPM_TOKEN").ok().as_deref() != Some(t.as_str()));
    let session_manager =
        lpm_auth::SessionManager::new(registry_url.to_string(), explicit_flag_token);
    let session_manager = auth_storage_notice::attach(session_manager, cli.json);
    let session = std::sync::Arc::new(session_manager);

    let mut client = lpm_registry::RegistryClient::new()
        .with_base_url(registry_url.to_string())
        .with_insecure(cli.insecure)
        .with_session(session.clone());

    // Step 3 transition bridge: until Step 4 wires posture-aware
    // dispatch through SessionManager, also seed the legacy
    // `with_token` path so existing request methods keep their bearer.
    // SessionManager is the source of truth — this branch goes away
    // once Step 4 lands.
    if let Some(bearer) = session.current_bearer_for_bridge() {
        client = client.with_token(bearer);
    }

    // run global recovery before any command that reads
    // or writes ~/.lpm/global/ state. Skipped for read-only commands
    // (`--help`, `--version`, plain project install) so path
    // construction stays side-effect-free for the common case. Idempotent
    // when no recovery is needed (empty WAL → fast no-op).
    if command_needs_global_state(&command)
        && let Ok(root) = lpm_common::LpmRoot::from_env()
    {
        // one-time warning when $LPM_HOME sits on
        // NFS/SMB/CIFS — advisory locks on those filesystems are
        // famously unreliable and the install transaction's atomicity
        // guarantees degrade. Suppressed by a marker file after the
        // first emission so users in CI/enterprise environments are
        // not nagged on every invocation.
        maybe_emit_network_fs_warning(&root);

        match lpm_global::recover(&root) {
            Ok(report) => {
                if !report.skipped_due_to_lock {
                    for tx in &report.reconciled {
                        match &tx.outcome {
                            lpm_global::ReconciliationOutcome::RolledForward => {
                                tracing::info!(
                                    "global recovery: rolled forward {} (tx {})",
                                    tx.package,
                                    tx.tx_id
                                );
                            }
                            lpm_global::ReconciliationOutcome::RolledBack { reason } => {
                                tracing::info!(
                                    "global recovery: rolled back {} (tx {}, reason: {})",
                                    tx.package,
                                    tx.tx_id,
                                    reason
                                );
                            }
                            lpm_global::ReconciliationOutcome::AlreadyCommitted => {
                                // Manifest was already committed but the
                                // WAL was missing the COMMIT record. We just
                                // emitted that marker, so nothing
                                // user-visible changed.
                                tracing::debug!(
                                    "global recovery: emitted missing COMMIT for already-committed {} (tx {})",
                                    tx.package,
                                    tx.tx_id
                                );
                            }
                            lpm_global::ReconciliationOutcome::NothingToDo => {
                                tracing::debug!(
                                    "global recovery: orphan tx {} cleaned up",
                                    tx.tx_id
                                );
                            }
                            lpm_global::ReconciliationOutcome::Deferred { reason } => {
                                // Surface deferred transactions to the user;
                                // they're typically transient (Windows AV
                                // holding a file), but pending cleanup should
                                // not be silent. Also emit a structured
                                // warning on stderr so `--json` keeps a
                                // single stdout document while automation can
                                // still detect dirty global state.
                                tracing::warn!(
                                    target: "lpm_cli::global_recovery",
                                    package = %tx.package,
                                    tx_id = %tx.tx_id,
                                    reason = %reason,
                                    "global recovery deferred — re-run lpm so the next sweep can retry the cleanup",
                                );
                                output::warn(&format!(
                                    "global recovery deferred tx for '{}': {}",
                                    lpm_common::sanitize_for_terminal(&tx.package),
                                    lpm_common::sanitize_for_terminal(reason)
                                ));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                // Recovery failure (most often: WAL written by newer
                // lpm) must NOT silently let the command proceed
                // against potentially stale state. Surface and abort.
                //
                // L44: in `--json` mode, route through the same
                // `{"success": false, "error", "error_code"}` envelope
                // that wraps dispatch errors below — otherwise the
                // recovery path emits a human diagnostic on stderr and
                // the JSON consumer sees an empty stdout
                // alongside a non-zero exit, breaking the
                // `--json contract` exactly when the user most needs to
                // parse the failure (corrupt / newer WAL, etc.).
                exit_with_lpm_error(&e, cli.json, registry_url);
            }
        }
    }

    // Capture whether the user invoked `lpm self-update` directly so the
    // post-command "update available" banner (read from disk, printed
    // unconditionally below) can be suppressed when the just-run command
    // tells the user to "run lpm self-update" — they did, and the cooldown
    // already explained why it didn't proceed. Suppressing here keeps the
    // suppression scoped to this invocation only; the next command still
    // sees the banner.
    let is_self_update_command = matches!(command, Commands::SelfUpdate { .. });

    // Wrap the entire dispatch in an async block so every
    // `?` inside a match arm body propagates to THIS block's
    // `Result<(), LpmError>` — and from there into `result`, where the
    // top-level `--json` envelope handler renders it.
    //
    // Do NOT remove this wrap without auditing every arm body for `?`
    // operators and explicit `return Err(...)` paths — both rely on
    // returning to *this* block, not to `async_main`'s outer result.
    // The redundant per-arm wraps from the v2 sweep (Install, Login,
    // Dlx, Use, Tunnel) were flattened alongside finding A — there is
    // no remaining defense-in-depth.
    let result: Result<(), lpm_common::LpmError> = async {
    match command {
        Commands::Info {
            package,
            package_version,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::info::run(&client, &cwd, &package, package_version.as_deref(), cli.json)
                .await
        }
        Commands::Search { query, limit } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::search::run(&client, &cwd, &query, limit, cli.json).await
        }
        Commands::Quality { package } => commands::quality::run(&client, &package, cli.json).await,
        Commands::Whoami => commands::whoami::run(&client, cli.json).await,
        Commands::Health => commands::health::run(&client, registry_url, cli.json).await,
        Commands::Download {
            package,
            package_version,
            output,
            allow_unverified,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::download::run(
                &client,
                &cwd,
                &package,
                package_version.as_deref(),
                output.as_deref(),
                allow_unverified,
                cli.json,
            )
            .await
        }
        Commands::Fetch { platform } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::fetch::run(&client, &cwd, platform.as_deref(), cli.json).await
        }
        Commands::Tidy { fix } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::tidy::run(&client, &cwd, fix, cli.json).await
        }
        Commands::Resolve { packages } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::resolve::run(&client, &cwd, &packages, cli.json).await
        }
        Commands::Install {
            packages,
            save_dev,
            omit,
            prod,
            offline,
            frozen_lockfile,
            no_frozen_lockfile,
            force,
            allow_new,
            strict_integrity,
            strict_peer_dependencies,
            no_strict_peer_dependencies,
            min_release_age,
            ignore_provenance_drift,
            ignore_provenance_drift_all,
            unverified_provenance,
            unverified_provenance_all,
            linker,
            no_skills,
            no_editor_setup,
            no_security_summary,
            auto_build,
            no_engine_strict,
            audit_after_install,
            no_audit_after_install,
            filter,
            filter_prod,
            changed_files_ignore_pattern,
            test_pattern,
            workspace_root,
            fail_if_no_match,
            yes,
            exact,
            tilde,
            save_prefix,
            catalog,
            global,
            replace_bin,
            alias,
            policy,
            yolo,
            triage_alias,
            advisor,
            strict_sandbox,
            paranoid,
            no_sandbox,
        } => {
            let cli_strict_peer_dependencies =
                match (strict_peer_dependencies, no_strict_peer_dependencies) {
                    (true, false) => Some(true),
                    (false, true) => Some(false),
                    _ => None,
                };
            let omit_policy = install_omit_policy_from_cli(&omit, prod);
            if save_dev && omit_policy.dev {
                return Err(lpm_common::LpmError::Script(
                    "`-D` / `--save-dev` cannot be combined with `--prod`, \
                     `--production`, or `--omit dev`; a dev-only add would be \
                     omitted from node_modules before it can be finalized."
                        .into(),
                ));
            }

            // Route `lpm install --global` / `-g` to the persistent
            // IsolatedInstall pipeline. Supports fresh install, upgrade,
            // and collision resolution. The pipeline takes care of the
            // three-phase tx (Intent + slow install +
            // commit) and the recovery hook above already handled
            // any prior crashed install for this command's package.
            if global {
                if packages.is_empty() {
                    return Err(lpm_common::LpmError::Script(
                        "`lpm install --global` requires a package spec (e.g. \
                         `lpm install -g eslint` or `lpm install -g typescript@^5`)"
                            .into(),
                    ));
                }
                if packages.len() > 1 {
                    return Err(lpm_common::LpmError::Script(format!(
                        "`lpm install --global` accepts a single package per invocation \
                         (got {}). Run it once per package, or use \
                         `lpm global update` for multi-package upgrades.",
                        packages.len()
                    )));
                }
                // Reject any project-install-only flag that's
                // meaningless for global. Keeps the surface honest.
                validate_global_install_project_scoped_flags(
                    save_dev,
                    &filter,
                    &filter_prod,
                    &changed_files_ignore_pattern,
                    &test_pattern,
                    workspace_root,
                    fail_if_no_match,
                    yes,
                    catalog.is_some(),
                    omit_policy != commands::install::InstallOmitPolicy::default(),
                )?;
                if frozen_lockfile || no_frozen_lockfile {
                    return Err(lpm_common::LpmError::Script(
                        "`--frozen-lockfile` and `--no-frozen-lockfile` only apply to project installs."
                            .into(),
                    ));
                }
                // parse collision-resolution flags. Syntactic
                // validation only (no lookup against marker commands —
                // that happens at commit time with authoritative data).
                let resolution = commands::install_global::CollisionResolution::parse_from_flags(
                    &replace_bin,
                    &alias,
                )
                .map_err(lpm_common::LpmError::Script)?;
                let _ = (
                    offline,
                    force,
                    linker,
                    no_skills,
                    no_editor_setup,
                    no_security_summary,
                    exact,
                    tilde,
                    save_prefix,
                    catalog,
                ); // not wired for global install; ignored for now.

                let mut overrides = build_install_global_overrides(
                    allow_new,
                    auto_build,
                    policy.as_deref(),
                    yolo,
                    triage_alias,
                    min_release_age.as_deref(),
                    ignore_provenance_drift,
                    ignore_provenance_drift_all,
                    unverified_provenance,
                    unverified_provenance_all,
                )?;
                overrides.strict_peer_dependencies_override = cli_strict_peer_dependencies;

                return commands::install_global::run(
                    &client,
                    &packages[0],
                    resolution,
                    cli.json,
                    overrides,
                )
                .await;
            }

            // Reject collision-resolution flags on the non-global
            // install path. These flags only make sense for `-g`
            // installs because only the global command-shim system can
            // collide. Accepting them silently would drop the user's
            // resolution intent.
            if !replace_bin.is_empty() || !alias.is_empty() {
                return Err(lpm_common::LpmError::Script(
                    "`--replace-bin` and `--alias` are collision-resolution flags for global \
                     installs (`-g`) only. Add `-g` to install globally, or drop the flags for \
                     a project install."
                        .into(),
                ));
            }

            // Token expiry warnings (Feature 42)
            if !cli.json {
                for warning in auth::check_token_expiry_warnings() {
                    output::warn(&warning);
                }
            }
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            // Resolve the project root before any downstream work
            // touches `package.json`. Matches the directory-discovery
            // contract of npm / pnpm / yarn / bun: if the cwd has no
            // manifest, walk up to the nearest ancestor that does and
            // treat THAT directory as the project root for this
            // invocation. When nothing is found anywhere and the user
            // is adding packages (`lpm i <pkg>` rather than bare
            // `lpm install`), create a minimal manifest in cwd so the
            // add path doesn't crash on the missing file. Bare install
            // intentionally keeps the missing-manifest error — it has
            // nothing to install against.
            let cwd = resolve_install_project_dir(&cwd, !packages.is_empty(), cli.json)?;
            let frozen_lockfile_mode = if frozen_lockfile {
                commands::install::FrozenLockfileMode::Always
            } else if no_frozen_lockfile {
                commands::install::FrozenLockfileMode::Never
            } else {
                commands::install::FrozenLockfileMode::Auto
            };
            if !packages.is_empty()
                && frozen_lockfile_mode != commands::install::FrozenLockfileMode::Never
                && (frozen_lockfile
                    || (cwd.join(lpm_lockfile::LOCKFILE_NAME).exists()
                        && commands::install::install_running_in_ci()))
            {
                return Err(lpm_common::LpmError::Script(
                    "frozen installs do not accept package specs. Run `lpm install` locally to update package.json and lpm.lock, or pass --no-frozen-lockfile for a mutable install."
                        .into(),
                ));
            }
            let cfg = commands::config::GlobalConfig::load();
            let eff_allow_new = allow_new || cfg.get_bool("allowNew").unwrap_or(false);

            // Resolve the audit-after-install precedence chain ONCE
            // before threading the resolved boolean into every install
            // entry point. Order (highest first):
            //   1. `--audit-after-install` / `--no-audit-after-install`
            //      (clap already enforced mutual exclusion)
            //   2. `LPM_AUDIT_AFTER_INSTALL` env
            //      (`1`/`true`/`yes`/`on` → on, `0`/`false`/`no`/`off`
            //      → off, anything else falls through)
            //   3. `~/.lpm/config.toml > audit-after-install`
            //   4. Default off.
            let eff_audit_after_install: bool = if audit_after_install {
                true
            } else if no_audit_after_install {
                false
            } else if let Ok(env_val) = std::env::var("LPM_AUDIT_AFTER_INSTALL") {
                match env_val.trim().to_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => true,
                    "0" | "false" | "no" | "off" => false,
                    _ => cfg.get_bool("audit-after-install").unwrap_or(false),
                }
            } else {
                cfg.get_bool("audit-after-install").unwrap_or(false)
            };

            // engines.lpm / engines.node enforcement (workspace root).
            // Runs before any install work so a constraint violation
            // exits cheaply with a structured error code. The gate
            // discovers the workspace root internally so a member-dir
            // invocation honors the root's `lpm.engineStrict` opt-out.
            engine_check::enforce(&cwd, no_engine_strict, cli.json)?;

            //: parse `--min-release-age=<dur>` once, at the
            // clap layer, so invalid input surfaces before any install
            // work starts. `None` means the flag was absent and the
            // resolver walks the full precedence chain inside
            // `run_with_options`.
            let min_release_age_override: Option<u64> = match min_release_age.as_deref() {
                Some(s) => Some(release_age_config::parse_duration(s)?),
                None => None,
            };

            // canonicalize
            // `--ignore-provenance-drift <pkg>` + `--ignore-provenance-drift-all`
            // into a single policy enum. Per Q2 of the kickoff,
            // `-all` supersedes the per-package list — no clap
            // mutex, just collapse internally.
            let drift_ignore_policy = provenance_fetch::DriftIgnorePolicy::from_cli(
                ignore_provenance_drift,
                ignore_provenance_drift_all,
            );

            // Canonicalize the per-package crypto opt-out flags +
            // env / config-resolved `EnforceMode` into a single
            // `VerifyPolicy`. The two axes (enforce, skip) compose
            // orthogonally — see `SkipPolicy` doc. Resolution walks
            // the full precedence chain:
            //   env LPM_PROVENANCE_ENFORCE
            //     → config [sigstore].verify in ~/.lpm/config.toml
            //       → default Deny.
            let (verify_policy, verify_source) = provenance_fetch::VerifyPolicy::resolve_from_chain(
                unverified_provenance,
                unverified_provenance_all,
                std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref(),
                || cfg.get_sigstore_verify(),
            );
            // Loud-when-degraded: emit one heads-up per install run
            // when the resolved mode is not `Deny`. The hint names
            // the source (env / config / default) and the re-enable
            // command so an operator who flipped the knob once and
            // forgot doesn't fly blind. Tracing always fires so
            // structured-log consumers (JSON-mode pipelines, log
            // forwarders) capture the posture-degrade independent of
            // stderr; stderr `output::warn` is suppressed under
            // `--json` because the per-package envelope is the
            // canonical signal there.
            if !matches!(verify_policy.enforce, provenance_fetch::EnforceMode::Deny) {
                let mode_label = match verify_policy.enforce {
                    provenance_fetch::EnforceMode::Warn => "warn",
                    provenance_fetch::EnforceMode::Off => "off",
                    provenance_fetch::EnforceMode::Deny => unreachable!("guarded above"),
                };
                tracing::warn!(
                    target = "lpm::provenance",
                    enforce_mode = mode_label,
                    source = ?verify_source,
                    "sigstore verification posture is degraded for this install run",
                );
                if !cli.json {
                    output::warn(&format!(
                        "Sigstore provenance verification posture: {} (source: {}). \
                         Provenance attestations will {} be cryptographically verified \
                         for this install. To re-enable fail-closed: {}.",
                        mode_label,
                        match verify_source {
                            provenance_fetch::EnforceModeSource::Env =>
                                "LPM_PROVENANCE_ENFORCE env",
                            provenance_fetch::EnforceModeSource::Config =>
                                "[sigstore] verify in ~/.lpm/config.toml",
                            provenance_fetch::EnforceModeSource::Default => "default",
                        },
                        if matches!(verify_policy.enforce, provenance_fetch::EnforceMode::Off) {
                            "NOT"
                        } else {
                            "be checked but rejections will only log, not block —"
                        },
                        verify_source.re_enable_hint(),
                    ));
                }
            }

            // Resolve the effective script-policy through the precedence
            // chain (CLI > package.json > global > default). Clap
            // enforces mutual exclusion between the three flags, so
            // `collapse_policy_flags` only needs to validate the
            // `--policy` string payload.
            //
            // Loading the config here (rather than inside
            // `resolve_script_policy`) lets us surface a typo in
            // `package.json > lpm > scriptPolicy` to the user. Warning
            // emission is deferred until after resolve so the user sees
            // the policy that actually took effect.
            let script_policy_cfg =
                script_policy_config::ScriptPolicyConfig::from_package_json(&cwd);
            // preserve the collapsed CLI override
            // separately so we can forward it to install entry points
            // that re-resolve against a workspace member's config.
            // `effective_script_policy` below is the CWD-level view
            // used for logging; each install target resolves its own.
            let cli_script_policy_override =
                script_policy_config::collapse_policy_flags(policy.as_deref(), yolo, triage_alias)
                    .map_err(lpm_common::LpmError::Script)?;
            let effective_script_policy =
                script_policy_config::resolve_script_policy_with_security(
                    &cwd,
                    cli_script_policy_override,
                    &script_policy_cfg,
                    cli.json,
                )?;
            tracing::debug!(
                "lpm install: effective script-policy = {}",
                effective_script_policy.as_str()
            );
            if let Some(invalid) = &script_policy_cfg.policy_parse_error
                && !cli.json
            {
                output::warn(&format!(
                    "package.json > lpm > scriptPolicy: invalid value '{invalid}' \
                     (expected one of: deny, allow, triage); this key was \
                     ignored — effective policy: {}",
                    effective_script_policy.as_str(),
                ));
            }

            // build the SaveFlags struct from the per-command CLI
            // overrides. clap already enforces mutual exclusion between
            // `--exact`, `--tilde`, and `--save-prefix`, so at most one of
            // these is set. `--save-prefix` strings are validated here so
            // bad values fail before we touch the install pipeline.
            let parsed_save_prefix = match save_prefix.as_deref() {
                Some(s) => Some(save_spec::SavePrefix::parse(s)?),
                None => None,
            };
            let save_flags = save_spec::SaveFlags {
                exact,
                tilde,
                save_prefix: parsed_save_prefix,
            };

            if packages.is_empty() {
                // --filter / -w / --fail-if-no-match only
                // apply when adding packages. Bare `lpm install` is the
                // refresh-from-package.json operation and ignores them
                // (or hard-errors if the user mistakenly passed them).
                if catalog.is_some() {
                    return Err(lpm_common::LpmError::Script(
                        "`--catalog` only applies when adding packages. Pass package specs \
                         (e.g., `lpm install --catalog react`) or run `lpm install` alone \
                         to refresh from package.json."
                            .into(),
                    ));
                }
                if !filter.is_empty()
                    || !filter_prod.is_empty()
                    || !changed_files_ignore_pattern.is_empty()
                    || !test_pattern.is_empty()
                    || workspace_root
                    || fail_if_no_match
                {
                    Err(lpm_common::LpmError::Script(
                        "`--filter`, `--filter-prod`, `--changed-files-ignore-pattern`, `--test-pattern`, `-w`, and `--fail-if-no-match` only apply when adding packages. \
                         Pass package specs (e.g., `lpm install react --filter web`) or run `lpm install` \
                         alone to refresh from package.json."
                            .into(),
                    ))
                } else {
                    // Bare install path.
                    let eff_no_skills = no_skills || cfg.get_bool("noSkills").unwrap_or(false);
                    let eff_no_editor =
                        no_editor_setup || cfg.get_bool("noEditorSetup").unwrap_or(false);
                    let eff_no_sec =
                        no_security_summary || cfg.get_bool("noSecuritySummary").unwrap_or(false);
                    let eff_auto_build = auto_build || cfg.get_bool("autoBuild").unwrap_or(false);
                    // Top-level dispatch passes ONLY the CLI flag through;
                    // `~/.lpm/config.toml > linker`, `LPM_LINKER`, and
                    // `package.json > lpm > linker` are resolved inside the
                    // install pipeline so every internal caller (add /
                    // upgrade / dev / migrate / deploy / dlx / -g / global
                    // update / doctor) gets the same precedence chain
                    // without each call site re-implementing it.
                    let cli_linker = linker.map(LinkerCli::into_linker_mode);

                    let root_lifecycle = commands::root_lifecycle::RootProjectLifecycle::load(&cwd)?;
                    root_lifecycle.run_dev_preinstall(&cwd, cli.json)?;

                    commands::install::run_with_options(
                        &client,
                        &cwd,
                        cli.json,
                        offline,
                        frozen_lockfile_mode,
                        force,
                        eff_allow_new,
                        strict_integrity,
                        cli_strict_peer_dependencies,
                        cli_linker,
                        eff_no_skills,
                        eff_no_editor,
                        eff_no_sec,
                        eff_auto_build,
                        None, // target_set: bare-install path is single-target
                        None, // direct_versions_out: bare install does not finalize a manifest
                        None, // requested_add_count: bare install reports the full graph
                        cli_script_policy_override,
                        advisor.clone(),
                        min_release_age_override,
                        drift_ignore_policy,
                        verify_policy,
                        omit_policy,
                        // collapse `--strict-sandbox`
                        // and its `--paranoid` alias into a single bool
                        // before the resolver (the chain inside
                        // `rebuild::run` already accepts a single
                        // `strict_sandbox` boolean).
                        strict_sandbox || paranoid,
                        no_sandbox,
                        cli.verbose,
                        eff_audit_after_install,
                    )
                    .await?;

                    commands::root_lifecycle::RootProjectLifecycle::load(&cwd)?
                        .run_after_successful_install(&cwd, cli.json)
                }
            } else if !filter.is_empty() || !filter_prod.is_empty() || workspace_root {
                // explicit filter or -w flag → workspace-aware path.
                commands::install::run_install_filtered_add(
                    &client,
                    &cwd,
                    &packages,
                    save_dev,
                    &filter,
                    &filter_prod,
                    &changed_files_ignore_pattern,
                    &test_pattern,
                    workspace_root,
                    fail_if_no_match,
                    yes,
                    cli.json,
                    eff_allow_new,
                    force,
                    save_flags,
                    catalog.as_deref(),
                    cli_script_policy_override,
                    advisor.clone(),
                    min_release_age_override,
                    drift_ignore_policy,
                    verify_policy,
                    cli_strict_peer_dependencies,
                    omit_policy,
                    strict_sandbox || paranoid,
                    no_sandbox,
                    cli.verbose,
                    eff_audit_after_install,
                )
                .await
            } else {
                // No explicit flags. The new filtered path also handles the
                // "inside a workspace member directory" case via target
                // resolution — so we ALWAYS prefer it for workspace mode.
                // For pure standalone projects with NO workspace, the
                // legacy `run_add_packages` is still preferred because it
                // handles per-package Swift (SE-0292) routing, which                 // intentionally defers from the workspace path.
                let workspace = lpm_workspace::discover_workspace(&cwd).ok().flatten();
                if workspace.is_some() {
                    commands::install::run_install_filtered_add(
                        &client,
                        &cwd,
                        &packages,
                        save_dev,
                        &filter,
                        &filter_prod,
                        &changed_files_ignore_pattern,
                        &test_pattern,
                        workspace_root,
                        fail_if_no_match,
                        yes,
                        cli.json,
                        eff_allow_new,
                        force,
                        save_flags,
                        catalog.as_deref(),
                        cli_script_policy_override,
                        advisor.clone(),
                        min_release_age_override,
                        drift_ignore_policy,
                        verify_policy,
                        cli_strict_peer_dependencies,
                        omit_policy,
                        strict_sandbox || paranoid,
                        no_sandbox,
                        cli.verbose,
                        eff_audit_after_install,
                    )
                    .await
                } else {
                    commands::install::run_add_packages(
                        &client,
                        &cwd,
                        &packages,
                        save_dev,
                        cli.json,
                        eff_allow_new,
                        force,
                        save_flags,
                        catalog.as_deref(),
                        cli_script_policy_override,
                        advisor.clone(),
                        min_release_age_override,
                        drift_ignore_policy,
                        verify_policy,
                        cli_strict_peer_dependencies,
                        omit_policy,
                        strict_sandbox || paranoid,
                        no_sandbox,
                        cli.verbose,
                        eff_audit_after_install,
                    )
                    .await
                }
            }
        }
        Commands::Uninstall {
            packages,
            filter,
            filter_prod,
            changed_files_ignore_pattern,
            test_pattern,
            workspace_root,
            fail_if_no_match,
            yes,
            global,
        } => {
            // `lpm uninstall -g <pkg>` routes to the
            // global uninstall pipeline. Project flags are mutually
            // exclusive with -g — no `--filter` / `-w` /
            // `--fail-if-no-match` for global ops since there's no
            // workspace dimension. Equivalent to
            // `lpm global remove <pkg>` (both paths share one impl).
            if global {
                if packages.is_empty() {
                    Err(lpm_common::LpmError::Script(
                        "`lpm uninstall --global` requires a package spec (e.g. \
                         `lpm uninstall -g eslint`)"
                            .into(),
                    ))
                } else if packages.len() > 1 {
                    Err(lpm_common::LpmError::Script(format!(
                        "`lpm uninstall --global` accepts a single package per invocation \
                         (got {}). Run it once per package.",
                        packages.len()
                    )))
                } else if let Err(error) = validate_global_uninstall_project_scoped_flags(
                    &filter,
                    &filter_prod,
                    &changed_files_ignore_pattern,
                    &test_pattern,
                    workspace_root,
                    fail_if_no_match,
                    yes,
                ) {
                    Err(error)
                } else {
                    commands::uninstall_global::run(&packages[0], cli.json).await
                }
            } else {
                let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
                commands::uninstall::run(
                    &client,
                    &cwd,
                    &packages,
                    &filter,
                    &filter_prod,
                    &changed_files_ignore_pattern,
                    &test_pattern,
                    workspace_root,
                    fail_if_no_match,
                    yes,
                    cli.json,
                )
                .await
            }
        }
        Commands::Add {
            package,
            path,
            yes,
            force,
            dry_run,
            no_install_deps,
            no_skills,
            no_editor_setup,
            pm,
            alias,
            target,
            no_engine_strict,
        } => {
            // Token expiry warnings (Feature 42)
            if !cli.json {
                for warning in auth::check_token_expiry_warnings() {
                    output::warn(&warning);
                }
            }
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            // engines.* preflight: run BEFORE add mutates package.json
            // so a constraint violation can't leave the project
            // half-modified. Skip in --dry-run since nothing is
            // written. Tolerates the no-`package.json` directory by
            // returning Ok early — that's the supported plain source
            // copy flow.
            if !dry_run {
                engine_check::enforce(&cwd, no_engine_strict, cli.json)?;
            }
            commands::add::run(
                &client,
                &cwd,
                &package,
                path.as_deref(),
                yes,
                cli.json,
                force,
                dry_run,
                no_install_deps,
                no_skills,
                no_editor_setup,
                &pm,
                alias.as_deref(),
                target.as_deref(),
            )
            .await
        }
        Commands::Publish {
            dry_run,
            check,
            yes,
            provenance,
            min_score,
            allow_secrets,
            npm,
            lpm,
            github,
            gitlab,
            publish_registry,
        } => {
            // Token expiry warnings (Feature 42)
            if !cli.json {
                for warning in auth::check_token_expiry_warnings() {
                    output::warn(&warning);
                }
            }
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;

            // OIDC auto-exchange happens inside publish::run after package.json
            // is parsed — the origin requires `package` for `scope=publish`.
            commands::publish::run(
                &client,
                &cwd,
                dry_run,
                check,
                yes,
                cli.json,
                min_score,
                allow_secrets,
                npm,
                lpm,
                github,
                gitlab,
                publish_registry.as_deref(),
                provenance,
            )
            .await
        }
        Commands::Stage { command } => {
            if argv_has_global_registry_flag(std::env::args_os()) {
                return Err(lpm_common::LpmError::Registry(
                    "`lpm stage` uses npm registries; use --npm-registry instead of global --registry.".into(),
                ));
            }
            if !cli.json {
                for warning in auth::check_token_expiry_warnings() {
                    output::warn(&warning);
                }
            }
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            match command {
                StageCommands::Publish {
                    tag,
                    access,
                    dry_run,
                    provenance,
                    min_score,
                    allow_secrets,
                    yes,
                    npm_registry,
                } => {
                    commands::stage::publish_current_project(
                        &cwd,
                        commands::stage::StagePublishOptions {
                            tag: tag.as_deref(),
                            access: access.as_deref(),
                            dry_run,
                            provenance,
                            min_score,
                            allow_secrets,
                            yes,
                            npm_registry: npm_registry.as_deref(),
                            json_output: cli.json,
                        },
                    )
                    .await
                }
                StageCommands::List {
                    package,
                    npm_registry,
                } => {
                    commands::stage::list(
                        &cwd,
                        package.as_deref(),
                        npm_registry.as_deref(),
                        cli.json,
                    )
                    .await
                }
                StageCommands::View {
                    stage_id,
                    npm_registry,
                } => {
                    commands::stage::view(
                        &cwd,
                        &stage_id,
                        npm_registry.as_deref(),
                        cli.json,
                    )
                    .await
                }
                StageCommands::Approve {
                    stage_id,
                    otp,
                    npm_registry,
                } => {
                    commands::stage::approve(
                        &cwd,
                        &stage_id,
                        otp.as_deref(),
                        npm_registry.as_deref(),
                        cli.json,
                        false,
                    )
                    .await
                }
                StageCommands::Reject {
                    stage_id,
                    otp,
                    npm_registry,
                } => {
                    commands::stage::reject(
                        &cwd,
                        &stage_id,
                        otp.as_deref(),
                        npm_registry.as_deref(),
                        cli.json,
                        false,
                    )
                    .await
                }
                StageCommands::Download {
                    stage_id,
                    npm_registry,
                } => {
                    commands::stage::download(
                        &cwd,
                        &stage_id,
                        npm_registry.as_deref(),
                        cli.json,
                    )
                    .await
                }
            }
        }
        Commands::Login {
            npm,
            github,
            gitlab,
            login_registry,
            token,
        } => {
            if npm {
                commands::third_party_login::run_npm(token, cli.json).await
            } else if github {
                commands::third_party_login::run_github(token, cli.json)
            } else if gitlab {
                commands::third_party_login::run_gitlab(token, cli.json)
            } else if let Some(url) = login_registry.as_deref() {
                commands::third_party_login::run_custom(url, token, cli.json)
            } else {
                // Standard LPM login (browser flow)
                let registry = cli
                    .registry
                    .as_deref()
                    .unwrap_or(lpm_common::DEFAULT_REGISTRY_URL);
                commands::login::run(registry, cli.json).await
            }
        }
        Commands::Logout {
            revoke,
            npm,
            github,
            gitlab,
            all,
            logout_registry,
        } => {
            let has_specific = npm || github || gitlab || logout_registry.is_some();

            if all || (!has_specific) {
                // Default: LPM only. --all: everything.
                let registry = cli
                    .registry
                    .as_deref()
                    .unwrap_or(lpm_common::DEFAULT_REGISTRY_URL);
                commands::logout::run(&client, registry, revoke, cli.json).await?;
            }

            if all || npm {
                match auth::clear_npm_token() {
                    Ok(()) if !cli.json => output::success("Logged out from npmjs.org"),
                    Err(_) if !cli.json => output::info("Not logged in to npmjs.org"),
                    _ => {}
                }
                auth::clear_token_expiry("npmjs.org");
            }
            if all || github {
                match auth::clear_github_token() {
                    Ok(()) if !cli.json => output::success(
                        "Logged out from GitHub Packages fallback token (GitHub CLI auth is managed by gh)",
                    ),
                    Err(_) if !cli.json => output::info("Not logged in to GitHub Packages"),
                    _ => {}
                }
                auth::clear_token_expiry("github.com");
            }
            if all || gitlab {
                match auth::clear_gitlab_token() {
                    Ok(()) if !cli.json => output::success(
                        "Logged out from GitLab Packages fallback token (GitLab CLI auth is managed by glab)",
                    ),
                    Err(_) if !cli.json => output::info("Not logged in to GitLab Packages"),
                    _ => {}
                }
                auth::clear_token_expiry("gitlab.com");
            }

            // Custom registry logout (explicit URL or --all)
            if let Some(url) = &logout_registry {
                match auth::clear_custom_registry_token(url) {
                    Ok(()) if !cli.json => output::success(&format!("Logged out from {url}")),
                    Err(_) if !cli.json => output::info(&format!("Not logged in to {url}")),
                    _ => {}
                }
            }
            if all {
                for (url, result) in auth::clear_all_custom_registries() {
                    match result {
                        Ok(()) if !cli.json => output::success(&format!("Logged out from {url}")),
                        _ => {}
                    }
                }
            }

            Ok(())
        }
        Commands::Setup { action } => match action {
            SetupAction::Ci {
                target,
                env,
                registry: setup_registry,
                oidc,
                proxy,
                scoped: _,
            } => {
                let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
                let target = target.as_deref().ok_or_else(|| {
                    lpm_common::LpmError::Script(
                        "usage: lpm setup ci <target>. Available: npmrc, github-actions, gitlab"
                            .into(),
                    )
                })?;
                match target {
                    "npmrc" => {
                        let effective_registry = setup_registry.as_deref().unwrap_or(registry_url);
                        let cfg = commands::config::GlobalConfig::load();
                        let eff_proxy = proxy || cfg.get_bool("proxy").unwrap_or(false);
                        commands::setup::run(effective_registry, &cwd, cli.json, oidc, eff_proxy)
                            .await
                    }
                    "github-actions" | "github" | "gha" => {
                        commands::setup::run_ci_platform(target, &cwd, &env)?;
                        Ok(())
                    }
                    "gitlab" | "gitlab-ci" => {
                        commands::setup::run_ci_platform(target, &cwd, &env)?;
                        Ok(())
                    }
                    other => Err(lpm_common::LpmError::Script(format!(
                        "unknown CI setup target: '{other}'. Available: npmrc, github-actions, gitlab"
                    ))),
                }
            }
            SetupAction::Local {
                days,
                proxy,
                scoped: _,
            } => {
                let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
                let cfg = commands::config::GlobalConfig::load();
                let eff_proxy = proxy || cfg.get_bool("proxy").unwrap_or(false);
                commands::npmrc::run(&client, &cwd, registry_url, days, eff_proxy, cli.json)
                    .await
            }
        },
        Commands::TokenRotate => commands::token::run_rotate(&client, registry_url, cli.json).await,
        Commands::Outdated { registry_only } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::outdated::run(
                &client,
                &cwd,
                cli.json,
                matches!(registry_only, OutdatedRegistryScope::All),
            )
            .await
        }
        Commands::Upgrade {
            major,
            dry_run,
            interactive,
            yes,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::upgrade::run(&client, &cwd, major, dry_run, interactive, yes, cli.json).await
        }
        Commands::Init { yes } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::init::run(&client, &cwd, yes, cli.json).await
        }
        Commands::Config {
            action,
            key,
            value,
            set,
        } => {
            commands::config::run(
                &action,
                key.as_deref(),
                value.as_deref(),
                set.as_deref(),
                cli.json,
            )
            .await
        }
        Commands::Security { action } => commands::security::run(&action, cli.json).await,
        Commands::Cache {
            action,
            subcategory,
            apply,
            max_age,
            project,
        } => {
            commands::cache::run(
                &action,
                subcategory.as_deref(),
                cli.json,
                commands::cache::PruneFlags {
                    apply,
                    max_age: max_age.as_deref(),
                    project: project.as_deref(),
                },
            )
            .await
        }
        Commands::Store { action, deep, fix } => {
            commands::store::run(&action, deep, fix, cli.json).await
        }
        Commands::Catalog { action } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::catalog::run(&cwd, action, cli.json)
        }
        Commands::Global { action } => commands::global::run(&client, action, cli.json).await,
        Commands::Trust { action } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::trust::run(&action, &cwd, cli.json).await
        }
        Commands::Pool => commands::pool::run(&client, cli.json).await,
        Commands::Skills { action, package } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::skills::run(&client, &action, package.as_deref(), &cwd, cli.json).await
        }
        Commands::Remove { package } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::remove::run(&cwd, &package, cli.json).await
        }
        Commands::Audit {
            action,
            level,
            fail_on,
            secrets,
            fix,
            dry_run,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            if let Some(commands::audit::AuditCmd::Fix { dry_run }) = action.as_ref() {
                if fix {
                    return Err(lpm_common::LpmError::Script(
                        "use either `lpm audit fix` or `lpm audit --fix`, not both".into(),
                    ));
                }
                if secrets {
                    return Err(lpm_common::LpmError::Script(
                        "`lpm audit fix` cannot be combined with `--secrets`".into(),
                    ));
                }
                commands::audit::run_fix(&client, &cwd, cli.json, *dry_run).await
            } else if let Some(commands::audit::AuditCmd::Signatures) = action.as_ref() {
                if fix {
                    return Err(lpm_common::LpmError::Script(
                        "`lpm audit signatures` cannot be combined with `--fix`".into(),
                    ));
                }
                if secrets {
                    return Err(lpm_common::LpmError::Script(
                        "`lpm audit signatures` cannot be combined with `--secrets`".into(),
                    ));
                }
                commands::audit::run_signatures(&client, &cwd, cli.json).await
            } else if fix {
                commands::audit::run_fix(&client, &cwd, cli.json, dry_run).await
            } else if secrets {
                commands::audit::run_secrets(&cwd, cli.json, fail_on.as_deref()).await
            } else {
                commands::audit::run(
                    &client,
                    &cwd,
                    cli.json,
                    level.as_deref(),
                    fail_on.as_deref(),
                )
                .await
            }
        }
        Commands::Query {
            selector,
            count,
            query_verbose,
            assert_none,
            format,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::query::run(
                &client,
                &cwd,
                selector.as_deref(),
                count,
                cli.json,
                query_verbose || cli.verbose,
                assert_none,
                &format,
            )
            .await
        }
        Commands::Rebuild {
            packages,
            all,
            dry_run,
            force,
            timeout,
            deny_all,
            policy,
            yolo,
            triage_alias,
            no_sandbox,
            strict_sandbox,
            paranoid,
            sandbox_log,
            no_engine_strict,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            // engines.* enforcement: rebuild executes lifecycle scripts
            // under the project's engine constraints, so the gate runs
            // before any script is selected. Skip in --dry-run since no
            // scripts execute.
            if !dry_run {
                engine_check::enforce(&cwd, no_engine_strict, cli.json)?;
            }
            //: resolve the effective script-policy through
            // the precedence chain. Clap already enforced mutual-
            // exclusion between `--policy`, `--yolo`, `--triage`, so
            // at most one of the three is set per invocation.
            // `lpm rebuild` itself does not branch on the resolved value
            // yet, but loading the config here still surfaces typos in
            // `package.json > lpm > scriptPolicy` instead of silently
            // falling through. Warning emission is deferred until after
            // resolve so the user sees the policy that actually took
            // effect.
            let script_policy_cfg =
                script_policy_config::ScriptPolicyConfig::from_package_json(&cwd);
            let cli_override =
                script_policy_config::collapse_policy_flags(policy.as_deref(), yolo, triage_alias)
                    .map_err(lpm_common::LpmError::Script)?;
            let effective = script_policy_config::resolve_script_policy_with_security(
                &cwd,
                cli_override,
                &script_policy_cfg,
                cli.json,
            )?;
            tracing::debug!(
                "lpm rebuild: effective script-policy = {}",
                effective.as_str()
            );
            if let Some(invalid) = &script_policy_cfg.policy_parse_error
                && !cli.json
            {
                output::warn(&format!(
                    "package.json > lpm > scriptPolicy: invalid value '{invalid}' \
                     (expected one of: deny, allow, triage); this key was \
                     ignored — effective policy: {}",
                    effective.as_str(),
                ));
            }
            commands::rebuild::run(
                &cwd,
                &packages,
                all,
                dry_run,
                force,
                timeout,
                cli.json,
                deny_all,
                no_sandbox,
                // `--paranoid` is a clap alias for
                // `--strict-sandbox`. Either form sets the strict flag
                // before flowing into `resolve_sandbox_mode_from_chain`.
                strict_sandbox || paranoid,
                sandbox_log,
                // pass the resolved effective
                // policy through. Previously `effective` was computed
                // only for the typo-warning + debug log above and
                // never reached `rebuild::run`; closes that gap
                // so can consult it for green-tier promotion
                // without another signature change.
                effective,
                // standalone `lpm rebuild` has no
                // install-time advisor context — only the trust
                // manifest authorises execution here. The ephemeral
                // advisor approvals live exclusively on the install
                // path.
                None,
            )
            .await
        }
        Commands::Doctor {
            all,
            fix,
            yes,
            action,
        } => match action {
            Some(DoctorAction::List { code, category }) => {
                commands::doctor::list(cli.json, code.as_deref(), category.as_deref())
            }
            None => {
                let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
                commands::doctor::run(
                    &client,
                    registry_url,
                    &cwd,
                    cli.json,
                    all,
                    fix || yes,
                    yes,
                )
                .await
            }
        },
        Commands::SwiftRegistry { force } => {
            commands::swift_registry::run(registry_url, cli.json, force).await
        },
        Commands::Mcp { action, name } => {
            commands::mcp::run(&action, name.as_deref(), cli.json).await
        },
        Commands::Use {
            args,
            list,
            pin,
            remove,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::r#use::run_cli(&args, list, pin, remove, &cwd, cli.json).await
        },
        Commands::Env { extra: _ } => {
            // Subcommand args are re-parsed from raw argv inside run().
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::env::run(&client, &cwd, cli.json).await
        },
        Commands::Run {
            scripts,
            env,
            parallel,
            continue_on_error,
            workspace_concurrency,
            stream,
            all,
            filter,
            filter_prod,
            fail_if_no_match,
            affected,
            base,
            changed_files_ignore_pattern,
            test_pattern,
            no_cache,
            no_env_check,
            watch,
            args,
        } => {
            lpm_runner::script::set_skip_env_validation(no_env_check);
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let workspace_mode = all || !filter.is_empty() || !filter_prod.is_empty() || affected;
            if workspace_concurrency.is_some() && !workspace_mode {
                return Err(lpm_common::LpmError::Script(
                    "--workspace-concurrency requires --all, --filter, --filter-prod, or --affected"
                        .into(),
                ));
            }
            if watch {
                if scripts.len() != 1 {
                    return Err(lpm_common::LpmError::Script(
                        "--watch supports exactly one script".into(),
                    ));
                }
                if all || !filter.is_empty() || !filter_prod.is_empty() || affected {
                    return Err(lpm_common::LpmError::Script(
                        "--watch does not support --all/--filter/--filter-prod/--affected; run the watcher inside a single package instead"
                            .into(),
                    ));
                }
                let bin_hint = commands::run::ensure_runtime(&cwd).await;
                commands::run::run_watch(&cwd, &scripts[0], &args, env.as_deref(), bin_hint)
            } else if workspace_mode {
                // Workspace mode: run scripts across packages with task graph
                commands::run::run_workspace(
                    &cwd,
                    &scripts,
                    &args,
                    env.as_deref(),
                    &filter,
                    &filter_prod,
                    affected,
                    &base,
                    &changed_files_ignore_pattern,
                    &test_pattern,
                    fail_if_no_match,
                    no_cache,
                    parallel,
                    continue_on_error,
                    workspace_concurrency,
                    stream,
                    cli.json,
                )
                .await
            } else {
                // Single package mode: supports multi-script + parallel
                commands::run::run_multi(
                    &cwd,
                    &scripts,
                    &args,
                    env.as_deref(),
                    parallel,
                    continue_on_error,
                    stream,
                    no_cache,
                    cli.json,
                )
                .await
            }
        }
        Commands::Exec {
            file,
            no_env_check,
            args,
        } => {
            lpm_runner::script::set_skip_env_validation(no_env_check);
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::run::exec(&cwd, &file, &args).await
        }
        Commands::Dlx {
            package,
            refresh,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::run::dlx(&client, &cwd, &package, &args, refresh).await
        }
        Commands::Filter {
            exprs,
            filter_prod,
            changed_files_ignore_pattern,
            test_pattern,
            explain,
            fail_if_no_match,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::filter::run(
                &cwd,
                &exprs,
                &filter_prod,
                &changed_files_ignore_pattern,
                &test_pattern,
                explain,
                fail_if_no_match,
                cli.json,
            )
            .await
        }
        Commands::Deploy {
            output,
            filter,
            filter_prod,
            changed_files_ignore_pattern,
            test_pattern,
            force,
            prod,
            dev,
            no_optional,
            dry_run,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let output_path = std::path::PathBuf::from(&output);
            commands::deploy::run(
                &client,
                &cwd,
                &output_path,
                &filter,
                &filter_prod,
                &changed_files_ignore_pattern,
                &test_pattern,
                force,
                prod,
                dev,
                no_optional,
                dry_run,
                cli.json,
            )
            .await
        }
        Commands::ApproveScripts {
            package,
            yes,
            list,
            global,
            group,
            dry_run,
        } => {
            if global {
                // global-scoped approve-scripts reads the
                // aggregate across every `lpm install -g` install root
                // and writes approvals to
                // `~/.lpm/global/trusted-dependencies.json`. `--group`
                // groups list + interactive review by top-level global,
                // while persisted trust still remains per dependency row.
                commands::approve_scripts::run_global(
                    package.as_deref(),
                    yes,
                    list,
                    group,
                    dry_run,
                    cli.json,
                )
                .await
            } else {
                // `--group` is only meaningful with `--global` today.
                // Reject early so users don't think it affects the
                // project-scoped flow.
                if group {
                    return Err(lpm_common::LpmError::Script(
                        "`--group` is a global-scope option; use it with `--global` or drop it."
                            .into(),
                    ));
                }
                let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
                commands::approve_scripts::run(
                    &cwd,
                    package.as_deref(),
                    yes,
                    list,
                    dry_run,
                    cli.json,
                )
                .await
            }
        }
        Commands::Patch { key } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::patch::run_patch(&cwd, &key, cli.json).await
        }
        Commands::PatchCommit { staging_dir } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let staging = std::path::PathBuf::from(staging_dir);
            commands::patch::run_patch_commit(&cwd, &staging, cli.json).await
        }
        Commands::PatchRemove {
            selectors,
            dry_run,
            keep_file,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::patch::run_patch_remove(&cwd, &selectors, dry_run, keep_file, cli.json).await
        }
        Commands::Sbom {
            format,
            output,
            registry_metadata,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::sbom::run(&client, &cwd, format, output.as_deref(), registry_metadata).await
        }
        Commands::Plugin { action, name } => {
            commands::plugin::run(&action, name.as_deref(), cli.json).await
        }
        Commands::Lint {
            all,
            filter,
            filter_prod,
            affected,
            base,
            changed_files_ignore_pattern,
            test_pattern,
            fail_if_no_match,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            tool_pin_validation::warn_unsupported_tool_pins_once(&cwd);
            if all || affected || !filter.is_empty() || !filter_prod.is_empty() {
                let affected_ref = if affected { Some(base.as_str()) } else { None };
                commands::tools::tool_workspace(
                    &cwd,
                    "lint",
                    &args,
                    false,
                    None,
                    &filter,
                    &filter_prod,
                    &changed_files_ignore_pattern,
                    &test_pattern,
                    affected_ref,
                    fail_if_no_match,
                    commands::tools::WorkspaceConcurrency::HostDefault,
                    cli.json,
                )
                .await
            } else {
                commands::tools::lint(&cwd, &args, cli.json).await
            }
        }
        Commands::Fmt {
            check,
            all,
            filter,
            filter_prod,
            affected,
            base,
            changed_files_ignore_pattern,
            test_pattern,
            fail_if_no_match,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            tool_pin_validation::warn_unsupported_tool_pins_once(&cwd);
            if all || affected || !filter.is_empty() || !filter_prod.is_empty() {
                let affected_ref = if affected { Some(base.as_str()) } else { None };
                commands::tools::tool_workspace(
                    &cwd,
                    "fmt",
                    &args,
                    check,
                    None,
                    &filter,
                    &filter_prod,
                    &changed_files_ignore_pattern,
                    &test_pattern,
                    affected_ref,
                    fail_if_no_match,
                    commands::tools::WorkspaceConcurrency::HostDefault,
                    cli.json,
                )
                .await
            } else {
                commands::tools::fmt(&cwd, &args, check, cli.json).await
            }
        }
        Commands::Check {
            all,
            filter,
            filter_prod,
            affected,
            base,
            changed_files_ignore_pattern,
            test_pattern,
            fail_if_no_match,
            engine,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            tool_pin_validation::warn_unsupported_tool_pins_once(&cwd);
            if all || affected || !filter.is_empty() || !filter_prod.is_empty() {
                let affected_ref = if affected { Some(base.as_str()) } else { None };
                commands::tools::tool_workspace(
                    &cwd,
                    "check",
                    &args,
                    false,
                    Some(engine),
                    &filter,
                    &filter_prod,
                    &changed_files_ignore_pattern,
                    &test_pattern,
                    affected_ref,
                    fail_if_no_match,
                    commands::tools::WorkspaceConcurrency::HostDefault,
                    cli.json,
                )
                .await
            } else {
                commands::tools::check(&cwd, &args, engine, cli.json).await
            }
        }
        Commands::Bundle {
            all,
            filter,
            filter_prod,
            affected,
            base,
            changed_files_ignore_pattern,
            test_pattern,
            fail_if_no_match,
            entry,
            out_dir,
            config,
            format,
            platform,
            minify,
            sourcemap,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let options = commands::bundle::BundleOptions {
                entry,
                out_dir,
                config,
                format,
                platform,
                minify,
                sourcemap,
                args,
            };
            commands::bundle::dispatch(
                &cwd,
                &options,
                all,
                &filter,
                &filter_prod,
                &changed_files_ignore_pattern,
                &test_pattern,
                affected,
                &base,
                fail_if_no_match,
                cli.json,
            )
            .await
        }
        Commands::Pack {
            all,
            filter,
            filter_prod,
            affected,
            base,
            changed_files_ignore_pattern,
            test_pattern,
            fail_if_no_match,
            entry,
            out_dir,
            config,
            tsconfig,
            target,
            format,
            platform,
            dts,
            minify,
            sourcemap,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let options = commands::pack::PackOptions {
                entry,
                out_dir,
                config,
                tsconfig,
                target,
                format,
                platform,
                dts,
                minify,
                sourcemap,
                args,
            };
            commands::pack::dispatch(
                &cwd,
                &options,
                all,
                &filter,
                &filter_prod,
                &changed_files_ignore_pattern,
                &test_pattern,
                affected,
                &base,
                fail_if_no_match,
                cli.json,
            )
            .await
        }
        Commands::Test {
            all,
            filter,
            filter_prod,
            affected,
            base,
            changed_files_ignore_pattern,
            test_pattern,
            fail_if_no_match,
            workspace_concurrency,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            tool_pin_validation::warn_unsupported_tool_pins_once(&cwd);
            commands::tools::dispatch_test_or_bench(
                &cwd,
                "test",
                &args,
                all,
                &filter,
                &filter_prod,
                &changed_files_ignore_pattern,
                &test_pattern,
                affected,
                &base,
                fail_if_no_match,
                workspace_concurrency,
                cli.json,
            )
            .await
        }
        Commands::Bench {
            all,
            filter,
            filter_prod,
            affected,
            base,
            changed_files_ignore_pattern,
            test_pattern,
            fail_if_no_match,
            workspace_concurrency,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            tool_pin_validation::warn_unsupported_tool_pins_once(&cwd);
            commands::tools::dispatch_test_or_bench(
                &cwd,
                "bench",
                &args,
                all,
                &filter,
                &filter_prod,
                &changed_files_ignore_pattern,
                &test_pattern,
                affected,
                &base,
                fail_if_no_match,
                workspace_concurrency,
                cli.json,
            )
            .await
        }
        Commands::Ci {
            omit,
            prod,
            offline,
            allow_new,
            strict_integrity,
            strict_peer_dependencies,
            no_strict_peer_dependencies,
            min_release_age,
            ignore_provenance_drift,
            ignore_provenance_drift_all,
            unverified_provenance,
            unverified_provenance_all,
            linker,
            no_skills,
            no_editor_setup,
            no_security_summary,
            auto_build,
            no_engine_strict,
            audit_after_install,
            no_audit_after_install,
            policy,
            yolo,
            triage_alias,
            advisor,
            strict_sandbox,
            paranoid,
            no_sandbox,
        } => {
            let cli_strict_peer_dependencies =
                match (strict_peer_dependencies, no_strict_peer_dependencies) {
                    (true, false) => Some(true),
                    (false, true) => Some(false),
                    _ => None,
                };
            let omit_policy = install_omit_policy_from_cli(&omit, prod);

            if !cli.json {
                for warning in auth::check_token_expiry_warnings() {
                    output::warn(&warning);
                }
            }

            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let cwd = resolve_install_project_dir(&cwd, false, cli.json)?;
            let cfg = commands::config::GlobalConfig::load();
            let eff_allow_new = allow_new || cfg.get_bool("allowNew").unwrap_or(false);
            let eff_no_skills = no_skills || cfg.get_bool("noSkills").unwrap_or(false);
            let eff_no_editor =
                no_editor_setup || cfg.get_bool("noEditorSetup").unwrap_or(false);
            let eff_no_sec =
                no_security_summary || cfg.get_bool("noSecuritySummary").unwrap_or(false);
            let eff_auto_build = auto_build || cfg.get_bool("autoBuild").unwrap_or(false);
            let eff_audit_after_install: bool = if audit_after_install {
                true
            } else if no_audit_after_install {
                false
            } else if let Ok(env_val) = std::env::var("LPM_AUDIT_AFTER_INSTALL") {
                match env_val.trim().to_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => true,
                    "0" | "false" | "no" | "off" => false,
                    _ => cfg.get_bool("audit-after-install").unwrap_or(false),
                }
            } else {
                cfg.get_bool("audit-after-install").unwrap_or(false)
            };

            engine_check::enforce(&cwd, no_engine_strict, cli.json)?;

            let min_release_age_override: Option<u64> = match min_release_age.as_deref() {
                Some(s) => Some(release_age_config::parse_duration(s)?),
                None => None,
            };
            let drift_ignore_policy = provenance_fetch::DriftIgnorePolicy::from_cli(
                ignore_provenance_drift,
                ignore_provenance_drift_all,
            );
            let (verify_policy, verify_source) = provenance_fetch::VerifyPolicy::resolve_from_chain(
                unverified_provenance,
                unverified_provenance_all,
                std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref(),
                || cfg.get_sigstore_verify(),
            );
            if !matches!(verify_policy.enforce, provenance_fetch::EnforceMode::Deny) {
                let mode_label = match verify_policy.enforce {
                    provenance_fetch::EnforceMode::Warn => "warn",
                    provenance_fetch::EnforceMode::Off => "off",
                    provenance_fetch::EnforceMode::Deny => unreachable!("guarded above"),
                };
                tracing::warn!(
                    target = "lpm::provenance",
                    enforce_mode = mode_label,
                    source = ?verify_source,
                    "sigstore verification posture is degraded for this install run",
                );
                if !cli.json {
                    output::warn(&format!(
                        "Sigstore provenance verification posture: {} (source: {}). \
                         Provenance attestations will {} be cryptographically verified \
                         for this install. To re-enable fail-closed: {}.",
                        mode_label,
                        match verify_source {
                            provenance_fetch::EnforceModeSource::Env =>
                                "LPM_PROVENANCE_ENFORCE env",
                            provenance_fetch::EnforceModeSource::Config =>
                                "[sigstore] verify in ~/.lpm/config.toml",
                            provenance_fetch::EnforceModeSource::Default => "default",
                        },
                        if matches!(verify_policy.enforce, provenance_fetch::EnforceMode::Off) {
                            "NOT"
                        } else {
                            "be checked but rejections will only log, not block —"
                        },
                        verify_source.re_enable_hint(),
                    ));
                }
            }

            let script_policy_cfg =
                script_policy_config::ScriptPolicyConfig::from_package_json(&cwd);
            let cli_script_policy_override =
                script_policy_config::collapse_policy_flags(policy.as_deref(), yolo, triage_alias)
                    .map_err(lpm_common::LpmError::Script)?;
            let effective_script_policy =
                script_policy_config::resolve_script_policy_with_security(
                    &cwd,
                    cli_script_policy_override,
                    &script_policy_cfg,
                    cli.json,
                )?;
            tracing::debug!(
                "lpm ci: effective script-policy = {}",
                effective_script_policy.as_str()
            );
            if let Some(invalid) = &script_policy_cfg.policy_parse_error
                && !cli.json
            {
                output::warn(&format!(
                    "package.json > lpm > scriptPolicy: invalid value '{invalid}' \
                     (expected one of: deny, allow, triage); this key was \
                     ignored — effective policy: {}",
                    effective_script_policy.as_str(),
                ));
            }

            let cli_linker = linker.map(LinkerCli::into_linker_mode);
            let root_lifecycle = commands::root_lifecycle::RootProjectLifecycle::load(&cwd)?;
            root_lifecycle.run_dev_preinstall(&cwd, cli.json)?;

            commands::install::run_with_options(
                &client,
                &cwd,
                cli.json,
                offline,
                commands::install::FrozenLockfileMode::Always,
                false,
                eff_allow_new,
                strict_integrity,
                cli_strict_peer_dependencies,
                cli_linker,
                eff_no_skills,
                eff_no_editor,
                eff_no_sec,
                eff_auto_build,
                None,
                None,
                None,
                cli_script_policy_override,
                advisor.clone(),
                min_release_age_override,
                drift_ignore_policy,
                verify_policy,
                omit_policy,
                strict_sandbox || paranoid,
                no_sandbox,
                cli.verbose,
                eff_audit_after_install,
            )
            .await?;

            commands::root_lifecycle::RootProjectLifecycle::load(&cwd)?
                .run_after_successful_install(&cwd, cli.json)
        }
        Commands::Dev {
            https,
            tunnel,
            network,
            port,
            host,
            domain,
            env,
            no_open,
            no_install,
            no_tunnel,
            no_https,
            no_env_check,
            tunnel_auth,
            quiet,
            dashboard,
            no_dashboard,
            no_inspect,
            inspect_port,
            yes,
            allow_ca_bootstrap,
            args,
        } => {
            lpm_runner::script::set_skip_env_validation(no_env_check);
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;

            // Read lpm.json for auto-detection
            let lpm_config = lpm_runner::lpm_json::read_lpm_json(&cwd).ok().flatten();

            // Auto-detect tunnel from lpm.json if not explicitly set.
            // Track the source for the startup banner.
            let domain_from_cli = domain.is_some();
            let tunnel_domain = domain.clone().or_else(|| {
                lpm_config
                    .as_ref()
                    .and_then(|c| c.tunnel.as_ref())
                    .and_then(|t| t.domain.clone())
            });
            let tunnel_source = if domain_from_cli {
                Some("--domain")
            } else if tunnel_domain.is_some() {
                Some("lpm.json")
            } else if tunnel {
                Some("--tunnel")
            } else {
                None
            };
            let tunnel = (tunnel || tunnel_domain.is_some()) && !no_tunnel;
            // Auto-detect HTTPS from lpm.json if not explicitly set via --https flag
            let https_from_config = lpm_config.as_ref().and_then(|c| c.https).unwrap_or(false);
            let https = (https || https_from_config) && !no_https;

            // Resolve token through the SessionManager attached to
            // `client` so refresh-only-state recovery and
            // session-source classification both apply. `tunnel` is a
            // session-bound feature; `SessionRequired` rejects
            // `--token`/`LPM_TOKEN`/CI tokens with a clear message.
            let resolved_token = if tunnel {
                match client.session() {
                    Some(s) => Some(
                        s.bearer_string_for(lpm_auth::AuthRequirement::SessionRequired)
                            .await
                            .map_err(|_| {
                                lpm_common::LpmError::Tunnel(
                                    "tunnel requires a refresh-backed `lpm login` session.\n  \
                                     `--token` / `LPM_TOKEN` / CI tokens are not accepted."
                                        .into(),
                                )
                            })?,
                    ),
                    None => None,
                }
            } else {
                None
            };

            commands::dev::run(
                &client,
                &cwd,
                https,
                tunnel,
                network,
                port,
                host.as_deref(),
                resolved_token.as_deref(),
                tunnel_domain.as_deref(),
                tunnel_source,
                &args,
                env.as_deref(),
                no_open,
                no_install,
                quiet,
                dashboard && !no_dashboard,
                lpm_config,
                tunnel_auth,
                no_inspect,
                inspect_port,
                yes,
                allow_ca_bootstrap,
            )
            .await
        }
        Commands::Cert {
            action,
            host,
            project,
            keep_old_trusted,
            fail_on_missing,
            dry_run,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::cert::run(
                &action,
                &cwd,
                &host,
                cli.json,
                commands::cert::ExtraArgs {
                    extra_projects: project,
                    keep_old_trusted_days: keep_old_trusted,
                    fail_on_missing,
                    dry_run,
                },
            )
            .await
        }
        Commands::Graph {
            package,
            format,
            why,
            depth,
            filter,
            prod,
            dev,
            no_open,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::graph::run(
                &cwd,
                package.as_deref(),
                why.as_deref(),
                &format,
                depth,
                filter.as_deref(),
                prod,
                dev,
                cli.json,
                no_open,
            )
            .await
        }
        Commands::Ports {
            action,
            target,
            all,
            yes,
            pid,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::ports::run(&action, target.as_deref(), &cwd, cli.json, all, yes, pid).await
        }
        Commands::Hosts { action, yes } => commands::hosts::run(&action, cli.json, yes),
        Commands::Proxy {
            action,
            detach,
            privileged_ports,
            replace,
            http_port,
            http_redirect_port,
            tls_port,
            forwarder_config,
        } => {
            let project_dir = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::proxy::run(commands::proxy::ProxyRunOptions {
                action: &action,
                project_dir: &project_dir,
                json_output: cli.json,
                detach,
                privileged_ports,
                replace,
                http_port,
                http_redirect_port,
                tls_port,
                forwarder_config: forwarder_config.as_deref(),
            })
            .await
        }
        Commands::InternalHostsFile {
            action,
            block_id,
            hosts,
        } => commands::hosts::run_internal_hosts_file(&action, block_id.as_deref(), &hosts),
        Commands::Tunnel {
            action,
            domain,
            org,
            tunnel_auth,
            auto_ack,
            session,
            no_inspect,
            inspect_port,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            // Determine if action is a port number or a named action
            let (effective_action, effective_port) = if let Ok(p) = action.parse::<u16>() {
                ("start", p)
            } else {
                (action.as_str(), 3000u16)
            };
            // Only the relay-facing tunnel actions need a refresh-backed session.
            // Local log inspection and replay stay useful on a fresh machine and
            // should not depend on keychain-backed auth state.
            let resolved_token = if tunnel_action_requires_session(effective_action) {
                match client.session() {
                    Some(s) => Some(
                        s.bearer_string_for(lpm_auth::AuthRequirement::SessionRequired)
                            .await
                            .map_err(|_| {
                                lpm_common::LpmError::Tunnel(
                                    "tunnel requires a refresh-backed `lpm login` session.\n  \
                                     `--token` / `LPM_TOKEN` / CI tokens are not accepted."
                                        .into(),
                                )
                            })?,
                    ),
                    None => None,
                }
            } else {
                None
            };
            commands::tunnel::run(
                &client,
                effective_action,
                resolved_token.as_deref(),
                effective_port,
                domain.as_deref(),
                org.as_deref(),
                cli.json,
                &cwd,
                &args,
                tunnel_auth,
                no_inspect,
                inspect_port,
                auto_ack,
                session.as_deref(),
            )
            .await
        }
        Commands::Migrate {
            skip_verify,
            no_npmrc,
            no_ci,
            ci,
            no_install,
            dry_run,
            force,
            rollback,
            yes: _yes,
        } => {
            // `-y` is reserved (non-interactive flag) and intentionally
            // does NOT imply `--force`. The migrate flow has no
            // interactive prompts today; if the user wants to clobber
            // an existing lpm.lock they must pass `--force` explicitly.
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::migrate::run(
                &client,
                &cwd,
                skip_verify,
                no_npmrc,
                no_ci,
                ci,
                no_install,
                dry_run,
                force,
                rollback,
                cli.json,
            )
            .await
        }
        Commands::Vault { action } => commands::vault::run(&action, cli.json).await,
        Commands::SelfUpdate { refresh } => commands::self_update::run(cli.json, refresh).await,
        Commands::Completions { shell } => {
            commands::completions::run(shell);
            Ok(())
        }
        Commands::Schema { kind, out } => commands::schema::run(&kind, out.as_deref()),
        Commands::InternalUpdateCheck => {
            // hidden subcommand — unconditionally refresh the
            // update cache. The parent already checked is_stale() before
            // spawning this. Runs in a detached child process.
            //
            // Exit immediately after the refresh attempt — must NOT fall
            // through to the common tail path which calls is_stale() +
            // spawn_background_update_check(). Without this early exit,
            // a failed refresh (lastCheck not updated) would recursively
            // spawn another internal-update-check child on every failure.
            update_check::refresh_cache_now().await;
            std::process::exit(0);
        }
        Commands::External(args) => {
            // Try as package.json script shortcut: `lpm dev` → `lpm run dev`
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let scripts = vec![args[0].clone()];
            let extra_args = if args.len() > 1 { &args[1..] } else { &[] };
            commands::run::run_multi(&cwd, &scripts, extra_args, None, false, false, false, false, cli.json)
                .await
        }
    }
    }
    .await;

    // Update check: show notice from previous check (instant, no network).
    //
    // Suppress the banner whenever the just-run command was
    // `lpm self-update`, regardless of outcome. On failure the banner
    // would loop the user back into the same command that just errored;
    // on success the running PID is still the old binary while the
    // on-disk cache now reflects the just-upgraded `latest`, so the
    // banner predicate (`cache.latest > current`) fires and produces
    // the contradictory `Updated to 0.38.0` + `Update available:
    // 0.37.0 → 0.38.0` pair. The suppression is per-invocation; the
    // on-disk cache is untouched, so the next unrelated command still
    // surfaces the banner.
    let suppress_banner = should_suppress_update_banner(is_self_update_command);
    if !cli.json
        && !suppress_banner
        && let Some(notice) = update_check::read_cached_notice()
    {
        eprint!("{notice}");
    }

    // spawn a detached child process to refresh the update cache
    // if stale. The parent never waits for it — command exit is immediate.
    // The staleness check is sync (file stat + timestamp comparison).
    if update_check::is_stale() {
        spawn_background_update_check();
    }

    if let Err(e) = &result {
        exit_with_lpm_error(e, cli.json, registry_url);
    }

    Ok(())
}
