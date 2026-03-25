use clap::{Parser, Subcommand};
use miette::{IntoDiagnostic, Result};

mod auth;
mod commands;
pub mod constraints;
mod import_rewriter;
pub mod intelligence;
mod oidc;
mod output;
mod quality;
pub mod security_check;
mod swift_manifest;
mod update_check;

#[derive(Parser)]
#[command(
    name = "lpm-rs",
    version,
    about = "LPM — the package manager for modern software",
    long_about = "Rust-based LPM client. Fast, correct, registry-aware."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Use a specific auth token instead of the stored one.
    #[arg(long, global = true, env = "LPM_TOKEN")]
    token: Option<String>,

    /// Override the registry URL.
    #[arg(long, global = true, env = "LPM_REGISTRY_URL")]
    registry: Option<String>,

    /// Output as JSON (for CI/scripting).
    #[arg(long, global = true)]
    json: bool,

    /// Show verbose output (debug logging).
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
#[command(allow_external_subcommands = true)]
enum Commands {
    /// Show package information.
    Info {
        /// Package name (e.g., @lpm.dev/owner.package or owner.package)
        package: String,

        /// Show a specific version instead of latest.
        #[arg(long)]
        version: Option<String>,
    },

    /// Search for packages.
    Search {
        /// Search query.
        query: String,

        /// Maximum results (1-20).
        #[arg(long, default_value = "10")]
        limit: u32,
    },

    /// Show quality report for a package.
    Quality {
        /// Package name (e.g., owner.package)
        package: String,
    },

    /// Show who you're logged in as.
    Whoami,

    /// Check registry health.
    Health,

    /// Download and extract a package tarball.
    Download {
        /// Package name (e.g., @lpm.dev/owner.package or owner.package)
        package: String,

        /// Version to download (default: latest).
        #[arg(long)]
        version: Option<String>,

        /// Directory to extract into (default: current directory).
        #[arg(long, short)]
        output: Option<String>,
    },

    /// Resolve dependency tree for packages.
    Resolve {
        /// Packages to resolve (e.g., @lpm.dev/owner.package@^1.0.0)
        packages: Vec<String>,
    },

    /// Install dependencies from package.json, or add specific packages.
    Install {
        /// Packages to install (e.g., express@^4.0.0, @lpm.dev/neo.highlight).
        /// If omitted, installs all dependencies from package.json.
        packages: Vec<String>,

        /// Save as devDependencies instead of dependencies.
        #[arg(long, short = 'D')]
        save_dev: bool,

        /// Install without network (use lockfile + global store only).
        #[arg(long)]
        offline: bool,
    },

    /// Remove packages from dependencies and node_modules.
    Uninstall {
        /// Packages to remove (e.g., express, @lpm.dev/neo.highlight).
        packages: Vec<String>,
    },

    /// Add source files from a package into your project (shadcn-style).
    Add {
        /// Package to add (e.g., @lpm.dev/owner.package@1.0.0?component=dialog).
        package: String,

        /// Target directory (overrides auto-detection).
        #[arg(long)]
        path: Option<String>,

        /// Skip interactive prompts, use defaults.
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Publish a package to the LPM registry.
    Publish {
        /// Preview without uploading.
        #[arg(long)]
        dry_run: bool,

        /// Only show quality report, don't publish.
        #[arg(long)]
        check: bool,

        /// Skip confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,

        /// Require OIDC provenance (fail if not in CI).
        #[arg(long)]
        provenance: bool,
    },

    /// Log in to the LPM registry.
    Login,

    /// Log out from the LPM registry.
    Logout {
        /// Also revoke the token on the server.
        #[arg(long)]
        revoke: bool,
    },

    /// Generate .npmrc for CI/CD.
    Setup,

    /// Rotate your auth token.
    #[command(name = "token-rotate")]
    TokenRotate,

    /// Check for newer versions of LPM dependencies.
    Outdated,

    /// Initialize a new LPM package.
    Init {
        /// Skip prompts, use defaults.
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Manage CLI configuration.
    Config {
        /// Action: get, set, delete, list.
        action: String,
        /// Config key.
        key: Option<String>,
        /// Config value (for set).
        value: Option<String>,
    },

    /// Manage the global package cache.
    Cache {
        /// Action: list, clean, path.
        action: String,
    },

    /// Show pool revenue stats.
    Pool,

    /// Manage Agent Skills.
    Skills {
        /// Action: list, install, validate, clean.
        action: String,
        /// Package name (for install).
        package: Option<String>,
    },

    /// Remove a source-delivered package (reverse of `add`).
    Remove {
        /// Package to remove.
        package: String,
    },

    /// Audit installed packages for security/quality issues.
    Audit,

    /// Health check: verify auth, registry, store, project state.
    Doctor,

    /// Configure Swift Package Manager to use LPM as a package registry (SE-0292).
    #[command(name = "swift-registry")]
    SwiftRegistry,

    /// Manage MCP servers (setup, remove, status).
    Mcp {
        /// Action: setup, remove, status.
        action: String,
        /// Server name (for setup/remove).
        name: Option<String>,
    },

    /// Generate a read-only .npmrc token for local development.
    Npmrc {
        /// Token validity in days (default: 30).
        #[arg(long, default_value = "30")]
        days: u32,

        /// Use scoped registry (@lpm.dev:registry=) instead of default registry.
        #[arg(long)]
        scoped: bool,
    },

    /// Install and manage Node.js versions (e.g., lpm use node@22).
    Use {
        /// Runtime and version spec (e.g., node@22, node@lts, 22.5.0).
        /// Or an action: --list, --pin.
        spec: Option<String>,

        /// List installed runtime versions.
        #[arg(long)]
        list: bool,

        /// Pin the version to lpm.json (instead of just installing).
        #[arg(long)]
        pin: bool,
    },

    /// Alias for `lpm use` (backwards compatibility).
    #[command(hide = true)]
    Env {
        /// Action: install, list, pin.
        action: String,
        /// Runtime and version spec.
        spec: Option<String>,
    },

    /// Run a script from package.json.
    Run {
        /// Script name (e.g., dev, build, test).
        script: String,

        /// Load a specific .env file by mode (e.g., --env=staging loads .env.staging).
        #[arg(long)]
        env: Option<String>,

        /// Run in all workspace packages (topological order).
        #[arg(long)]
        all: bool,

        /// Run only in packages matching this filter (name or path glob).
        #[arg(long)]
        filter: Option<String>,

        /// Run only in packages affected by git changes (vs base branch).
        #[arg(long)]
        affected: bool,

        /// Git base ref for --affected (default: main).
        #[arg(long, default_value = "main")]
        base: String,

        /// Disable task caching (force re-execution).
        #[arg(long)]
        no_cache: bool,

        /// Re-run on file changes.
        #[arg(long)]
        watch: bool,

        /// Extra arguments passed to the script.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Execute a file directly (auto-detects runtime: node for .js, tsx for .ts).
    Exec {
        /// File to execute (e.g., src/seed.ts, scripts/migrate.js).
        file: String,
        /// Extra arguments passed to the file.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Run a package binary without installing it into the project.
    Dlx {
        /// Package to run (e.g., cowsay, create-next-app@latest).
        package: String,
        /// Extra arguments passed to the binary.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Manage tool plugins (list installed, update to latest).
    Plugin {
        /// Action: list, update.
        action: String,
        /// Plugin name (for update). Omit to update all.
        name: Option<String>,
    },

    /// Lint source files (powered by Oxlint, lazy-downloaded on first use).
    Lint {
        /// Extra arguments passed to oxlint (e.g., --fix, src/).
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Format source files (powered by Biome, lazy-downloaded on first use).
    Fmt {
        /// Extra arguments passed to biome format (e.g., --check, src/).
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Type-check the project (runs tsc --noEmit).
    Check {
        /// Extra arguments passed to tsc.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Run tests (auto-detects vitest/jest/mocha).
    Test {
        /// Extra arguments passed to the test runner.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Run benchmarks (auto-detects vitest bench).
    Bench {
        /// Extra arguments passed to the bench runner.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Catch-all: unknown subcommands are tried as package.json scripts.
    /// e.g., `lpm dev` runs the "dev" script if no built-in command matches.
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install miette's fancy error handler for pretty error display
    miette::set_hook(Box::new(|_| {
        Box::new(
            miette::MietteHandlerOpts::new()
                .terminal_links(true)
                .context_lines(2)
                .build(),
        )
    }))
    .ok();

    let cli = Cli::parse();

    // Set up tracing based on verbosity
    let filter = if cli.verbose {
        "lpm=debug,reqwest=debug"
    } else {
        "lpm=warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| filter.into()),
        )
        .with_target(false)
        .without_time()
        .init();

    let registry_url = cli
        .registry
        .as_deref()
        .unwrap_or(lpm_common::DEFAULT_REGISTRY_URL);

    let mut client = lpm_registry::RegistryClient::new()
        .with_base_url(registry_url.to_string());

    // Token priority: --token flag → env var / keychain / encrypted file
    if let Some(token) = &cli.token {
        client = client.with_token(token.clone());
    } else if let Some(token) = auth::get_token(registry_url) {
        client = client.with_token(token);
    }

    let result = match cli.command {
        Commands::Info { package, version } => {
            commands::info::run(&client, &package, version.as_deref(), cli.json).await
        }
        Commands::Search { query, limit } => {
            commands::search::run(&client, &query, limit, cli.json).await
        }
        Commands::Quality { package } => {
            commands::quality::run(&client, &package, cli.json).await
        }
        Commands::Whoami => commands::whoami::run(&client, cli.json).await,
        Commands::Health => commands::health::run(&client).await,
        Commands::Download {
            package,
            version,
            output,
        } => {
            commands::download::run(&client, &package, version.as_deref(), output.as_deref())
                .await
        }
        Commands::Resolve { packages } => {
            commands::resolve::run(&client, &packages, cli.json).await
        }
        Commands::Install {
            packages,
            save_dev,
            offline,
        } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            if packages.is_empty() {
                commands::install::run_with_options(
                    &client, &cwd, cli.json, offline,
                )
                .await
            } else {
                commands::install::run_add_packages(
                    &client, &cwd, &packages, save_dev, cli.json,
                )
                .await
            }
        }
        Commands::Uninstall { packages } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::uninstall::run(&client, &cwd, &packages, cli.json).await
        }
        Commands::Add { package, path, yes } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::add::run(
                &client,
                &cwd,
                &package,
                path.as_deref(),
                yes,
                cli.json,
            )
            .await
        }
        Commands::Publish {
            dry_run,
            check,
            yes,
            provenance,
        } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;

            // OIDC: auto-detect CI environment or require with --provenance
            if provenance || oidc::detect_ci_environment().is_some() {
                match oidc::exchange_oidc_token(registry_url, None, "publish").await {
                    Ok(oidc_token) => {
                        let oidc_client = client
                            .clone_with_config()
                            .with_token(oidc_token.token);
                        return commands::publish::run(
                            &oidc_client, &cwd, dry_run, check, yes, cli.json,
                        )
                        .await
                        .into_diagnostic();
                    }
                    Err(e) => {
                        if provenance {
                            return Err(e).into_diagnostic();
                        }
                        tracing::debug!("OIDC auto-detect failed, using stored token: {e}");
                    }
                }
            }

            commands::publish::run(&client, &cwd, dry_run, check, yes, cli.json).await
        }
        Commands::Login => {
            let registry = cli
                .registry
                .as_deref()
                .unwrap_or(lpm_common::DEFAULT_REGISTRY_URL);
            commands::login::run(registry, cli.json).await
        }
        Commands::Logout { revoke } => {
            let registry = cli
                .registry
                .as_deref()
                .unwrap_or(lpm_common::DEFAULT_REGISTRY_URL);
            commands::logout::run(&client, registry, revoke, cli.json).await
        }
        Commands::Setup => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::setup::run(registry_url, &cwd, cli.json).await
        }
        Commands::TokenRotate => {
            commands::token::run_rotate(&client, registry_url, cli.json).await
        }
        Commands::Outdated => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::outdated::run(&client, &cwd, cli.json).await
        }
        Commands::Init { yes } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::init::run(&cwd, yes, cli.json).await
        }
        Commands::Config { action, key, value } => {
            commands::config::run(
                &action,
                key.as_deref(),
                value.as_deref(),
                cli.json,
            )
            .await
        }
        Commands::Cache { action } => {
            commands::cache::run(&action, cli.json).await
        }
        Commands::Pool => {
            commands::pool::run(&client, cli.json).await
        }
        Commands::Skills {
            action,
            package,
        } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::skills::run(
                &client,
                &action,
                package.as_deref(),
                &cwd,
                cli.json,
            )
            .await
        }
        Commands::Remove { package } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::remove::run(&cwd, &package, cli.json).await
        }
        Commands::Audit => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::audit::run(&client, &cwd, cli.json).await
        }
        Commands::Doctor => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::doctor::run(&client, registry_url, &cwd, cli.json).await
        }
        Commands::SwiftRegistry => {
            commands::swift_registry::run(registry_url, cli.json).await
        }
        Commands::Mcp { action, name } => {
            commands::mcp::run(&action, name.as_deref(), cli.json).await
        }
        Commands::Use { spec, list, pin } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            if list {
                commands::env::run(&client, "list", spec.as_deref(), &cwd, cli.json).await
            } else if pin {
                let s = spec.as_deref().ok_or_else(|| {
                    lpm_common::LpmError::Script("missing version. Usage: lpm use --pin node@22.5.0".into())
                })?;
                commands::env::run(&client, "pin", Some(s), &cwd, cli.json).await
            } else if let Some(s) = &spec {
                commands::env::run(&client, "install", Some(s.as_str()), &cwd, cli.json).await
            } else {
                // No spec, no flags — show list
                commands::env::run(&client, "list", None, &cwd, cli.json).await
            }
        }
        Commands::Env { action, spec } => {
            // Hidden backwards-compat alias
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::env::run(&client, &action, spec.as_deref(), &cwd, cli.json).await
        }
        Commands::Npmrc { days, scoped } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::npmrc::run(&client, &cwd, &registry_url, days, scoped, cli.json).await
        }
        Commands::Run { script, env, all, filter, affected, base, no_cache, watch, args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            if watch {
                commands::run::run_watch(&cwd, &script, &args, env.as_deref(), no_cache)
            } else if all || filter.is_some() || affected {
                commands::run::run_workspace(
                    &cwd, &script, &args, env.as_deref(),
                    all, filter.as_deref(), affected, &base, no_cache, cli.json,
                ).await
            } else {
                commands::run::run(&cwd, &script, &args, env.as_deref(), no_cache).await
            }
        }
        Commands::Exec { file, args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::run::exec(&cwd, &file, &args).await
        }
        Commands::Dlx { package, args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::run::dlx(&cwd, &package, &args).await
        }
        Commands::Plugin { action, name } => {
            commands::plugin::run(&action, name.as_deref(), cli.json).await
        }
        Commands::Lint { args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::tools::lint(&cwd, &args, cli.json).await
        }
        Commands::Fmt { args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::tools::fmt(&cwd, &args, cli.json).await
        }
        Commands::Check { args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::tools::check(&cwd, &args, cli.json).await
        }
        Commands::Test { args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::tools::test(&cwd, &args, cli.json).await
        }
        Commands::Bench { args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::tools::bench(&cwd, &args, cli.json).await
        }
        Commands::External(args) => {
            // Try as package.json script shortcut: `lpm dev` → `lpm run dev`
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            let script_name = &args[0];
            let extra_args = if args.len() > 1 { &args[1..] } else { &[] };
            commands::run::run(&cwd, script_name, extra_args, None, false).await
        }
    };

    // Update check: show notice from previous check (instant, no network)
    if !cli.json {
        if let Some(notice) = update_check::read_cached_notice() {
            eprint!("{notice}");
        }
    }

    // Refresh update cache if stale (max 3s, once per 24h)
    update_check::refresh_cache_if_stale().await;

    result.into_diagnostic()
}
