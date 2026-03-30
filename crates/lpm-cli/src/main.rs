use clap::{Parser, Subcommand};
use miette::{IntoDiagnostic, Result};

mod auth;
mod commands;
pub mod constraints;
pub mod editor_skills;
mod graph_render;
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

    /// Allow insecure HTTP connections to non-localhost registries.
    #[arg(long, global = true)]
    insecure: bool,
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
        #[arg(long, default_value = "20")]
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
    #[command(visible_alias = "i")]
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

        /// Allow recently published packages (skip minimumReleaseAge check).
        #[arg(long)]
        allow_new: bool,

        /// Linking mode: isolated (default, pnpm-style) or hoisted (npm-style).
        #[arg(long)]
        linker: Option<String>,

        /// Skip skills auto-install.
        #[arg(long)]
        no_skills: bool,

        /// Skip editor auto-integration.
        #[arg(long)]
        no_editor_setup: bool,
    },

    /// Remove packages from dependencies and node_modules.
    #[command(visible_aliases = ["un", "unlink"])]
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

        /// Force overwrite existing files without prompting.
        #[arg(long)]
        force: bool,

        /// Show what would be done without making changes.
        #[arg(long)]
        dry_run: bool,

        /// Skip dependency installation after adding.
        #[arg(long)]
        no_install_deps: bool,

        /// Skip skills auto-install.
        #[arg(long)]
        no_skills: bool,

        /// Skip editor auto-integration.
        #[arg(long)]
        no_editor_setup: bool,

        /// Package manager for dependency installation (lpm, npm, pnpm, yarn, bun, auto).
        #[arg(long, default_value = "lpm")]
        pm: String,
    },

    /// Publish a package to the LPM registry.
    #[command(visible_alias = "p")]
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

        /// Minimum quality score required to publish (0-100).
        #[arg(long)]
        min_score: Option<u32>,
    },

    /// Log in to the LPM registry.
    #[command(visible_alias = "l")]
    Login,

    /// Log out from the LPM registry.
    #[command(visible_alias = "lo")]
    Logout {
        /// Also revoke the token on the server.
        #[arg(long)]
        revoke: bool,
    },

    /// Generate .npmrc for CI/CD.
    Setup {
        /// Override the registry URL for .npmrc (default: current --registry or LPM_REGISTRY_URL).
        #[arg(short = 'r', long)]
        registry: Option<String>,

        /// Use OIDC token exchange instead of stored token.
        #[arg(long)]
        oidc: bool,

        /// Use scoped registry (@lpm.dev:registry=) instead of default registry.
        #[arg(long)]
        scoped: bool,
    },

    /// Rotate your auth token.
    #[command(name = "token-rotate")]
    TokenRotate,

    /// Check for newer versions of LPM dependencies.
    Outdated,

    /// Upgrade outdated LPM dependencies to latest versions.
    Upgrade {
        /// Upgrade to latest major versions (breaking changes).
        #[arg(long)]
        major: bool,
        /// Show what would be upgraded without making changes.
        #[arg(long)]
        dry_run: bool,
    },

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

    /// Manage the global content-addressable package store.
    Store {
        /// Action: verify, list, path, gc.
        action: String,

        /// Deep verification: parse package.json and validate name/version consistency.
        #[arg(long)]
        deep: bool,

        /// Preview what GC would remove without actually deleting anything.
        #[arg(long)]
        dry_run: bool,

        /// Only remove packages older than this duration (e.g., "30d", "7d", "24h").
        #[arg(long)]
        older_than: Option<String>,

        /// Force GC even when no lockfile is found (removes ALL unreferenced packages).
        #[arg(long)]
        force: bool,
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
    #[command(visible_alias = "rm")]
    Remove {
        /// Package to remove.
        package: String,
    },

    /// Audit installed packages for security/quality issues.
    Audit {
        /// Minimum severity level to report (info, moderate, high).
        #[arg(long)]
        level: Option<String>,
    },

    /// Health check: verify auth, registry, store, project state.
    Doctor {
        /// Auto-fix issues (install missing Node, run lpm install, run lpm fmt).
        #[arg(long)]
        fix: bool,

        /// Skip confirmation prompts for auto-fix actions (implies --fix).
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Configure Swift Package Manager to use LPM as a package registry (SE-0292).
    #[command(name = "swift-registry")]
    SwiftRegistry {
        /// Force re-download the signing certificate (useful for cert rotation).
        #[arg(long)]
        force: bool,
    },

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
        #[arg(short = 'd', long, default_value = "30")]
        days: u32,

        /// Use scoped registry (@lpm.dev:registry=) instead of default registry.
        #[arg(long)]
        scoped: bool,
    },

    /// Install, pin, and manage Node.js versions (e.g., lpm use node@22).
    ///
    /// `lpm use node@22` installs Node 22 and pins it in lpm.json.
    /// Scripts then auto-use the pinned version via PATH injection.
    Use {
        /// Runtime and version spec (e.g., node@22, node@lts, 22.5.0).
        spec: Option<String>,

        /// List installed runtime versions.
        #[arg(long)]
        list: bool,

        /// Pin only (skip install if already installed).
        #[arg(long)]
        pin: bool,
    },

    /// Alias for `lpm use` (backwards compatibility).
    #[command(hide = true)]
    Env {
        /// Action: install, list, pin, vars.
        action: String,
        /// Runtime and version spec, or vars sub-action.
        spec: Option<String>,
        /// Extra arguments (passed through to vars subcommands like set/delete).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra: Vec<String>,
    },

    /// Run script(s) from package.json.
    Run {
        /// Script name(s) to run. Multiple scripts separated by spaces.
        #[arg(required = true, num_args = 1..)]
        scripts: Vec<String>,

        /// Load a specific .env file by mode (e.g., --env=staging loads .env.staging).
        #[arg(long)]
        env: Option<String>,

        /// Run scripts in parallel (respects task dependencies from lpm.json).
        #[arg(long, short = 'p')]
        parallel: bool,

        /// Continue running remaining tasks even if one fails.
        #[arg(long)]
        continue_on_error: bool,

        /// Stream output with task prefixes instead of buffering.
        #[arg(long)]
        stream: bool,

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

        /// Extra arguments passed to scripts (after --).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Execute a file directly (auto-detects runtime: node for .js, tsx for .ts).
    Exec {
        /// File to execute (e.g., src/seed.ts, scripts/migrate.js).
        file: String,
        /// Extra arguments passed to the file. Use -- to separate from lpm flags.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run a package binary without installing it into the project.
    Dlx {
        /// Package to run (e.g., cowsay, create-next-app@latest).
        package: String,
        /// Force reinstall (ignore cache).
        #[arg(long)]
        refresh: bool,
        /// Extra arguments passed to the binary.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
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
        /// Run in all workspace packages.
        #[arg(long)]
        all: bool,
        /// Extra arguments passed to oxlint (e.g., --fix, src/).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Format source files (powered by Biome, lazy-downloaded on first use).
    Fmt {
        /// Check formatting without writing (CI mode, exits non-zero if unformatted).
        #[arg(long)]
        check: bool,
        /// Run in all workspace packages.
        #[arg(long)]
        all: bool,
        /// Extra arguments passed to biome format.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Type-check the project (runs tsc --noEmit).
    Check {
        /// Run in all workspace packages.
        #[arg(long)]
        all: bool,
        /// Extra arguments passed to tsc.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run tests (auto-detects vitest/jest/mocha).
    Test {
        /// Extra arguments passed to the test runner.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run benchmarks (auto-detects vitest bench).
    Bench {
        /// Extra arguments passed to the bench runner.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Start the dev server with optional HTTPS, tunnel, and network features.
    ///
    /// Auto-detects features from lpm.json: tunnel.domain enables --tunnel,
    /// services enables orchestrator. Dependencies auto-installed if stale.
    Dev {
        /// Enable local HTTPS with auto-generated certificates.
        #[arg(long)]
        https: bool,

        /// Expose localhost to the internet via LPM tunnel.
        #[arg(long)]
        tunnel: bool,

        /// Show network URLs and QR code for mobile testing.
        #[arg(long)]
        network: bool,

        /// Override the dev server port.
        #[arg(long)]
        port: Option<u16>,

        /// Custom hostname for the HTTPS certificate.
        #[arg(long)]
        host: Option<String>,

        /// Tunnel domain (e.g., acme-api.lpm.llc). Overrides lpm.json tunnel.domain.
        #[arg(long)]
        domain: Option<String>,

        /// Load a specific .env file by mode.
        #[arg(long)]
        env: Option<String>,

        /// Skip auto-opening browser after services are ready.
        #[arg(long)]
        no_open: bool,

        /// Skip auto-install even if dependencies are stale.
        #[arg(long)]
        no_install: bool,

        /// Disable tunnel even if configured in lpm.json.
        #[arg(long)]
        no_tunnel: bool,

        /// Disable HTTPS even if configured in lpm.json.
        #[arg(long)]
        no_https: bool,

        /// Extra arguments passed to the dev script.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Manage local HTTPS certificates (status, trust, uninstall, generate).
    Cert {
        /// Action: status, trust, uninstall, generate.
        action: String,

        /// Extra hostnames to include in the certificate SAN.
        #[arg(long)]
        host: Vec<String>,
    },

    /// Visualize the dependency graph (tree, DOT, Mermaid, JSON, HTML).
    Graph {
        /// Output format: tree (default), dot, mermaid, json, stats, html.
        #[arg(long, default_value = "tree")]
        format: String,

        /// Explain why a package is in your tree (show all paths from root).
        #[arg(long, name = "WHY")]
        why: Option<String>,

        /// Limit tree depth.
        #[arg(long)]
        depth: Option<usize>,

        /// Only show subtrees containing this package name.
        #[arg(long)]
        filter: Option<String>,

        /// Only show production dependencies.
        #[arg(long)]
        prod: bool,

        /// Only show devDependencies.
        #[arg(long)]
        dev: bool,
    },

    /// Manage dev service ports (list, kill, reset).
    Ports {
        /// Action: list (default), kill, reset.
        #[arg(default_value = "list")]
        action: String,
        /// Port number (for kill).
        port: Option<u16>,
    },

    /// Expose a local port to the internet via LPM tunnel.
    ///
    /// Actions: (default) start, claim, unclaim, list, inspect, replay, log
    /// Examples:
    ///   lpm tunnel 3000              — start tunnel on port 3000
    ///   lpm tunnel claim myapp       — claim myapp.t.lpm.dev
    ///   lpm tunnel unclaim myapp     — release myapp.t.lpm.dev
    ///   lpm tunnel list              — list your claimed subdomains
    ///   lpm tunnel inspect           — show captured webhooks
    ///   lpm tunnel replay 3          — replay webhook #3
    ///   lpm tunnel log               — browse webhook event log
    Tunnel {
        /// Action or port number. Actions: claim, unclaim, list, inspect, replay, log.
        /// If a number, starts a tunnel on that port.
        #[arg(default_value = "3000")]
        action: String,

        /// Subdomain name (for claim/unclaim) or specific subdomain (for start).
        subdomain: Option<String>,

        /// Organization slug (for org tunnel subdomains).
        #[arg(long)]
        org: Option<String>,

        /// Extra arguments for webhook subcommands (--last, --filter, --status, etc.).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Migrate from npm/yarn/pnpm/bun to LPM.
    Migrate {
        /// Skip lockfile verification after migration.
        #[arg(long)]
        skip_verify: bool,

        /// Don't configure .npmrc for the LPM registry.
        #[arg(long)]
        no_npmrc: bool,

        /// Don't generate CI template.
        #[arg(long)]
        no_ci: bool,

        /// Parse and convert only, don't write any files.
        #[arg(long)]
        dry_run: bool,

        /// Overwrite existing lpm.lock without prompting.
        #[arg(long)]
        force: bool,

        /// Restore files from .backup copies created by a previous migration.
        #[arg(long)]
        rollback: bool,

        /// Skip confirmation prompts, use defaults (implies --force).
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Open the LPM Vault app (install if not found, check for updates).
    Vault {
        /// Action: open (default), update, version.
        #[arg(default_value = "")]
        action: String,
    },

    /// Update LPM to the latest version.
    #[command(name = "self-update")]
    SelfUpdate,

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
        .with_base_url(registry_url.to_string())
        .with_insecure(cli.insecure);

    // Token priority: --token flag → env var / keychain / encrypted file
    if let Some(token) = &cli.token {
        client = client.with_token(token.clone());
    } else if let Some(token) = auth::get_token(registry_url) {
        client = client.with_token(token);

        // Periodic token validation — once every 24h, call whoami to detect expired tokens early
        if auth::should_revalidate_token() {
            match client.whoami().await {
                Ok(_) => auth::mark_token_validated(),
                Err(lpm_common::LpmError::AuthRequired) => {
                    let _ = auth::clear_token(registry_url);
                    tracing::warn!("stored token expired — cleared. Run: lpm login");
                }
                Err(_) => {
                    // Network errors etc. — don't clear, just skip validation
                }
            }
        }
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
        Commands::Health => commands::health::run(&client, registry_url, cli.json).await,
        Commands::Download {
            package,
            version,
            output,
        } => {
            commands::download::run(&client, &package, version.as_deref(), output.as_deref(), cli.json)
                .await
        }
        Commands::Resolve { packages } => {
            commands::resolve::run(&client, &packages, cli.json).await
        }
        Commands::Install {
            packages,
            save_dev,
            offline,
            allow_new,
            linker,
            no_skills,
            no_editor_setup,
        } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            if packages.is_empty() {
                commands::install::run_with_options(
                    &client, &cwd, cli.json, offline, allow_new, linker.as_deref(), no_skills, no_editor_setup,
                )
                .await
            } else {
                commands::install::run_add_packages(
                    &client, &cwd, &packages, save_dev, cli.json, allow_new,
                )
                .await
            }
        }
        Commands::Uninstall { packages } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::uninstall::run(&client, &cwd, &packages, cli.json).await
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
        } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
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
            )
            .await
        }
        Commands::Publish {
            dry_run,
            check,
            yes,
            provenance,
            min_score,
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
                            &oidc_client, &cwd, dry_run, check, yes, cli.json, min_score,
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

            commands::publish::run(&client, &cwd, dry_run, check, yes, cli.json, min_score).await
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
        Commands::Setup { registry: setup_registry, oidc, scoped } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            let effective_registry = setup_registry.as_deref().unwrap_or(registry_url);
            commands::setup::run(effective_registry, &cwd, cli.json, oidc, scoped).await
        }
        Commands::TokenRotate => {
            commands::token::run_rotate(&client, registry_url, cli.json).await
        }
        Commands::Outdated => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::outdated::run(&client, &cwd, cli.json).await
        }
        Commands::Upgrade { major, dry_run } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::upgrade::run(&client, &cwd, major, dry_run, cli.json).await
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
        Commands::Store {
            action,
            deep,
            dry_run,
            older_than,
            force,
        } => {
            commands::store::run(&action, deep, dry_run, older_than.as_deref(), force, cli.json).await
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
        Commands::Audit { level } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::audit::run(&client, &cwd, cli.json, level.as_deref()).await
        }
        Commands::Doctor { fix, yes } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::doctor::run(&client, registry_url, &cwd, cli.json, fix || yes, yes).await
        }
        Commands::SwiftRegistry { force } => {
            commands::swift_registry::run(registry_url, cli.json, force).await
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
                // `lpm use node@20` = install + pin (one command does both)
                commands::env::run(&client, "install", Some(s.as_str()), &cwd, cli.json).await?;
                commands::env::run(&client, "pin", Some(s.as_str()), &cwd, cli.json).await
            } else {
                // No spec, no flags — show list
                commands::env::run(&client, "list", None, &cwd, cli.json).await
            }
        }
        Commands::Env { action, spec, extra: _ } => {
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
        Commands::Run { scripts, env, parallel, continue_on_error, stream, all, filter, affected, base, no_cache, watch, args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            if watch {
                commands::run::ensure_runtime(&cwd).await;
                commands::run::run_watch(&cwd, &scripts[0], &args, env.as_deref(), no_cache)
            } else if all || filter.is_some() || affected {
                // Workspace mode: run each script across packages
                for script in &scripts {
                    commands::run::run_workspace(
                        &cwd, script, &args, env.as_deref(),
                        all, filter.as_deref(), affected, &base, no_cache, cli.json,
                    ).await?;
                }
                Ok(())
            } else {
                // Single package mode: supports multi-script + parallel
                commands::run::run_multi(
                    &cwd, &scripts, &args, env.as_deref(),
                    parallel, continue_on_error, stream, no_cache,
                ).await
            }
        }
        Commands::Exec { file, args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::run::exec(&cwd, &file, &args).await
        }
        Commands::Dlx { package, refresh, args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::run::dlx(&cwd, &package, &args, refresh).await
        }
        Commands::Plugin { action, name } => {
            commands::plugin::run(&action, name.as_deref(), cli.json).await
        }
        Commands::Lint { all, args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            if all {
                commands::tools::tool_workspace(&cwd, "lint", &args, false, cli.json).await
            } else {
                commands::tools::lint(&cwd, &args, cli.json).await
            }
        }
        Commands::Fmt { check, all, args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            if all {
                commands::tools::tool_workspace(&cwd, "fmt", &args, check, cli.json).await
            } else {
                commands::tools::fmt(&cwd, &args, check, cli.json).await
            }
        }
        Commands::Check { all, args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            if all {
                commands::tools::tool_workspace(&cwd, "check", &args, false, cli.json).await
            } else {
                commands::tools::check(&cwd, &args, cli.json).await
            }
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
            args,
        } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;

            // Read lpm.json for auto-detection
            let lpm_config = lpm_runner::lpm_json::read_lpm_json(&cwd)
                .ok()
                .flatten();

            // Auto-detect tunnel from lpm.json if not explicitly set
            let tunnel_domain = domain.clone().or_else(|| {
                lpm_config.as_ref()
                    .and_then(|c| c.tunnel.as_ref())
                    .and_then(|t| t.domain.clone())
            });
            let tunnel = (tunnel || tunnel_domain.is_some()) && !no_tunnel;
            let https = https && !no_https;

            // Resolve token if tunnel is enabled
            let resolved_token = if tunnel {
                cli.token.clone().or_else(|| auth::get_token(registry_url))
            } else {
                None
            };

            commands::dev::run(
                &cwd,
                https,
                tunnel,
                network,
                port,
                host.as_deref(),
                resolved_token.as_deref(),
                tunnel_domain.as_deref(),
                &args,
                env.as_deref(),
                no_open,
                no_install,
                lpm_config,
            )
            .await
        }
        Commands::Cert { action, host } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::cert::run(&action, &cwd, &host, cli.json).await
        }
        Commands::Graph { format, why, depth, filter, prod, dev } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::graph::run(
                &cwd,
                why.as_deref(),
                &format,
                depth,
                filter.as_deref(),
                prod,
                dev,
                cli.json,
            )
            .await
        }
        Commands::Ports { action, port } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::ports::run(&action, port, &cwd, cli.json).await
        }
        Commands::Tunnel { action, subdomain, org, args } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            let resolved_token = cli.token.clone()
                .or_else(|| auth::get_token(registry_url));
            // Determine if action is a port number or a named action
            let (effective_action, effective_port) = if let Ok(p) = action.parse::<u16>() {
                ("start", p)
            } else {
                (action.as_str(), 3000u16)
            };
            commands::tunnel::run(
                &client,
                effective_action,
                resolved_token.as_deref(),
                effective_port,
                subdomain.as_deref(),
                org.as_deref(),
                cli.json,
                &cwd,
                &args,
            )
            .await
        }
        Commands::Migrate { skip_verify, no_npmrc, no_ci, dry_run, force, rollback, yes } => {
            let cwd = std::env::current_dir()
                .map_err(|e| lpm_common::LpmError::Io(e))?;
            commands::migrate::run(&cwd, skip_verify, no_npmrc, no_ci, dry_run, force || yes, rollback, cli.json).await
        }
        Commands::Vault { action } => {
            commands::vault::run(&action, cli.json).await
        }
        Commands::SelfUpdate => {
            commands::self_update::run(cli.json).await
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

    // Handle ExitCode at the top level — the only place process::exit() should be called.
    // Library code returns Err(LpmError::ExitCode(code)) instead of calling process::exit()
    // directly, so Drop handlers run and the code remains testable.
    match &result {
        Err(e) => {
            // --json mode: output structured error JSON so LLMs/MCP servers can parse failures.
            // Without this, miette prints colored human-readable errors that can't be parsed.
            if cli.json {
                let json = serde_json::json!({
                    "success": false,
                    "error": format!("{e}"),
                    "error_code": e.error_code(),
                });
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            }

            // Preserve existing side effects before exiting
            match e {
                lpm_common::LpmError::ExitCode(code) => {
                    std::process::exit(*code);
                }
                lpm_common::LpmError::AuthRequired => {
                    let _ = auth::clear_token(registry_url);
                    if cli.json {
                        std::process::exit(1);
                    }
                }
                _ => {
                    if cli.json {
                        std::process::exit(1);
                    }
                }
            }
        }
        Ok(()) => {}
    }

    result.into_diagnostic()
}
