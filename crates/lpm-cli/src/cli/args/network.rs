use super::parsers::parse_workspace_concurrency;
use clap::Args;

#[derive(Args)]
pub(crate) struct EnvArgs {
    /// Subcommand and its arguments (e.g., `set KEY=VALUE`,
    /// `pull --org acme`, `oidc allow --provider=github …`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) extra: Vec<String>,
}

#[derive(Args)]
pub(crate) struct RunArgs {
    /// Script name(s) to run. Multiple scripts separated by spaces.
    #[arg(required = true, num_args = 1..)]
    pub(crate) scripts: Vec<String>,

    /// Load a specific .env file by mode (e.g., --env=staging loads .env.staging).
    #[arg(long)]
    pub(crate) env: Option<String>,

    /// Run scripts in parallel (respects task dependencies from lpm.json).
    #[arg(long, short = 'p')]
    pub(crate) parallel: bool,

    /// Do not bail after a task or selected workspace package fails.
    #[arg(long = "no-bail")]
    pub(crate) continue_on_error: bool,

    /// Limit concurrently running workspace packages.
    #[arg(long = "workspace-concurrency", value_name = "N", value_parser = parse_workspace_concurrency)]
    pub(crate) workspace_concurrency: Option<std::num::NonZeroUsize>,

    /// Stream output with task prefixes instead of buffering.
    #[arg(long)]
    pub(crate) stream: bool,

    /// Run in all workspace packages (topological order). Mutually
    /// exclusive with filters and `--affected`.
    #[arg(long, conflicts_with_all = ["filter", "filter_prod", "affected"])]
    pub(crate) all: bool,

    /// Filter workspace packages with the grammar. Can be passed
    /// multiple times: `--filter foo --filter bar` unions the two sets.
    ///
    /// Grammar: exact name (`foo`), glob (`@scope/*`, `foo-*`),
    /// path glob (`./apps/*`), path exact (`{./apps/web}`),
    /// git ref (`[origin/main]`), forward closure (`foo...`, `foo^...`),
    /// reverse closure (`...foo`, `...^foo`), exclusion (`!foo`).
    ///
    /// Note: removed the legacy substring matcher per design
    /// decision D2. `--filter core` no longer matches `@babel/core` —
    /// write `--filter '*/core'` for that.
    #[arg(long)]
    pub(crate) filter: Vec<String>,

    /// Filter workspace packages with production dependency closures.
    /// Same grammar as `--filter`, but `...` and `^...` do not walk
    /// `devDependencies` edges.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,

    /// Exit with a non-zero status if no workspace package matches the
    /// filter set. Recommended in CI to catch typo'd filters early.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,

    /// Run only in packages affected by git changes (vs base branch).
    #[arg(long)]
    pub(crate) affected: bool,

    /// Git base ref for --affected (default: main).
    #[arg(long, default_value = "main")]
    pub(crate) base: String,

    /// Ignore changed files matching this git-diff glob when evaluating
    /// `--affected` or `[git-ref]` filters. Can be passed multiple times.
    #[arg(long = "changed-files-ignore-pattern")]
    pub(crate) changed_files_ignore_pattern: Vec<String>,

    /// Treat changed files matching this git-diff glob as tests, so
    /// `--affected` and reverse git-ref closures do not fan out to
    /// dependents from them.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,

    /// Disable task caching (force re-execution).
    #[arg(long)]
    pub(crate) no_cache: bool,

    /// Skip environment variable schema validation.
    #[arg(long)]
    pub(crate) no_env_check: bool,

    /// Re-run on file changes.
    #[arg(long)]
    pub(crate) watch: bool,

    /// Extra arguments passed to scripts (after --).
    #[arg(last = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct ExecArgs {
    /// Environment mode to load (e.g., staging loads .env.staging).
    #[arg(long)]
    pub(crate) env: Option<String>,

    /// Skip environment variable schema validation.
    #[arg(long)]
    pub(crate) no_env_check: bool,

    /// Project-local binary to execute.
    pub(crate) command: String,

    /// Extra arguments passed to the binary.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct RunFileArgs {
    /// Environment mode to load (e.g., staging loads .env.staging).
    #[arg(long)]
    pub(crate) env: Option<String>,

    /// File to execute (e.g., src/seed.ts, scripts/migrate.js).
    pub(crate) file: String,

    /// Skip environment variable schema validation.
    #[arg(long)]
    pub(crate) no_env_check: bool,

    /// Disable LPM's TypeScript runtime preload and child Node propagation.
    #[arg(long = "plain-node", alias = "no-augment")]
    pub(crate) plain_node: bool,

    /// Re-run on file changes.
    #[arg(long)]
    pub(crate) watch: bool,

    /// Extra arguments passed to the file. Use -- to separate from lpm flags.
    #[arg(num_args = 0..)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct DlxArgs {
    /// Package to run (e.g., cowsay, create-next-app@latest).
    pub(crate) package: String,
    /// Force reinstall (ignore cache).
    #[arg(long)]
    pub(crate) refresh: bool,
    /// Allow recently published packages for this dlx run.
    #[arg(long)]
    pub(crate) allow_new: bool,
    /// Override the minimumReleaseAge cooldown for this dlx run only.
    #[arg(long, value_name = "DUR")]
    pub(crate) min_release_age: Option<String>,
    /// Exempt one exact package name from minimumReleaseAge for this dlx run only.
    #[arg(long, value_name = "PKG")]
    pub(crate) min_release_age_exclude: Vec<String>,
    /// Extra arguments passed to the binary.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct PortsArgs {
    /// Action: list (default), all, inspect, kill, reset, or a port number to inspect.
    #[arg(default_value = "list")]
    pub(crate) action: String,
    /// Port, range, or other action target.
    pub(crate) target: Option<String>,
    /// Show all listening TCP ports, not just the current project.
    #[arg(long)]
    pub(crate) all: bool,
    /// Confirm destructive range kills without prompting.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,
    /// Kill this PID explicitly. Bare numeric kill targets are ports.
    #[arg(long)]
    pub(crate) pid: Option<u32>,
}

#[derive(Args)]
pub(crate) struct HostsArgs {
    /// Action: clean.
    #[arg(default_value = "clean")]
    pub(crate) action: String,
    /// Confirm hosts-file cleanup without prompting.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,
}

#[derive(Args)]
pub(crate) struct ProxyArgs {
    /// Action: status, list, start, stop, install, uninstall.
    #[arg(default_value = "status")]
    pub(crate) action: String,
    /// Start the daemon in the background. Only valid with `start`.
    #[arg(long)]
    pub(crate) detach: bool,
    /// Install/remove the Unix low-port forwarder for 80/443 alongside the user service.
    #[arg(long = "privileged-ports")]
    pub(crate) privileged_ports: bool,
    /// Replace an existing privileged low-port forwarder owned by another UID.
    #[arg(long = "replace")]
    pub(crate) replace: bool,
    /// Also bind a plain HTTP listener on 127.0.0.1:<PORT>. Valid with `start` and `install`.
    #[arg(long = "http-port")]
    pub(crate) http_port: Option<u16>,
    /// Also bind a plain HTTP redirect listener on 127.0.0.1:<PORT>. Valid with `start` and `install`; requires `--tls-port`.
    #[arg(long = "http-redirect-port")]
    pub(crate) http_redirect_port: Option<u16>,
    /// Also bind a HTTPS listener on 127.0.0.1:<PORT>. Valid with `start` and `install`.
    #[arg(long = "tls-port")]
    pub(crate) tls_port: Option<u16>,
    /// Root-forwarder runtime config path. Internal service entrypoint.
    #[arg(long = "forwarder-config", hide = true)]
    pub(crate) forwarder_config: Option<std::path::PathBuf>,
}

#[derive(Args)]
pub(crate) struct TunnelArgs {
    /// Action or port number. Actions: claim, unclaim, list, domains, inspect, replay, log.
    /// If a number, starts a tunnel on that port.
    #[arg(default_value = "start")]
    pub(crate) action: String,

    /// Full tunnel domain (e.g., acme-api.lpm.llc) for claim/unclaim/start.
    #[arg(allow_hyphen_values = true)]
    pub(crate) domain: Option<String>,

    /// Organization slug (for org tunnel domains).
    #[arg(long)]
    pub(crate) org: Option<String>,

    /// Require auth token to access the tunnel URL (Pro/Org only).
    #[arg(long)]
    pub(crate) tunnel_auth: bool,

    /// Auto-acknowledge webhooks when the local server is down.
    /// Returns 200 OK to prevent provider retries and endpoint deactivation.
    #[arg(long)]
    pub(crate) auto_ack: bool,

    /// Name for this tunnel session (visible in inspector session list).
    #[arg(long)]
    pub(crate) session: Option<String>,

    /// Disable the inspector UI (default: inspector starts automatically).
    #[arg(long)]
    pub(crate) no_inspect: bool,

    /// Port for the inspector UI (default: auto-pick a free ephemeral port).
    ///
    /// When omitted, the inspector binds `127.0.0.1:0` and the OS picks an
    /// unused port — race-free against `lpm dev`'s service ports or any
    /// other local server. Pass an explicit value to bind that exact port
    /// strictly (fails with a clear diagnostic if the port is in use).
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) inspect_port: Option<u16>,

    /// Extra arguments for webhook subcommands (--last, --filter, --status, etc.).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct InternalHostsFileArgs {
    /// Action: upsert, remove, or clean.
    pub(crate) action: String,
    /// Managed block id for upsert/remove.
    #[arg(long = "block-id")]
    pub(crate) block_id: Option<String>,
    /// Hostname to place in the managed block. Repeat for multiple hosts.
    #[arg(long = "host")]
    pub(crate) hosts: Vec<String>,
}
