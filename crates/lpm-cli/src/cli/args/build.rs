use super::parsers::{parse_advisor_slug, parse_workspace_concurrency};
use super::{BundleFormat, BundlePlatform, CheckEngine, InstallOmitCli, LinkerCli};
use clap::Args;

#[derive(Args)]
pub(crate) struct PluginArgs {
    /// Action: `list` (alias `ls`), `outdated`, `update` (alias `upgrade`), `remove` (aliases `rm`, `uninstall`).
    pub(crate) action: String,
    /// Plugin name. Optional for `update` (omit to update all); required for `remove`.
    pub(crate) name: Option<String>,
}

#[derive(Args)]
pub(crate) struct LintArgs {
    /// Run in all workspace packages. Mutually exclusive with filters
    /// and `--affected` — pick one selection mode.
    #[arg(long, conflicts_with_all = ["filter", "filter_prod", "affected"])]
    pub(crate) all: bool,
    /// Filter workspace packages with the grammar. Can be passed
    /// multiple times: `--filter foo --filter bar` unions the two sets.
    ///
    /// Grammar: exact name (`foo`), glob (`@scope/*`, `foo-*`),
    /// path glob (`./apps/*`), path exact (`{./apps/web}`),
    /// git ref (`[origin/main]`), forward closure (`foo...`, `foo^...`),
    /// reverse closure (`...foo`, `...^foo`), exclusion (`!foo`).
    #[arg(long)]
    pub(crate) filter: Vec<String>,
    /// Filter workspace packages with production dependency closures.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,
    /// Run only in packages affected by git changes (vs base branch).
    #[arg(long, conflicts_with = "all")]
    pub(crate) affected: bool,
    /// Git base ref for --affected (default: main).
    #[arg(long, default_value = "main")]
    pub(crate) base: String,
    /// Ignore changed files matching this git-diff glob when evaluating
    /// `--affected` or `[git-ref]` filters. Can be passed multiple times.
    #[arg(long = "changed-files-ignore-pattern")]
    pub(crate) changed_files_ignore_pattern: Vec<String>,
    /// Treat changed files matching this git-diff glob as tests, so
    /// affected reverse fan-out skips dependents for test-only changes.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,
    /// Exit non-zero if no workspace package matches the filter set.
    /// Recommended in CI to catch typo'd filters early.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,
    /// Extra arguments passed to oxlint (e.g., --fix, src/).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct FmtArgs {
    /// Check formatting without writing (CI mode, exits non-zero if unformatted).
    #[arg(long)]
    pub(crate) check: bool,
    /// Run in all workspace packages. Mutually exclusive with filters
    /// and `--affected` — pick one selection mode.
    #[arg(long, conflicts_with_all = ["filter", "filter_prod", "affected"])]
    pub(crate) all: bool,
    /// Filter workspace packages with the grammar. Can be passed
    /// multiple times: `--filter foo --filter bar` unions the two sets.
    #[arg(long)]
    pub(crate) filter: Vec<String>,
    /// Filter workspace packages with production dependency closures.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,
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
    /// affected reverse fan-out skips dependents for test-only changes.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,
    /// Exit non-zero if no workspace package matches the filter set.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,
    /// Extra arguments passed to biome format.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct CheckArgs {
    /// Run in all workspace packages. Mutually exclusive with filters
    /// and `--affected` — pick one selection mode.
    #[arg(long, conflicts_with_all = ["filter", "filter_prod", "affected"])]
    pub(crate) all: bool,
    /// Filter workspace packages with the grammar. Can be passed
    /// multiple times: `--filter foo --filter bar` unions the two sets.
    #[arg(long)]
    pub(crate) filter: Vec<String>,
    /// Filter workspace packages with production dependency closures.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,
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
    /// affected reverse fan-out skips dependents for test-only changes.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,
    /// Exit non-zero if no workspace package matches the filter set.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,
    /// Type-check engine to run.
    #[arg(long, value_enum, default_value_t = CheckEngine::Tsc)]
    pub(crate) engine: CheckEngine,
    /// Extra arguments passed to the selected engine.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct BundleArgs {
    /// Run in all workspace packages. Mutually exclusive with filters
    /// and `--affected` — pick one selection mode.
    #[arg(long, conflicts_with_all = ["filter", "filter_prod", "affected"])]
    pub(crate) all: bool,
    /// Filter workspace packages with the grammar. Can be passed
    /// multiple times: `--filter foo --filter bar` unions the two sets.
    #[arg(long)]
    pub(crate) filter: Vec<String>,
    /// Filter workspace packages with production dependency closures.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,
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
    /// affected reverse fan-out skips dependents for test-only changes.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,
    /// Exit non-zero if no workspace package matches the filter set.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,
    /// Entry file to bundle.
    #[arg(long)]
    pub(crate) entry: Option<String>,
    /// Output directory for bundled files.
    #[arg(long)]
    pub(crate) out_dir: Option<String>,
    /// Explicit rolldown config path.
    #[arg(long)]
    pub(crate) config: Option<String>,
    /// Output format for the generated bundle.
    #[arg(long, value_enum)]
    pub(crate) format: Option<BundleFormat>,
    /// Target platform for the generated code.
    #[arg(long, value_enum)]
    pub(crate) platform: Option<BundlePlatform>,
    /// Minify the bundle output.
    #[arg(long)]
    pub(crate) minify: bool,
    /// Generate a sourcemap alongside the output.
    #[arg(long)]
    pub(crate) sourcemap: bool,
    /// Extra arguments passed through to rolldown.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct PackArgs {
    /// Run in all workspace packages. Mutually exclusive with filters
    /// and `--affected` — pick one selection mode.
    #[arg(long, conflicts_with_all = ["filter", "filter_prod", "affected"])]
    pub(crate) all: bool,
    /// Filter workspace packages with the grammar. Can be passed
    /// multiple times: `--filter foo --filter bar` unions the two sets.
    #[arg(long)]
    pub(crate) filter: Vec<String>,
    /// Filter workspace packages with production dependency closures.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,
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
    /// affected reverse fan-out skips dependents for test-only changes.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,
    /// Exit non-zero if no workspace package matches the filter set.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,
    /// Entry file to pack.
    #[arg(long)]
    pub(crate) entry: Option<String>,
    /// Output directory for packed files.
    #[arg(long)]
    pub(crate) out_dir: Option<String>,
    /// Explicit tsdown config path.
    #[arg(long)]
    pub(crate) config: Option<String>,
    /// Explicit tsconfig path.
    #[arg(long)]
    pub(crate) tsconfig: Option<String>,
    /// Target runtime for the generated code.
    #[arg(long)]
    pub(crate) target: Option<String>,
    /// Output format for the generated package build.
    #[arg(long, value_enum)]
    pub(crate) format: Option<BundleFormat>,
    /// Target platform for the generated code.
    #[arg(long, value_enum)]
    pub(crate) platform: Option<BundlePlatform>,
    /// Generate declaration files.
    #[arg(long)]
    pub(crate) dts: bool,
    /// Minify the packed output.
    #[arg(long)]
    pub(crate) minify: bool,
    /// Generate a sourcemap alongside the output.
    #[arg(long)]
    pub(crate) sourcemap: bool,
    /// Extra arguments passed through to tsdown.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct TestArgs {
    /// Run in all workspace packages. Mutually exclusive with filters
    /// and `--affected` — pick one selection mode.
    #[arg(long, conflicts_with_all = ["filter", "filter_prod", "affected"])]
    pub(crate) all: bool,
    /// Filter workspace packages with the grammar. Can be passed
    /// multiple times: `--filter foo --filter bar` unions the two sets.
    #[arg(long)]
    pub(crate) filter: Vec<String>,
    /// Filter workspace packages with production dependency closures.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,
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
    /// affected reverse fan-out skips dependents for test-only changes.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,
    /// Exit non-zero if no workspace package matches the filter set.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,
    /// Limit concurrently running workspace packages.
    #[arg(long = "workspace-concurrency", value_name = "N", value_parser = parse_workspace_concurrency)]
    pub(crate) workspace_concurrency: Option<std::num::NonZeroUsize>,
    /// Extra arguments passed to the test runner.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct BenchArgs {
    /// Run in all workspace packages. Mutually exclusive with filters
    /// and `--affected` — pick one selection mode.
    #[arg(long, conflicts_with_all = ["filter", "filter_prod", "affected"])]
    pub(crate) all: bool,
    /// Filter workspace packages with the grammar. Can be passed
    /// multiple times: `--filter foo --filter bar` unions the two sets.
    #[arg(long)]
    pub(crate) filter: Vec<String>,
    /// Filter workspace packages with production dependency closures.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,
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
    /// affected reverse fan-out skips dependents for test-only changes.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,
    /// Exit non-zero if no workspace package matches the filter set.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,
    /// Limit concurrently running workspace packages.
    #[arg(long = "workspace-concurrency", value_name = "N", value_parser = parse_workspace_concurrency)]
    pub(crate) workspace_concurrency: Option<std::num::NonZeroUsize>,
    /// Extra arguments passed to the bench runner.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct CiArgs {
    /// Omit dependency types from node_modules.
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) omit: Vec<InstallOmitCli>,

    /// Install production dependencies only.
    #[arg(long, alias = "production")]
    pub(crate) prod: bool,

    /// Install without network (use lockfile + global store only).
    #[arg(long)]
    pub(crate) offline: bool,

    /// Allow recently published packages (skip minimumReleaseAge check).
    #[arg(long)]
    pub(crate) allow_new: bool,

    /// Fail on tarball-URL deps that have no declared SRI integrity.
    #[arg(long)]
    pub(crate) strict_integrity: bool,

    /// Fail install when peer-dependency warnings or conflicts are detected.
    #[arg(
        long,
        id = "ci_strict_peer_dependencies",
        conflicts_with = "ci_no_strict_peer_dependencies"
    )]
    pub(crate) strict_peer_dependencies: bool,

    /// Disable strict peer-dependency failures for this install.
    #[arg(
        long,
        id = "ci_no_strict_peer_dependencies",
        conflicts_with = "ci_strict_peer_dependencies"
    )]
    pub(crate) no_strict_peer_dependencies: bool,

    /// Override the minimumReleaseAge cooldown for this install only.
    #[arg(long, value_name = "DUR")]
    pub(crate) min_release_age: Option<String>,

    /// Exempt a package name, exact version, or @scope/* from minimumReleaseAge.
    /// Repeatable. Alias selectors must use their canonical target name.
    #[arg(long, value_name = "SELECTOR")]
    pub(crate) min_release_age_exclude: Vec<String>,

    /// Skip the provenance-drift check for this package name.
    #[arg(long, value_name = "PKG")]
    pub(crate) ignore_provenance_drift: Vec<String>,

    /// Skip the provenance-drift check for every resolved package.
    #[arg(long)]
    pub(crate) ignore_provenance_drift_all: bool,

    /// Skip cryptographic Sigstore verification for this package name.
    #[arg(long, value_name = "PKG")]
    pub(crate) unverified_provenance: Vec<String>,

    /// Skip cryptographic Sigstore verification for every package.
    #[arg(long)]
    pub(crate) unverified_provenance_all: bool,

    /// Linking mode: `hoisted` or `isolated`.
    #[arg(long, value_enum)]
    pub(crate) linker: Option<LinkerCli>,

    /// Install package-published LPM.dev skills for this invocation.
    #[arg(long, id = "ci_skills", conflicts_with = "ci_no_skills")]
    pub(crate) skills: bool,

    /// Skip package-published LPM.dev skills auto-install.
    #[arg(long, id = "ci_no_skills", conflicts_with = "ci_skills")]
    pub(crate) no_skills: bool,

    /// Skip editor auto-integration.
    #[arg(long)]
    pub(crate) no_editor_setup: bool,

    /// Disable post-install security summary.
    #[arg(long)]
    pub(crate) no_security_summary: bool,

    /// Automatically run `lpm rebuild` for trusted packages after install.
    #[arg(long)]
    pub(crate) auto_build: bool,

    /// Use warning-only root and dependency engine checks for this invocation.
    #[arg(long)]
    pub(crate) no_engine_strict: bool,

    /// Run `lpm audit` once after a successful install.
    #[arg(
        long,
        id = "ci_audit_after_install",
        conflicts_with = "ci_no_audit_after_install"
    )]
    pub(crate) audit_after_install: bool,

    /// Suppress audit-after-install for this invocation.
    #[arg(
        long,
        id = "ci_no_audit_after_install",
        conflicts_with = "ci_audit_after_install"
    )]
    pub(crate) no_audit_after_install: bool,

    /// Lifecycle-script policy override for this invocation.
    #[arg(
        long,
        id = "ci_policy",
        value_name = "deny|allow|triage",
        conflicts_with_all = ["ci_yolo", "ci_triage_alias"],
    )]
    pub(crate) policy: Option<String>,

    /// Alias for `--policy=allow`.
    #[arg(long, id = "ci_yolo", conflicts_with_all = ["ci_policy", "ci_triage_alias"])]
    pub(crate) yolo: bool,

    /// Alias for `--policy=triage`.
    #[arg(long = "triage", id = "ci_triage_alias", conflicts_with_all = ["ci_policy", "ci_yolo"])]
    pub(crate) triage_alias: bool,

    /// Override the triage advisor for this run.
    #[arg(
        long,
        value_name = "none|claude-cli|codex|ollama",
        value_parser = parse_advisor_slug,
    )]
    pub(crate) advisor: Option<String>,

    /// Engage strict sandbox for lifecycle scripts.
    #[arg(
        long = "strict-sandbox",
        id = "ci_strict_sandbox",
        conflicts_with_all = ["ci_no_sandbox", "ci_paranoid"],
    )]
    pub(crate) strict_sandbox: bool,

    /// Alias for `--strict-sandbox`.
    #[arg(
        long = "paranoid",
        id = "ci_paranoid",
        conflicts_with_all = ["ci_no_sandbox", "ci_strict_sandbox"],
    )]
    pub(crate) paranoid: bool,

    /// Drop all containment for lifecycle scripts.
    #[arg(
        long = "no-sandbox",
        id = "ci_no_sandbox",
        conflicts_with_all = ["ci_strict_sandbox", "ci_paranoid"],
    )]
    pub(crate) no_sandbox: bool,
}

#[derive(Args)]
pub(crate) struct DevArgs {
    /// Enable local HTTPS with auto-generated certificates.
    #[arg(long)]
    pub(crate) https: bool,

    /// Expose localhost to the internet via LPM tunnel.
    #[arg(long)]
    pub(crate) tunnel: bool,

    /// Show network URLs and QR code for mobile testing.
    #[arg(long)]
    pub(crate) network: bool,

    /// Override the dev server port.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) port: Option<u16>,

    /// Custom hostname for the HTTPS certificate.
    #[arg(long)]
    pub(crate) host: Option<String>,

    /// Tunnel domain (e.g., acme-api.lpm.llc). Overrides lpm.json tunnel.domain.
    #[arg(long)]
    pub(crate) domain: Option<String>,

    /// Load a specific .env file by mode.
    #[arg(long)]
    pub(crate) env: Option<String>,

    /// Skip auto-opening browser after services are ready.
    #[arg(long)]
    pub(crate) no_open: bool,

    /// Skip auto-install even if dependencies are stale.
    #[arg(long)]
    pub(crate) no_install: bool,

    /// Disable tunnel even if configured in lpm.json.
    #[arg(long)]
    pub(crate) no_tunnel: bool,

    /// Disable HTTPS even if configured in lpm.json.
    #[arg(long)]
    pub(crate) no_https: bool,

    /// Skip environment variable schema validation.
    #[arg(long)]
    pub(crate) no_env_check: bool,

    /// Require auth token to access the tunnel URL (Pro/Org only).
    /// Generates a random token per session and prints it in the tunnel banner.
    #[arg(long)]
    pub(crate) tunnel_auth: bool,

    /// Suppress inline webhook output (webhooks still logged to disk).
    #[arg(long, short = 'q')]
    pub(crate) quiet: bool,

    /// Launch the TUI dashboard for multi-service log viewing and webhook inspection.
    #[arg(long, conflicts_with = "no_dashboard")]
    pub(crate) dashboard: bool,

    /// Force raw prefixed output instead of TUI dashboard.
    #[arg(long, conflicts_with = "dashboard")]
    pub(crate) no_dashboard: bool,

    /// Disable the browser inspector that auto-starts alongside `--tunnel`.
    ///
    /// The inspector is the same surface as `lpm tunnel inspect --ui` —
    /// real-time webhook capture, replay, snapshots. The dashboard's `o`
    /// key opens it in a browser; pass `--no-inspect` to skip starting it
    /// entirely. No-op without `--tunnel`.
    #[arg(long)]
    pub(crate) no_inspect: bool,

    /// Port for the inspector UI (default: auto-pick a free ephemeral port).
    ///
    /// When omitted, the inspector binds `127.0.0.1:0` and the OS picks an
    /// unused port — race-free against the dev server's own port. Pass an
    /// explicit value to bind that exact port strictly. No-op without
    /// `--tunnel`.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) inspect_port: Option<u16>,

    /// Pre-approve the trust-store install for `--https` (skips the prompt).
    /// Required in non-TTY contexts to avoid hanging on stdin.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,

    /// Serve the root CA over plain HTTP on an OS-assigned port so mobile
    /// devices on the LAN can bootstrap trust. Off by default — anyone on the
    /// LAN can grab the CA, so the flag is explicit.
    #[arg(long)]
    pub(crate) allow_ca_bootstrap: bool,

    /// Extra arguments passed to the dev script.
    #[arg(trailing_var_arg = true)]
    pub(crate) args: Vec<String>,
}

#[derive(Args)]
pub(crate) struct SelfUpdateArgs {
    /// Release channel to install. When omitted, stable installations
    /// follow stable and nightly installations follow nightly.
    #[arg(long, value_enum)]
    pub(crate) channel: Option<crate::release_channel::ReleaseChannel>,

    /// Bypass the 10-minute version-lookup cache and the
    /// post-failure cooldown. Forces a fresh probe regardless of
    /// recent state. Only affects the version check — not the
    /// upgrade itself, which always installs the resolved release.
    #[arg(long)]
    pub(crate) refresh: bool,
}

#[derive(Args)]
pub(crate) struct InternalTsTransformArgs {
    #[arg(long, hide = true)]
    pub(crate) persistent: bool,
}

#[derive(Args)]
pub(crate) struct CompletionsArgs {
    /// Target shell. One of: bash, zsh, fish, powershell, elvish.
    #[arg(value_enum)]
    pub(crate) shell: clap_complete::Shell,
}

#[derive(Args)]
pub(crate) struct SchemaArgs {
    /// Which schema to emit. Accepts `lpm.json` or `lpm.config.json`.
    pub(crate) kind: String,
    /// Write to this path instead of stdout.
    #[arg(long, short = 'o')]
    pub(crate) out: Option<String>,
}
