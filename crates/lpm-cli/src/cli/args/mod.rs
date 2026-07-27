use clap::{ArgAction, Parser, Subcommand, ValueEnum};

use crate::color_policy;

pub(in crate::cli) mod build;
pub(in crate::cli) mod lifecycle;
pub(in crate::cli) mod network;
mod parsers;
pub(in crate::cli) mod registry;
pub(in crate::cli) mod release;
pub(in crate::cli) mod security;

pub(crate) use registry::{SetupAction, StageCommands};
pub(crate) use release::{ReleaseCommands, ReleaseSelectionArgs};
pub(crate) use security::DoctorAction;

#[derive(Parser)]
#[command(
    name = "lpm",
    // We disable clap's auto-injected `--version` / `-V` flag so we can:
    //   (a) accept `-v` as an alias for `-V` (npm/pnpm/yarn convention,
    //       where `-v` prints the version), and
    //   (b) append the cached "update available" notice — clap's built-in
    //       version handler prints + exits before we get a chance to
    //       enrich the output.
    // The replacement is a top-level argv pre-check for `--version`
    // plus the short `-V` / `-v` clap flag below.
    disable_version_flag = true,
    about = "LPM — the package manager for modern software",
    long_about = "Rust-based LPM client. Fast, correct, registry-aware."
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Commands>,

    /// Print version and exit.
    ///
    /// Accepts `-V` and `-v`. Long `--version` is handled before clap
    /// parsing so subcommands like `info` and `download` can safely use
    /// `--version <package-version>`.
    #[arg(
        short = 'V',
        visible_short_alias = 'v',
        global = true,
        action = ArgAction::SetTrue,
    )]
    pub(crate) version_flag: bool,

    /// Use a specific auth token instead of the stored one.
    #[arg(long, global = true, env = "LPM_TOKEN")]
    pub(crate) token: Option<String>,

    /// Override the registry URL.
    #[arg(long, global = true, env = "LPM_REGISTRY_URL")]
    pub(crate) registry: Option<String>,

    /// Output as JSON (for CI/scripting).
    #[arg(long, global = true)]
    pub(crate) json: bool,

    /// Show verbose output (debug logging).
    ///
    /// Long form only — `-v` was reclaimed for `--version` to match
    /// npm/pnpm/yarn convention.
    #[arg(long, global = true)]
    pub(crate) verbose: bool,

    /// Allow insecure HTTP connections to non-localhost registries.
    #[arg(long, global = true)]
    pub(crate) insecure: bool,

    /// Color output mode. `auto` (default) honors `FORCE_COLOR`,
    /// `NO_COLOR`, then falls back to stdout TTY detection.
    #[arg(long, global = true, value_enum, default_value_t = color_policy::ColorChoice::Auto)]
    pub(crate) color: color_policy::ColorChoice,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutdatedRegistryScope {
    All,
    Lpm,
}

/// Linker mode as accepted by the `--linker` CLI flag. Clap clamps the input
/// at parse time so any unknown value fails before the command runs. Mirrors
/// `lpm_linker::LinkerMode::ACCEPTED_VALUES`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum LinkerCli {
    Isolated,
    Hoisted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum InstallOmitCli {
    Dev,
    Optional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CheckEngine {
    Tsc,
    Tsgo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum InitPackageTargetCli {
    Lpm,
    Npm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum BundleFormat {
    Esm,
    Cjs,
    Iife,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum BundlePlatform {
    Node,
    Browser,
    Neutral,
}

impl LinkerCli {
    pub(crate) fn into_linker_mode(self) -> lpm_linker::LinkerMode {
        match self {
            Self::Isolated => lpm_linker::LinkerMode::Isolated,
            Self::Hoisted => lpm_linker::LinkerMode::Hoisted,
        }
    }
}

// Linker override resolution moved to `linker_config` module + the
// install pipeline so every install entry point (top-level `lpm install`,
// `lpm add`, `lpm upgrade`, `lpm dev`, `lpm migrate`, `lpm deploy`,
// `lpm dlx`, `lpm install -g`, `lpm global update`, `lpm doctor --fix`)
// honors the same precedence chain. Top-level dispatch only translates
// the CLI flag — the rest of the chain is handled inside install.

#[derive(Subcommand)]
#[command(allow_external_subcommands = true)]
pub(crate) enum Commands {
    /// Show package information.
    Info(registry::InfoArgs),

    /// Search for packages.
    Search(registry::SearchArgs),

    /// Show quality report for a package.
    Quality(registry::QualityArgs),

    /// Show who you're logged in as.
    Whoami,

    /// Check registry health.
    Health,

    /// Download and extract a package tarball.
    Download(registry::DownloadArgs),

    /// Download packages from lpm.lock into the store without installing.
    Fetch(lifecycle::FetchArgs),

    /// Report unused dependencies and undeclared imports.
    Tidy(lifecycle::TidyArgs),

    /// Resolve dependency tree for packages.
    Resolve(lifecycle::ResolveArgs),

    /// Install dependencies from package.json, or add specific packages.
    ///
    /// SAVE POLICY
    ///
    /// By default, `lpm install <pkg>` saves `^resolvedVersion` to
    /// package.json. If you provide an explicit version or range, LPM
    /// preserves what you typed. Prereleases are saved exact for safety.
    ///
    ///   lpm install zod              → "zod": "^4.3.6"
    ///   lpm install zod@4.3.6        → "zod": "4.3.6"          (preserved)
    ///   lpm install zod@^4.3.0       → "zod": "^4.3.0"         (preserved)
    ///   lpm install zod@~4.3.6       → "zod": "~4.3.6"         (preserved)
    ///   lpm install zod@latest       → "zod": "^4.3.6"         (caret default)
    ///   lpm install zod@beta         → "zod": "4.4.0-beta.2"   (prerelease → exact)
    ///   lpm install zod@*            → "zod": "*"              (explicit wildcard)
    ///
    /// Use --exact, --tilde, or --save-prefix '<p>' to override the
    /// default for one invocation. Use ./lpm.toml (project) or
    /// ~/.lpm/config.toml (global) to set persistent defaults:
    ///
    ///   save-prefix = "^"   # one of "^", "~", or "" (exact, no prefix)
    ///   save-exact = false  # bool; true forces exact regardless of prefix
    ///
    /// Re-installing an existing dependency without a version or override
    /// flag refreshes lockfile/store state but does NOT rewrite the
    /// existing range — your "zod": "~4.3.6" stays put.
    #[command(visible_alias = "i", verbatim_doc_comment)]
    Install(lifecycle::InstallArgs),

    /// Remove packages from dependencies and node_modules.
    #[command(visible_aliases = ["un", "unlink"])]
    Uninstall(lifecycle::UninstallArgs),

    /// Add source files from a package into your project (shadcn-style).
    Add(lifecycle::AddArgs),

    /// Publish a package to the LPM registry.
    #[command(visible_alias = "p")]
    Publish(registry::PublishArgs),

    /// Bump package.json version, optionally committing and tagging it.
    Version(registry::VersionArgs),

    /// Plan, apply, or publish a workspace release.
    Release(release::ReleaseArgs),

    /// Stage packages for npm publishing.
    Stage(registry::StageArgs),

    /// Log in to a package registry.
    #[command(visible_alias = "l")]
    Login(registry::LoginArgs),

    /// Log out from a package registry.
    #[command(visible_alias = "lo")]
    Logout(registry::LogoutArgs),

    /// Configure project `.npmrc` for CI or local development.
    Setup(registry::SetupArgs),

    /// Rotate your auth token.
    #[command(name = "token-rotate")]
    TokenRotate,

    /// Check for newer versions of direct dependencies.
    ///
    /// By default this checks both `@lpm.dev/*` and npm dependencies
    /// listed in `package.json`.
    Outdated(lifecycle::OutdatedArgs),

    /// Upgrade outdated LPM dependencies to latest versions.
    ///
    /// TTY-aware: at a terminal, shows an interactive multiselect so you
    /// can pick per-package. In CI / piped output, runs non-interactively
    /// (today's behavior). Use `-y` to force non-interactive in a TTY,
    /// or `-i` to force interactive in a non-TTY context.
    Upgrade(lifecycle::UpgradeArgs),

    /// Initialize a new package.
    Init(lifecycle::InitArgs),

    /// Manage CLI configuration.
    Config(security::ConfigArgs),

    /// Inspect and test install-time policy extensions.
    Policy(security::PolicyArgs),

    /// Manage temporary approvals for guarded security weakeners.
    Security(security::SecurityArgs),

    /// Manage ephemeral caches under ~/.lpm/cache/ (metadata, tasks, dlx, mcp)
    /// and prune the global package store under ~/.lpm/store/.
    ///
    /// `lpm cache clean` wipes ephemeral caches only; `lpm cache prune`
    /// walks the global store and removes link entries + objects no
    /// longer reachable from any registered project, and sweeps any
    /// pending global-install tombstones from prior `lpm uninstall -g`
    /// runs. For a blunt store wipe, use `lpm store clean`.
    Cache(lifecycle::CacheArgs),

    /// Manage the global content-addressable package store.
    ///
    /// Actions: verify, path, clean. For reachability-aware orphan
    /// cleanup, use `lpm cache prune`.
    Store(lifecycle::StoreArgs),

    /// Inspect workspace catalog usage and resolved catalog provenance.
    Catalog(lifecycle::CatalogArgs),

    /// Manage globally-installed CLI packages under ~/.lpm/global/.
    ///
    /// Subcommands: `list` (with `--outdated`/`--verbose`), `bin`,
    /// `path <pkg>`, `link [path]`, `unlink <pkg>`, `remove <pkg>`
    /// (= `lpm uninstall -g <pkg>`), `update [<pkg>[@<spec>]]` (with `--dry-run`).
    Global(lifecycle::GlobalArgs),

    /// Inspect and manage `trustedDependencies` in package.json.
    ///
    ///: `lpm trust diff` shows how the current manifest's
    /// trust list differs from the last install's snapshot; `lpm trust
    /// prune` removes entries whose package is no longer installed.
    Trust(security::TrustArgs),

    /// Show pool revenue stats.
    Pool,

    /// Manage Agent Skills.
    Skills(lifecycle::SkillsArgs),

    /// Remove a source-delivered package (reverse of `add`).
    #[command(visible_alias = "rm")]
    Remove(lifecycle::RemoveArgs),

    /// Audit installed packages for security/quality issues.
    Audit(security::AuditArgs),

    /// Query installed packages using CSS-like selectors.
    ///
    /// Selectors target behavioral tags, state, and dependency relationships:
    ///   :eval, :network, :fs, :shell, :child-process, :native, :crypto,
    ///   :dynamic-require, :env, :ws, :obfuscated, :high-entropy, :minified,
    ///   :telemetry, :url-strings, :trivial, :protestware, :git-dep, :http-dep,
    ///   :wildcard-dep, :copyleft, :no-license, :scripts, :built, :vulnerable,
    ///   :deprecated, :lpm, :npm, :critical, :high, :medium, :info
    ///
    /// Combinators: :a:b (AND), :a,:b (OR), :not(:a), #name, :root > :child
    Query(security::QueryArgs),

    /// Inventory installed dependency licenses and enforce policy gates.
    Licenses(security::LicensesArgs),

    /// Execute dependency lifecycle scripts for installed packages (phase 2 of install).
    ///
    /// `lpm install` runs root-project lifecycle scripts on bare installs.
    /// Dependency lifecycle scripts remain separate: `lpm rebuild` selectively
    /// runs them based on the trust policy in `package.json`.
    ///
    /// Executed phases (in order): `preinstall`, `install`, `postinstall`.
    /// Other dependency lifecycle names like `prepare` / `prepublishOnly` are
    /// recognized for detection and audit, but never executed by the dependency
    /// rebuild pipeline.
    ///
    /// Scripts run inside the default sandbox — filesystem-write
    /// containment + env scrubbing, outbound network allowed. Strict mode
    /// (network denial) is opt-in via `--strict-sandbox` / `--paranoid`,
    /// `[sandbox] mode = "strict"` in `~/.lpm/config.toml` / `./lpm.toml`,
    /// or `LPM_STRICT_SANDBOX=1`. The escape hatch is `--no-sandbox`, which
    /// drops both containment AND env scrubbing in a single flag.
    ///
    /// Matches `npm rebuild` / `pnpm rebuild`.
    Rebuild(lifecycle::RebuildArgs),

    /// Health check: verify project state, runtime, store, and (with
    /// `--all`) auth, registry, tunnel, tooling, plugins, globals,
    /// sandbox, and full manifest-compat.
    ///
    /// Default: a fast, local-only "why is this project broken right
    /// now?" pass — no registry probe, no `whoami`, no tunnel lookup,
    /// no lint / fmt subprocess, no plugin update fetch. Pass `--all`
    /// for the full sweep across every catalog row.
    ///
    /// Subcommands target the inventory surface (always local):
    ///
    ///   lpm doctor list                — dump every code doctor can emit
    ///   lpm doctor list --code <code>  — show one entry
    ///   lpm doctor list --category Tunnel  — filter by category
    Doctor(security::DoctorArgs),

    /// Configure Swift Package Manager to use LPM as a package registry (SE-0292).
    #[command(name = "swift-registry")]
    SwiftRegistry(registry::SwiftRegistryArgs),

    /// Manage MCP servers (setup, remove, status).
    Mcp(security::McpArgs),

    /// Install, pin, and manage Node.js versions (e.g., lpm use node@22).
    ///
    /// `lpm use node@22` installs Node 22 and pins it in lpm.json.
    /// Scripts then auto-use the pinned version via PATH injection.
    Use(lifecycle::UseArgs),

    /// Manage project environment variables and secrets.
    ///
    /// Local-file management (`lpm env init`, `ls`, `set`, `get`, `delete`,
    /// `import`, `export`, `print`, `copy`, `check`) plus cloud sync
    /// (`pull`, `push`, `share`, `pair`, `diff`, `validate`), platform
    /// integrations (`push --to <platform>`, `pull --from <platform>`,
    /// `connect`, `status`), and OIDC policies (`oidc allow`, `oidc list`,
    /// `oidc pull`).
    Env(network::EnvArgs),

    /// Run script(s) from package.json.
    Run(network::RunArgs),

    /// Run a project-local binary from node_modules/.bin.
    Exec(network::ExecArgs),

    #[command(name = "__run-file", hide = true)]
    RunFile(network::RunFileArgs),

    /// Run a package binary without installing it into the project.
    Dlx(network::DlxArgs),

    /// Materialize a single workspace member's deploy closure into a
    /// self-contained output directory ready for `COPY --from=pruned` in a
    /// Dockerfile.
    ///
    /// The deploy output contains:
    /// - The targeted member's source files (excluding `.env*`, `node_modules`,
    ///   `.git`, and other LPM-internal state)
    /// - Local workspace dependencies needed by the selected dependency mode
    /// - A deploy-local store rooted under the output directory
    /// - A `node_modules/` populated by running the install pipeline at the
    ///   output directory
    /// - A `lpm.lock` pruned for the deploy output's dep tree
    ///
    /// **Constraints:**
    /// - `--filter` is required and must match exactly one workspace member
    /// - The output directory must be outside the workspace tree
    /// - `--prod` is the default dependency mode; `--dev` deploys dev deps only
    ///
    /// **Example:**
    /// ```dockerfile
    /// FROM workspace as pruned
    /// RUN lpm deploy /prod/api --filter api
    /// FROM node:20-alpine
    /// COPY --from=pruned /prod/api /app
    /// ```
    Deploy(lifecycle::DeployArgs),

    /// Review and approve packages whose lifecycle scripts were blocked by
    /// LPM's default-deny security posture.
    ///
    /// This command pairs with the post-install
    /// warning emitted by `lpm install` when packages with `preinstall` /
    /// `install` / `postinstall` scripts are not yet covered by an existing
    /// strict approval. Approvals are bound to
    /// `{name, version, integrity, script_hash}` so that ANY change to the
    /// script body (or to the package tarball) re-opens the package for
    /// review on the next install.
    ///
    /// **Modes:**
    /// - `lpm approve-scripts`               — interactive walk
    /// - `lpm approve-scripts --list`        — read-only listing
    /// - `lpm approve-scripts --yes`         — bulk approve (loud)
    /// - `lpm approve-scripts <pkg>`         — approve a specific package
    /// - `lpm approve-scripts --json`        — structured output for agents
    /// - `lpm approve-scripts --global`      — review global installs
    #[command(name = "approve-scripts")]
    ApproveScripts(security::ApproveScriptsArgs),

    /// Generate a local patch for an installed package, `patch-package` style.
    ///
    /// Extracts a clean copy of the global store entry to a temp staging
    /// directory and prints the path. Edit the files in that directory,
    /// then run `lpm patch-commit <staging_dir>` to produce a unified
    /// diff under `patches/` and register it in `package.json` under
    /// `lpm.patchedDependencies`. The patch is bound to the original
    /// store integrity — drift on a future install is a hard error.
    #[command(name = "patch")]
    Patch(lifecycle::PatchArgs),

    /// Finalize a patch staging directory created by `lpm patch`.
    ///
    /// Reads the staging breadcrumb, generates a unified diff against
    /// the store baseline, writes `patches/<key>.patch`, and updates
    /// `package.json :: lpm.patchedDependencies`.
    ///
    ///.
    #[command(name = "patch-commit")]
    PatchCommit(lifecycle::PatchCommitArgs),

    /// Remove one or more registered local patches.
    ///
    /// Removes entries from `package.json :: lpm.patchedDependencies`.
    /// Patch files are deleted when they are safely inside the project and
    /// no remaining patch entry still references them.
    #[command(name = "patch-remove")]
    PatchRemove(lifecycle::PatchRemoveArgs),

    /// Generate a Software Bill of Materials from lpm.lock.
    #[command(name = "sbom")]
    Sbom(security::SbomArgs),

    /// Preview the workspace package set that a `--filter` expression would
    /// select. Read-only — never executes scripts or modifies state.
    ///
    /// Drives the same `FilterEngine` as `lpm run --filter`, so the result
    /// is byte-identical to what `lpm run` would target.
    ///
    /// Default output is a terse list of matched package names, one per line.
    /// Pass `--explain` for the full per-package trace showing which filter
    /// matched each package and how (direct match vs closure expansion).
    Filter(lifecycle::FilterArgs),

    /// Manage tool plugins (list, outdated, update, remove).
    Plugin(build::PluginArgs),

    /// Lint source files (powered by Oxlint, lazy-downloaded on first use).
    Lint(build::LintArgs),

    /// Format source files (powered by Biome, lazy-downloaded on first use).
    Fmt(build::FmtArgs),

    /// Type-check the project (runs tsc --noEmit by default).
    Check(build::CheckArgs),

    /// Bundle the project with Rolldown through an LPM-owned command surface.
    Bundle(build::BundleArgs),

    /// Build package-oriented library output through a stable LPM command surface.
    Pack(build::PackArgs),

    /// Run tests (auto-detects vitest/jest/mocha).
    ///
    /// Workspace flags (`--all` / `--filter` / `--affected`) target the test
    /// suite across multiple workspace members. The trailing `args` are
    /// forwarded to the per-member runner. To pass `--all` / `--filter` etc.
    /// to the runner itself (e.g. bun's `--filter`), prefix with `--`:
    /// `lpm test -- --filter pattern`.
    Test(build::TestArgs),

    /// Run benchmarks (auto-detects vitest bench).
    ///
    /// Workspace flags behave the same as `lpm test`. To forward `--all`
    /// / `--filter` etc. to the bench runner itself, prefix with `--`.
    Bench(build::BenchArgs),

    /// Frozen install for CI.
    Ci(build::CiArgs),

    /// Start the dev server with optional HTTPS, tunnel, and network features.
    ///
    /// Auto-detects features from lpm.json: tunnel.domain enables --tunnel,
    /// services enables orchestrator. Dependencies auto-installed if stale.
    Dev(build::DevArgs),

    /// Manage local HTTPS certificates (status, trust, uninstall, generate, rotate, reconcile).
    Cert(security::CertArgs),

    /// Explain why a package is installed.
    Why(lifecycle::WhyArgs),

    /// Visualize the dependency graph (tree, DOT, Mermaid, JSON, stats, HTML).
    #[command(visible_alias = "ls")]
    Graph(lifecycle::GraphArgs),

    /// Manage dev service ports and inspect listening processes.
    Ports(network::PortsArgs),

    /// Manage LPM hosts-file entries.
    Hosts(network::HostsArgs),

    /// Manage the local-domain proxy daemon.
    Proxy(network::ProxyArgs),

    /// Expose a local port to the internet via LPM tunnel.
    ///
    /// Actions: (default) start, claim, unclaim, list, domains, inspect, replay, log
    /// Examples:
    ///   lpm tunnel 3000                       — start tunnel on port 3000
    ///   lpm tunnel claim acme-api.lpm.llc     — claim a tunnel domain
    ///   lpm tunnel unclaim acme-api.lpm.llc   — release a tunnel domain
    ///   lpm tunnel list                       — list your claimed domains
    ///   lpm tunnel domains                    — list available base domains
    ///   lpm tunnel inspect                    — show captured webhooks
    ///   lpm tunnel replay 3                   — replay webhook #3
    ///   lpm tunnel log                        — browse webhook event log
    Tunnel(network::TunnelArgs),

    /// Migrate from npm/yarn/pnpm/bun to LPM.
    Migrate(lifecycle::MigrateArgs),

    /// Internal macOS vault app surface.
    #[command(hide = true)]
    Vault(security::VaultArgs),

    /// Update LPM to the latest version.
    ///
    /// Detects the installation channel from the executable path
    /// (npm, Homebrew, cargo, or standalone) and runs the matching
    /// upgrade command. Version discovery probes the npm registry
    /// first and falls back to GitHub Releases — no token required
    /// for either path on the common case.
    #[command(name = "self-update")]
    SelfUpdate(build::SelfUpdateArgs),

    /// hidden subcommand for background update cache refresh.
    /// Spawned as a detached child process by the parent — never user-facing.
    #[command(name = "internal-update-check", hide = true)]
    InternalUpdateCheck,

    /// Hidden sudo helper for hosts-file mutation.
    #[command(name = "internal-hosts-file", hide = true)]
    InternalHostsFile(network::InternalHostsFileArgs),

    /// Hidden OXC transform helper for the LPM TypeScript runtime.
    #[command(name = "internal-ts-transform", hide = true)]
    InternalTsTransform(build::InternalTsTransformArgs),

    /// Generate a shell completion script.
    ///
    /// Pipe the output into your shell's completion-load path:
    ///
    /// ```text
    /// lpm completions zsh        > "${fpath[1]}/_lpm"
    /// lpm completions bash       > /etc/bash_completion.d/lpm
    /// lpm completions fish       > ~/.config/fish/completions/lpm.fish
    /// lpm completions powershell | Out-String | Invoke-Expression
    /// ```
    Completions(build::CompletionsArgs),

    /// Emit the JSON Schema for an LPM config file.
    ///
    /// Auto-derived for typed schemas (`lpm.json`); hand-authored for
    /// the dynamic ones (`lpm.config.json`). The same schemas are
    /// served at `https://cli.lpm.dev/schemas/<name>.json` for editor
    /// auto-discovery, with `https://lpm.dev/schemas/<name>.json` kept
    /// as a compatibility alias.
    ///
    /// Examples:
    /// ```bash
    /// lpm schema lpm.json                  # print to stdout
    /// lpm schema lpm.json -o schema.json   # write to file
    /// lpm schema lpm.config.json
    /// ```
    Schema(build::SchemaArgs),

    /// Catch-all: unknown subcommands are tried as package.json scripts.
    /// e.g., `lpm dev` runs the "dev" script if no built-in command matches.
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[cfg(test)]
mod tests;
