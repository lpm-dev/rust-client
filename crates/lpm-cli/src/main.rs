use clap::{Parser, Subcommand};
use miette::{IntoDiagnostic, Result};
use owo_colors::OwoColorize;

mod auth;
pub mod build_state;
mod commands;
pub mod constraints;
pub mod editor_skills;
mod graph_render;
mod import_rewriter;
pub mod intelligence;
mod oidc;
mod output;
mod provenance;
mod quality;
pub mod security_check;
mod sigstore;
mod swift_manifest;
mod update_check;
mod xcode_project;

#[derive(Parser)]
#[command(
    name = "lpm",
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

        /// Force full re-install: bypass the fast-exit hash check, skip the
        /// lockfile (force fresh resolution from registry), re-download all
        /// packages (even if already in the global store), and re-link
        /// node_modules from scratch.
        #[arg(long)]
        force: bool,

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

        /// Disable post-install security summary (faster CI).
        #[arg(long)]
        no_security_summary: bool,

        /// Automatically run `lpm build` for trusted packages after install.
        #[arg(long)]
        auto_build: bool,

        /// Phase 32 Phase 2: filter workspace members. Same grammar as
        /// `lpm run --filter`. Only meaningful when adding packages — bare
        /// `lpm install` (no packages) ignores this flag.
        ///
        /// Example: `lpm install react --filter web` adds react to
        /// `packages/web/package.json` and runs install at the workspace root.
        ///
        /// Mutually exclusive with `-w`.
        #[arg(long)]
        filter: Vec<String>,

        /// Phase 32 Phase 2: target the workspace root `package.json` instead
        /// of the current member. Mutually exclusive with `--filter`. Use
        /// when adding tooling packages that belong at the root rather than
        /// in a specific member (e.g., shared dev dependencies).
        #[arg(short = 'w', long = "workspace-root")]
        workspace_root: bool,

        /// Phase 32 Phase 2: exit non-zero if `--filter` matches no members.
        /// Recommended in CI to catch typo'd filters.
        #[arg(long)]
        fail_if_no_match: bool,
    },

    /// Remove packages from dependencies and node_modules.
    #[command(visible_aliases = ["un", "unlink"])]
    Uninstall {
        /// Packages to remove (e.g., express, @lpm.dev/neo.highlight).
        packages: Vec<String>,

        /// Phase 32 Phase 2: filter workspace members. Same grammar as
        /// `lpm run --filter`. Mutually exclusive with `-w`.
        ///
        /// Example: `lpm uninstall lodash --filter web` removes lodash from
        /// `packages/web/package.json` only.
        #[arg(long)]
        filter: Vec<String>,

        /// Phase 32 Phase 2: target the workspace root `package.json` instead
        /// of the current member.
        #[arg(short = 'w', long = "workspace-root")]
        workspace_root: bool,

        /// Phase 32 Phase 2: exit non-zero if `--filter` matches no members.
        #[arg(long)]
        fail_if_no_match: bool,
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

        /// Import alias prefix (e.g., @/components). Overrides auto-detection.
        #[arg(long)]
        alias: Option<String>,

        /// Swift SPM target name (e.g., MyAppTarget).
        #[arg(long)]
        target: Option<String>,
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

        /// Generate and require Sigstore provenance (CI with OIDC only). Fails if provenance cannot be produced.
        #[arg(long)]
        provenance: bool,

        /// Minimum quality score required to publish (0-100).
        #[arg(long)]
        min_score: Option<u32>,

        /// Skip pre-publish secret scanning (not recommended).
        #[arg(long)]
        allow_secrets: bool,

        /// Publish to npm registry.
        #[arg(long)]
        npm: bool,

        /// Publish to LPM registry (default if no other registry specified).
        #[arg(long)]
        lpm: bool,

        /// Publish to GitHub Packages.
        #[arg(long)]
        github: bool,

        /// Publish to GitLab Packages (requires publish.gitlab.projectId in lpm.json).
        #[arg(long)]
        gitlab: bool,

        /// Publish to a custom npm-compatible registry.
        #[arg(long = "publish-registry", value_name = "URL")]
        publish_registry: Option<String>,
    },

    /// Log in to a package registry.
    #[command(visible_alias = "l")]
    Login {
        /// Log in to npm registry with a granular access token.
        #[arg(long)]
        npm: bool,

        /// Log in to GitHub Packages with a personal access token.
        #[arg(long)]
        github: bool,

        /// Log in to GitLab Packages with a personal/deploy/job token.
        #[arg(long)]
        gitlab: bool,

        /// Log in to a custom npm-compatible registry.
        #[arg(long = "login-registry", value_name = "URL")]
        login_registry: Option<String>,

        /// Auth token (required for --npm, --github, --registry).
        #[arg(long)]
        token: Option<String>,
    },

    /// Log out from a package registry.
    #[command(visible_alias = "lo")]
    Logout {
        /// Also revoke the LPM token on the server.
        #[arg(long)]
        revoke: bool,

        /// Log out from npm registry.
        #[arg(long)]
        npm: bool,

        /// Log out from GitHub Packages.
        #[arg(long)]
        github: bool,

        /// Log out from GitLab Packages.
        #[arg(long)]
        gitlab: bool,

        /// Log out from all registries (LPM + npm + GitHub + GitLab + custom).
        #[arg(long)]
        all: bool,

        /// Log out from a custom npm-compatible registry.
        #[arg(long = "logout-registry", value_name = "URL")]
        logout_registry: Option<String>,
    },

    /// Generate .npmrc for CI/CD.
    Setup {
        /// Override the registry URL for .npmrc (default: current --registry or LPM_REGISTRY_URL).
        #[arg(short = 'r', long)]
        registry: Option<String>,

        /// Use OIDC token exchange instead of stored token.
        #[arg(long)]
        oidc: bool,

        /// Route all npm traffic through lpm.dev (Pro/Org feature for dependency visibility).
        #[arg(long, conflicts_with = "scoped")]
        proxy: bool,

        /// Use scoped registry (@lpm.dev:registry=). This is the default.
        #[arg(long, conflicts_with = "proxy")]
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

        /// Auto-fix issues found during verify (e.g., refresh stale security caches).
        #[arg(long)]
        fix: bool,
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

        /// CI exit code policy: what triggers a non-zero exit code.
        ///   vuln     — only confirmed vulnerabilities (OSV/registry)
        ///   behavior — only critical/high behavioral flags
        ///   all      — either vulnerabilities or behavioral flags (default)
        #[arg(long, value_name = "POLICY")]
        fail_on: Option<String>,

        /// Scan installed packages for hardcoded secrets (API keys, tokens, private keys).
        #[arg(long)]
        secrets: bool,
    },

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
    Query {
        /// Selector expression (e.g., ":eval", ":scripts:not(:built)", ":root > :network").
        selector: Option<String>,

        /// Show tag counts across all packages, grouped by severity.
        #[arg(long)]
        count: bool,

        /// Show tag details for each match.
        #[arg(long, short = 'V')]
        query_verbose: bool,

        /// Exit with code 1 if ANY packages match (CI gate).
        #[arg(long)]
        assert_none: bool,

        /// Output format: list (default) or mermaid (dependency subgraph diagram).
        #[arg(long, default_value = "list")]
        format: String,
    },

    /// Execute lifecycle scripts for installed packages (phase 2 of install).
    ///
    /// `lpm install` downloads and links packages without running any scripts.
    /// `lpm build` selectively runs lifecycle scripts (postinstall, etc.)
    /// based on the trust policy in package.json.
    Build {
        /// Specific packages to build. If omitted, builds all trusted packages.
        packages: Vec<String>,

        /// Build ALL packages with scripts (dangerous — bypasses trust policy).
        #[arg(long)]
        all: bool,

        /// Preview what would be built without executing scripts.
        #[arg(long)]
        dry_run: bool,

        /// Re-run scripts even for already-built packages.
        #[arg(long)]
        rebuild: bool,

        /// Timeout per script in seconds (default: 300 = 5 minutes).
        #[arg(long)]
        timeout: Option<u64>,

        /// Pass full environment to scripts without stripping credentials.
        /// WARNING: Exposes LPM_TOKEN, NPM_TOKEN, GITHUB_TOKEN, etc. to scripts.
        #[arg(long)]
        unsafe_full_env: bool,

        /// Refuse to run ANY scripts, even trusted ones.
        #[arg(long)]
        deny_all: bool,
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

        /// Route all npm traffic through lpm.dev (Pro/Org feature for dependency visibility).
        #[arg(long, conflicts_with = "scoped")]
        proxy: bool,

        /// Use scoped registry (@lpm.dev:registry=). This is the default.
        #[arg(long, conflicts_with = "proxy")]
        scoped: bool,
    },

    /// Install, pin, and manage Node.js versions (e.g., lpm use node@22).
    ///
    /// `lpm use node@22` installs Node 22 and pins it in lpm.json.
    /// Scripts then auto-use the pinned version via PATH injection.
    Use {
        /// Runtime and version spec (e.g., node@22, node@lts, 22.5.0), or "vars" for env management.
        spec: Option<String>,

        /// List installed runtime versions.
        #[arg(long)]
        list: bool,

        /// Pin only (skip install if already installed).
        #[arg(long)]
        pin: bool,

        /// Extra arguments (passed through to vars subcommands like set, get, print, example).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra: Vec<String>,
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

        /// Filter workspace packages with the Phase 32 grammar. Can be passed
        /// multiple times: `--filter foo --filter bar` unions the two sets.
        ///
        /// Grammar: exact name (`foo`), glob (`@scope/*`, `foo-*`),
        /// path glob (`./apps/*`), path exact (`{./apps/web}`),
        /// git ref (`[origin/main]`), forward closure (`foo...`, `foo^...`),
        /// reverse closure (`...foo`, `...^foo`), exclusion (`!foo`).
        ///
        /// Note: Phase 32 removed the legacy substring matcher per design
        /// decision D2. `--filter core` no longer matches `@babel/core` —
        /// write `--filter '*/core'` for that.
        #[arg(long)]
        filter: Vec<String>,

        /// Exit with a non-zero status if no workspace package matches the
        /// filter set. Recommended in CI to catch typo'd filters early.
        #[arg(long)]
        fail_if_no_match: bool,

        /// Run only in packages affected by git changes (vs base branch).
        #[arg(long)]
        affected: bool,

        /// Git base ref for --affected (default: main).
        #[arg(long, default_value = "main")]
        base: String,

        /// Disable task caching (force re-execution).
        #[arg(long)]
        no_cache: bool,

        /// Skip environment variable schema validation.
        #[arg(long)]
        no_env_check: bool,

        /// Re-run on file changes.
        #[arg(long)]
        watch: bool,

        /// Extra arguments passed to scripts (after --).
        #[arg(last = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Execute a file directly (auto-detects runtime: node for .js, tsx for .ts).
    Exec {
        /// File to execute (e.g., src/seed.ts, scripts/migrate.js).
        file: String,
        /// Skip environment variable schema validation.
        #[arg(long)]
        no_env_check: bool,
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

    /// Materialize a single workspace member's production closure into a
    /// self-contained output directory ready for `COPY --from=pruned` in a
    /// Dockerfile.
    ///
    /// Phase 32 Phase 3. The deploy output contains:
    /// - The targeted member's source files (excluding `.env*`, `node_modules`,
    ///   `.git`, and other LPM-internal state)
    /// - A `package.json` with `workspace:*` references rewritten to concrete
    ///   versions
    /// - A `node_modules/` populated by running the install pipeline at the
    ///   output directory
    /// - A `lpm.lock` for the deploy output's dep tree
    ///
    /// **Constraints:**
    /// - `--filter` is required and must match exactly one workspace member
    /// - The output directory must be outside the workspace tree
    /// - Workspace members referenced via `workspace:*` must be PUBLISHED to
    ///   the registry (the resolver has no local-package handling). Phase 12+
    ///   will add unpublished workspace dep injection.
    ///
    /// **Example:**
    /// ```dockerfile
    /// FROM workspace as pruned
    /// RUN lpm deploy /prod/api --filter api
    /// FROM node:20-alpine
    /// COPY --from=pruned /prod/api /app
    /// ```
    Deploy {
        /// Output directory (e.g., `/prod/api`). Must be outside the workspace.
        output: String,

        /// Filter expression identifying the member to deploy. Must match
        /// exactly one workspace member. Same grammar as `lpm run --filter`.
        #[arg(long, required = true)]
        filter: Vec<String>,

        /// Overwrite the output directory if it is non-empty. Without this
        /// flag, deploy refuses to write into a non-empty directory.
        #[arg(long)]
        force: bool,

        /// Show what would be deployed without making any filesystem changes.
        #[arg(long)]
        dry_run: bool,
    },

    /// Review and approve packages whose lifecycle scripts were blocked by
    /// LPM's default-deny security posture.
    ///
    /// **Phase 32 Phase 4.** This command pairs with the post-install
    /// warning emitted by `lpm install` when packages with `preinstall` /
    /// `install` / `postinstall` scripts are not yet covered by an existing
    /// strict approval. Approvals are bound to
    /// `{name, version, integrity, script_hash}` so that ANY change to the
    /// script body (or to the package tarball) re-opens the package for
    /// review on the next install.
    ///
    /// **Modes:**
    /// - `lpm approve-builds`               — interactive walk
    /// - `lpm approve-builds --list`        — read-only listing
    /// - `lpm approve-builds --yes`         — bulk approve (loud)
    /// - `lpm approve-builds <pkg>`         — approve a specific package
    /// - `lpm approve-builds --json`        — structured output for agents
    #[command(name = "approve-builds")]
    ApproveBuilds {
        /// Approve a specific package directly. Accepts `name` or
        /// `name@version`. Skips the interactive walk for that package.
        package: Option<String>,

        /// Bulk-approve every blocked package without per-package review.
        /// Loud — emits a warning banner. Mutually exclusive with `--list`.
        #[arg(long, conflicts_with = "list")]
        yes: bool,

        /// Read-only listing of the blocked set. No prompts, no mutations.
        /// Mutually exclusive with `--yes` and with the `package` argument.
        #[arg(long, conflicts_with = "yes")]
        list: bool,
    },

    /// Preview the workspace package set that a `--filter` expression would
    /// select. Read-only — never executes scripts or modifies state.
    ///
    /// Drives the same `FilterEngine` as `lpm run --filter`, so the result
    /// is byte-identical to what `lpm run` would target.
    ///
    /// Default output is a terse list of matched package names, one per line.
    /// Pass `--explain` for the full per-package trace showing which filter
    /// matched each package and how (direct match vs closure expansion).
    Filter {
        /// Filter expressions. Multiple expressions union; use `!expr` to
        /// exclude. Same grammar as `lpm run --filter`.
        #[arg(required = true)]
        exprs: Vec<String>,

        /// Show the full structured selection trace (which filter matched
        /// each package and how). Without this flag, output is a terse name
        /// list suitable for piping into shell tools.
        #[arg(long)]
        explain: bool,

        /// Exit non-zero if no packages matched.
        #[arg(long)]
        fail_if_no_match: bool,
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
        /// Run only in packages affected by git changes (vs base branch).
        #[arg(long, conflicts_with = "all")]
        affected: bool,
        /// Git base ref for --affected (default: main).
        #[arg(long, default_value = "main")]
        base: String,
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
        /// Run only in packages affected by git changes (vs base branch).
        #[arg(long, conflicts_with = "all")]
        affected: bool,
        /// Git base ref for --affected (default: main).
        #[arg(long, default_value = "main")]
        base: String,
        /// Extra arguments passed to biome format.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Type-check the project (runs tsc --noEmit).
    Check {
        /// Run in all workspace packages.
        #[arg(long)]
        all: bool,
        /// Run only in packages affected by git changes (vs base branch).
        #[arg(long, conflicts_with = "all")]
        affected: bool,
        /// Git base ref for --affected (default: main).
        #[arg(long, default_value = "main")]
        base: String,
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

    /// CI/CD helpers: load env vars, setup OIDC, generate workflow YAML.
    Ci {
        /// Action: env, setup.
        action: String,
        /// Extra arguments.
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

        /// Skip environment variable schema validation.
        #[arg(long)]
        no_env_check: bool,

        /// Require auth token to access the tunnel URL (Pro/Org only).
        /// Generates a random token per session and prints it in the tunnel banner.
        #[arg(long)]
        tunnel_auth: bool,

        /// Suppress inline webhook output (webhooks still logged to disk).
        #[arg(long, short = 'q')]
        quiet: bool,

        /// Launch the TUI dashboard for multi-service log viewing and webhook inspection.
        #[arg(long, conflicts_with = "no_dashboard")]
        dashboard: bool,

        /// Force raw prefixed output instead of TUI dashboard.
        #[arg(long, conflicts_with = "dashboard")]
        no_dashboard: bool,

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
        /// Package to show subtree for (optional — shows full graph if omitted).
        #[arg(value_name = "PACKAGE")]
        package: Option<String>,

        /// Output format: tree (default), dot, mermaid, json, stats, html.
        #[arg(long, default_value = "tree", value_parser = ["tree", "dot", "mermaid", "json", "stats", "html"])]
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
        #[arg(long, conflicts_with = "dev")]
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
    Tunnel {
        /// Action or port number. Actions: claim, unclaim, list, domains, inspect, replay, log.
        /// If a number, starts a tunnel on that port.
        #[arg(default_value = "3000")]
        action: String,

        /// Full tunnel domain (e.g., acme-api.lpm.llc) for claim/unclaim/start.
        domain: Option<String>,

        /// Organization slug (for org tunnel domains).
        #[arg(long)]
        org: Option<String>,

        /// Require auth token to access the tunnel URL (Pro/Org only).
        #[arg(long)]
        tunnel_auth: bool,

        /// Auto-acknowledge webhooks when the local server is down.
        /// Returns 200 OK to prevent provider retries and endpoint deactivation.
        #[arg(long)]
        auto_ack: bool,

        /// Name for this tunnel session (visible in inspector session list).
        #[arg(long)]
        session: Option<String>,

        /// Disable the inspector UI (default: inspector starts automatically).
        #[arg(long)]
        no_inspect: bool,

        /// Port for the inspector UI (default: 4400).
        #[arg(long, default_value_t = lpm_inspect::DEFAULT_PORT)]
        inspect_port: u16,

        /// Extra arguments for webhook subcommands (--last, --filter, --status, etc.).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Migrate from npm/yarn/pnpm/bun to LPM.
    Migrate {
        /// Skip build+test verification after migration.
        #[arg(long)]
        skip_verify: bool,

        /// Don't configure .npmrc for the LPM registry.
        #[arg(long)]
        no_npmrc: bool,

        /// Don't show CI template hint (or generate with --ci).
        #[arg(long)]
        no_ci: bool,

        /// Generate a CI workflow template for the detected platform.
        #[arg(long)]
        ci: bool,

        /// Don't run `lpm install` after conversion (lockfile-only migration).
        #[arg(long)]
        no_install: bool,

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

/// Attempt silent token refresh using the stored refresh token (Feature 44 Part B).
/// Returns the new access token if successful, None otherwise.
async fn try_silent_refresh(registry_url: &str) -> Option<String> {
    let refresh_token = auth::get_refresh_token(registry_url)?;

    // Compute device fingerprint (same as login)
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let device_fingerprint = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(
            format!("{hostname}:{username}:lpm-cli").as_bytes(),
        ))
    };

    let refresh_url = format!("{registry_url}/api/cli/refresh");
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;
    let resp = http_client
        .post(&refresh_url)
        .json(&serde_json::json!({
            "refreshToken": refresh_token,
            "deviceFingerprint": device_fingerprint,
        }))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        tracing::debug!("silent refresh failed: {}", resp.status());
        // If 401, the refresh token is invalid/revoked — clear it
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            auth::clear_refresh_token(registry_url);
        }
        return None;
    }

    let data: serde_json::Value = resp.json().await.ok()?;
    let new_token = data["token"].as_str()?.to_string();
    let new_refresh = data["refreshToken"].as_str().map(|s| s.to_string());

    // Store the new access token — the refresh token was already rotated server-side
    // (old one invalidated), so if storage fails the session may be lost on next command.
    if let Err(e) = auth::set_token(registry_url, &new_token) {
        tracing::warn!(
            "refreshed token obtained but failed to persist: {e}. Session may require re-login."
        );
    }

    // Store the rotated refresh token
    if let Some(rt) = new_refresh {
        auth::set_refresh_token(registry_url, &rt);
    }

    // Update precise session access-token expiry metadata
    if let Some(ea) = data["expiresAt"].as_str() {
        auth::set_session_access_token_expiry(registry_url, ea);
    }

    tracing::debug!("silent refresh succeeded");
    Some(new_token)
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

    // Set up tracing based on verbosity.
    //
    // **Phase 32 Phase 4 audit fix (D-impl-3, 2026-04-11):** the writer is
    // pinned to STDERR. Pre-fix this used `tracing_subscriber::fmt()`'s
    // default writer, which is STDOUT — meaning ANY `tracing::warn!` or
    // `tracing::info!` from anywhere in the CLI corrupted the `--json`
    // output stream by interleaving log lines with the JSON object. The
    // audit reproduced this end-to-end against `approve-builds --yes --json`
    // (a WARN line landed before the JSON, breaking JSON.parse). The fix
    // is global: stderr for tracing, stdout reserved for command output.
    let filter = if cli.verbose {
        "lpm=debug,reqwest=debug"
    } else {
        "lpm=warn"
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
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

    // Token priority: --token flag → env var / keychain / encrypted file → refresh
    if let Some(token) = &cli.token {
        client = client.with_token(token.clone());
    } else if let Some(token) = auth::get_token(registry_url) {
        client = client.with_token(token);

        if auth::has_refresh_token(registry_url)
            && auth::should_refresh_session_access_token(registry_url)
        {
            if let Some(new_token) = try_silent_refresh(registry_url).await {
                client = client.clone_with_config().with_token(new_token);
                auth::mark_token_validated();
            } else if auth::is_session_access_token_expired(registry_url) {
                let _ = auth::clear_token(registry_url);
                tracing::warn!(
                    "session access token expired and refresh failed — cleared. Run: lpm login"
                );
            }
        }

        // Periodic token validation — once every 24h, call whoami to detect expired tokens early
        if auth::should_revalidate_token() {
            match client.whoami().await {
                Ok(_) => auth::mark_token_validated(),
                Err(lpm_common::LpmError::AuthRequired) => {
                    // Access token expired — try silent refresh (Feature 44 Part B)
                    if let Some(new_token) = try_silent_refresh(registry_url).await {
                        client = client.clone_with_config().with_token(new_token);
                        auth::mark_token_validated();
                    } else {
                        let _ = auth::clear_token(registry_url);
                        tracing::warn!("stored token expired — cleared. Run: lpm login");
                    }
                }
                Err(_) => {
                    // Network errors etc. — don't clear, just skip validation
                }
            }
        }
    } else if let Some(new_token) = try_silent_refresh(registry_url).await {
        // No stored access token, but have a refresh token — recover the session
        client = client.clone_with_config().with_token(new_token);
    }

    let result = match cli.command {
        Commands::Info { package, version } => {
            commands::info::run(&client, &package, version.as_deref(), cli.json).await
        }
        Commands::Search { query, limit } => {
            commands::search::run(&client, &query, limit, cli.json).await
        }
        Commands::Quality { package } => commands::quality::run(&client, &package, cli.json).await,
        Commands::Whoami => commands::whoami::run(&client, cli.json).await,
        Commands::Health => commands::health::run(&client, registry_url, cli.json).await,
        Commands::Download {
            package,
            version,
            output,
        } => {
            commands::download::run(
                &client,
                &package,
                version.as_deref(),
                output.as_deref(),
                cli.json,
            )
            .await
        }
        Commands::Resolve { packages } => {
            commands::resolve::run(&client, &packages, cli.json).await
        }
        Commands::Install {
            packages,
            save_dev,
            offline,
            force,
            allow_new,
            linker,
            no_skills,
            no_editor_setup,
            no_security_summary,
            auto_build,
            filter,
            workspace_root,
            fail_if_no_match,
        } => {
            // Token expiry warnings (Feature 42)
            if !cli.json {
                for warning in auth::check_token_expiry_warnings() {
                    output::warn(&warning);
                }
            }
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let cfg = commands::config::GlobalConfig::load();
            let eff_allow_new = allow_new || cfg.get_bool("allowNew").unwrap_or(false);

            if packages.is_empty() {
                // Phase 32 Phase 2: --filter / -w / --fail-if-no-match only
                // apply when adding packages. Bare `lpm install` is the
                // refresh-from-package.json operation and ignores them
                // (or hard-errors if the user mistakenly passed them).
                if !filter.is_empty() || workspace_root || fail_if_no_match {
                    Err(lpm_common::LpmError::Script(
                        "`--filter`, `-w`, and `--fail-if-no-match` only apply when adding packages. \
                         Pass package specs (e.g., `lpm install react --filter web`) or run `lpm install` \
                         alone to refresh from package.json."
                            .into(),
                    ))
                } else {
                    // Bare install path — unchanged from pre-Phase-2.
                    let eff_no_skills = no_skills || cfg.get_bool("noSkills").unwrap_or(false);
                    let eff_no_editor =
                        no_editor_setup || cfg.get_bool("noEditorSetup").unwrap_or(false);
                    let eff_no_sec =
                        no_security_summary || cfg.get_bool("noSecuritySummary").unwrap_or(false);
                    let eff_auto_build = auto_build || cfg.get_bool("autoBuild").unwrap_or(false);
                    let eff_linker = linker.or_else(|| cfg.get_str("linker").map(String::from));

                    commands::install::run_with_options(
                        &client,
                        &cwd,
                        cli.json,
                        offline,
                        force,
                        eff_allow_new,
                        eff_linker.as_deref(),
                        eff_no_skills,
                        eff_no_editor,
                        eff_no_sec,
                        eff_auto_build,
                        None, // target_set: bare-install path is single-target
                    )
                    .await
                }
            } else if !filter.is_empty() || workspace_root {
                // Phase 32 Phase 2: explicit filter or -w flag → workspace-aware path.
                commands::install::run_install_filtered_add(
                    &client,
                    &cwd,
                    &packages,
                    save_dev,
                    &filter,
                    workspace_root,
                    fail_if_no_match,
                    cli.json,
                    eff_allow_new,
                    force,
                )
                .await
            } else {
                // No explicit flags. The new filtered path also handles the
                // "inside a workspace member directory" case via target
                // resolution — so we ALWAYS prefer it for workspace mode.
                // For pure standalone projects with NO workspace, the
                // legacy `run_add_packages` is still preferred because it
                // handles per-package Swift (SE-0292) routing, which Phase 2
                // intentionally defers from the workspace path.
                let workspace = lpm_workspace::discover_workspace(&cwd).ok().flatten();
                if workspace.is_some() {
                    commands::install::run_install_filtered_add(
                        &client,
                        &cwd,
                        &packages,
                        save_dev,
                        &filter,
                        workspace_root,
                        fail_if_no_match,
                        cli.json,
                        eff_allow_new,
                        force,
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
                    )
                    .await
                }
            }
        }
        Commands::Uninstall {
            packages,
            filter,
            workspace_root,
            fail_if_no_match,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::uninstall::run(
                &client,
                &cwd,
                &packages,
                &filter,
                workspace_root,
                fail_if_no_match,
                cli.json,
            )
            .await
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
        } => {
            // Token expiry warnings (Feature 42)
            if !cli.json {
                for warning in auth::check_token_expiry_warnings() {
                    output::warn(&warning);
                }
            }
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
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

            // OIDC: auto-detect CI environment for LPM token exchange
            // (separate from Sigstore provenance — both can happen)
            if oidc::detect_ci_environment().is_some() {
                match oidc::exchange_oidc_token(registry_url, None, "publish").await {
                    Ok(oidc_token) => {
                        let oidc_client = client.clone_with_config().with_token(oidc_token.token);
                        return commands::publish::run(
                            &oidc_client,
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
                        .into_diagnostic();
                    }
                    Err(e) => {
                        tracing::debug!("OIDC auto-detect failed, using stored token: {e}");
                    }
                }
            }

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
        Commands::Login {
            npm,
            github,
            gitlab,
            login_registry,
            token,
        } => {
            if npm || github || gitlab || login_registry.is_some() {
                let (registry_display, token_hint) = if npm {
                    (
                        "npmjs.org",
                        "Create a granular access token at npmjs.com/settings/tokens",
                    )
                } else if github {
                    (
                        "github.com",
                        "Create a PAT with write:packages at github.com/settings/tokens",
                    )
                } else if gitlab {
                    (
                        "gitlab.com",
                        "Create a personal/deploy token at gitlab.com/-/user_settings/personal_access_tokens",
                    )
                } else {
                    (
                        login_registry.as_deref().unwrap(),
                        "Provide the registry auth token",
                    )
                };

                if !cli.json {
                    output::print_header();
                }

                // Token: from --token flag, or interactive prompt with masked input
                let auth_token = if let Some(t) = token {
                    t
                } else if cli.json {
                    return Err(lpm_common::LpmError::Registry(format!(
                        "--token <token> required in JSON mode. {token_hint}"
                    )))
                    .into_diagnostic();
                } else {
                    // Interactive: prompt for token with masked input
                    eprintln!("  {}", token_hint.dimmed());
                    let t: String = cliclack::password(format!("Paste {registry_display} token"))
                        .mask('●')
                        .interact()
                        .map_err(|e| lpm_common::LpmError::Registry(e.to_string()))?;
                    t
                };

                if auth_token.is_empty() {
                    return Err(lpm_common::LpmError::Registry(
                        "token cannot be empty".into(),
                    ))
                    .into_diagnostic();
                }

                // Interactive: ask for token expiry reminder
                let expiry_days: Option<u32> =
                    if !cli.json && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                        let days: String = cliclack::input("Token expiry reminder (days, or skip)")
                            .placeholder("30")
                            .default_input("30")
                            .interact()
                            .unwrap_or_default();
                        days.parse().ok()
                    } else {
                        None
                    };

                // Ask about 2FA for npm-compat registries (interactive only)
                let otp_required = if !cli.json
                    && std::io::IsTerminal::is_terminal(&std::io::stdin())
                    && (npm || github || gitlab)
                {
                    cliclack::confirm("Does this account use 2FA / OTP for publishing?")
                        .initial_value(false)
                        .interact()
                        .unwrap_or(false)
                } else {
                    false
                };

                // Clear any previous metadata for this registry (single account per registry)
                auth::clear_token_expiry(registry_display);

                let store_result = if npm {
                    auth::set_npm_token(&auth_token)
                } else if github {
                    auth::set_github_token(&auth_token)
                } else if gitlab {
                    auth::set_gitlab_token(&auth_token)
                } else {
                    let url = login_registry.as_deref().unwrap();
                    auth::set_custom_registry_token(url, &auth_token)
                };

                store_result.map_err(|e| {
                    lpm_common::LpmError::Registry(format!("failed to store token: {e}"))
                })?;

                // Store OTP preference
                if otp_required {
                    auth::set_otp_required(registry_display, true);
                }

                // Store expiry reminder if provided
                if let Some(days) = expiry_days {
                    let expires_date = chrono::Utc::now() + chrono::Duration::days(days as i64);
                    let expires_iso = expires_date.format("%Y-%m-%d").to_string();
                    let expires_human = expires_date.format("%B %-d, %Y").to_string();
                    auth::set_token_expiry(registry_display, &expires_iso);
                    if !cli.json {
                        let otp_note = if otp_required { ", 2FA enabled" } else { "" };
                        output::success(&format!(
                            "Token stored for {} (reminder: {}{otp_note})",
                            registry_display.bold(),
                            expires_human.dimmed()
                        ));
                    }
                } else if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "success": true,
                            "registry": registry_display,
                            "otp_required": otp_required,
                        })
                    );
                } else {
                    let otp_note = if otp_required { " (2FA enabled)" } else { "" };
                    output::success(&format!(
                        "Token stored for {}{otp_note}",
                        registry_display.bold()
                    ));
                }
                Ok(())
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
                    Ok(()) if !cli.json => output::success("Logged out from GitHub Packages"),
                    Err(_) if !cli.json => output::info("Not logged in to GitHub Packages"),
                    _ => {}
                }
                auth::clear_token_expiry("github.com");
            }
            if all || gitlab {
                match auth::clear_gitlab_token() {
                    Ok(()) if !cli.json => output::success("Logged out from GitLab Packages"),
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
        Commands::Setup {
            registry: setup_registry,
            oidc,
            proxy,
            scoped: _,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let effective_registry = setup_registry.as_deref().unwrap_or(registry_url);
            let cfg = commands::config::GlobalConfig::load();
            let eff_proxy = proxy || cfg.get_bool("proxy").unwrap_or(false);
            commands::setup::run(effective_registry, &cwd, cli.json, oidc, eff_proxy).await
        }
        Commands::TokenRotate => commands::token::run_rotate(&client, registry_url, cli.json).await,
        Commands::Outdated => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::outdated::run(&client, &cwd, cli.json).await
        }
        Commands::Upgrade { major, dry_run } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::upgrade::run(&client, &cwd, major, dry_run, cli.json).await
        }
        Commands::Init { yes } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::init::run(&cwd, yes, cli.json).await
        }
        Commands::Config { action, key, value } => {
            commands::config::run(&action, key.as_deref(), value.as_deref(), cli.json).await
        }
        Commands::Cache { action } => commands::cache::run(&action, cli.json).await,
        Commands::Store {
            action,
            deep,
            dry_run,
            older_than,
            force,
            fix,
        } => {
            commands::store::run(
                &action,
                deep,
                dry_run,
                older_than.as_deref(),
                force,
                fix,
                cli.json,
            )
            .await
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
            level,
            fail_on,
            secrets,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            if secrets {
                commands::audit::run_secrets(&cwd, cli.json).await
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
        Commands::Build {
            packages,
            all,
            dry_run,
            rebuild,
            timeout,
            unsafe_full_env,
            deny_all,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::build::run(
                &cwd,
                &packages,
                all,
                dry_run,
                rebuild,
                timeout,
                cli.json,
                unsafe_full_env,
                deny_all,
            )
            .await
        }
        Commands::Doctor { fix, yes } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::doctor::run(&client, registry_url, &cwd, cli.json, fix || yes, yes).await
        }
        Commands::SwiftRegistry { force } => {
            commands::swift_registry::run(registry_url, cli.json, force).await
        }
        Commands::Mcp { action, name } => {
            commands::mcp::run(&action, name.as_deref(), cli.json).await
        }
        Commands::Use {
            spec,
            list,
            pin,
            extra: _,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            if spec.as_deref() == Some("vars") {
                // `lpm use vars ...` → delegate to vars handler
                // Extra args are re-parsed from raw argv inside run_vars()
                commands::env::run(&client, "vars", None, &cwd, cli.json).await
            } else if list {
                commands::env::run(&client, "list", spec.as_deref(), &cwd, cli.json).await
            } else if pin {
                let s = spec.as_deref().ok_or_else(|| {
                    lpm_common::LpmError::Script(
                        "missing version. Usage: lpm use --pin node@22.5.0".into(),
                    )
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
        Commands::Env {
            action,
            spec,
            extra: _,
        } => {
            // Hidden backwards-compat alias
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::env::run(&client, &action, spec.as_deref(), &cwd, cli.json).await
        }
        Commands::Npmrc {
            days,
            proxy,
            scoped: _,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let cfg = commands::config::GlobalConfig::load();
            let eff_proxy = proxy || cfg.get_bool("proxy").unwrap_or(false);
            commands::npmrc::run(&client, &cwd, registry_url, days, eff_proxy, cli.json).await
        }
        Commands::Run {
            scripts,
            env,
            parallel,
            continue_on_error,
            stream,
            all,
            filter,
            fail_if_no_match,
            affected,
            base,
            no_cache,
            no_env_check,
            watch,
            args,
        } => {
            lpm_runner::script::set_skip_env_validation(no_env_check);
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            if watch {
                commands::run::ensure_runtime(&cwd).await;
                commands::run::run_watch(&cwd, &scripts[0], &args, env.as_deref())
            } else if all || !filter.is_empty() || affected {
                // Workspace mode: run scripts across packages with task graph
                commands::run::run_workspace(
                    &cwd,
                    &scripts,
                    &args,
                    env.as_deref(),
                    &filter,
                    affected,
                    &base,
                    fail_if_no_match,
                    no_cache,
                    parallel,
                    continue_on_error,
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
            commands::run::dlx(&cwd, &package, &args, refresh).await
        }
        Commands::Filter {
            exprs,
            explain,
            fail_if_no_match,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::filter::run(&cwd, &exprs, explain, fail_if_no_match, cli.json).await
        }
        Commands::Deploy {
            output,
            filter,
            force,
            dry_run,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let output_path = std::path::PathBuf::from(&output);
            commands::deploy::run(&cwd, &output_path, &filter, force, dry_run, cli.json).await
        }
        Commands::ApproveBuilds {
            package,
            yes,
            list,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::approve_builds::run(&cwd, package.as_deref(), yes, list, cli.json).await
        }
        Commands::Plugin { action, name } => {
            commands::plugin::run(&action, name.as_deref(), cli.json).await
        }
        Commands::Lint {
            all,
            affected,
            base,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            if all || affected {
                let affected_ref = if affected { Some(base.as_str()) } else { None };
                commands::tools::tool_workspace(&cwd, "lint", &args, false, affected_ref, cli.json)
                    .await
            } else {
                commands::tools::lint(&cwd, &args, cli.json).await
            }
        }
        Commands::Fmt {
            check,
            all,
            affected,
            base,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            if all || affected {
                let affected_ref = if affected { Some(base.as_str()) } else { None };
                commands::tools::tool_workspace(&cwd, "fmt", &args, check, affected_ref, cli.json)
                    .await
            } else {
                commands::tools::fmt(&cwd, &args, check, cli.json).await
            }
        }
        Commands::Check {
            all,
            affected,
            base,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            if all || affected {
                let affected_ref = if affected { Some(base.as_str()) } else { None };
                commands::tools::tool_workspace(&cwd, "check", &args, false, affected_ref, cli.json)
                    .await
            } else {
                commands::tools::check(&cwd, &args, cli.json).await
            }
        }
        Commands::Test { args } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::tools::test(&cwd, &args, cli.json).await
        }
        Commands::Bench { args } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::tools::bench(&cwd, &args, cli.json).await
        }
        Commands::Ci { action, args } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            commands::ci::run(&action, &args_refs, &cwd, cli.json).await
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
                tunnel_source,
                &args,
                env.as_deref(),
                no_open,
                no_install,
                quiet,
                dashboard && !no_dashboard,
                lpm_config,
                tunnel_auth,
            )
            .await
        }
        Commands::Cert { action, host } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::cert::run(&action, &cwd, &host, cli.json).await
        }
        Commands::Graph {
            package,
            format,
            why,
            depth,
            filter,
            prod,
            dev,
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
            )
            .await
        }
        Commands::Ports { action, port } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::ports::run(&action, port, &cwd, cli.json).await
        }
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
            let resolved_token = cli.token.clone().or_else(|| auth::get_token(registry_url));
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
            yes,
        } => {
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
                force || yes,
                rollback,
                cli.json,
            )
            .await
        }
        Commands::Vault { action } => commands::vault::run(&action, cli.json).await,
        Commands::SelfUpdate => commands::self_update::run(cli.json).await,
        Commands::External(args) => {
            // Try as package.json script shortcut: `lpm dev` → `lpm run dev`
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let script_name = &args[0];
            let extra_args = if args.len() > 1 { &args[1..] } else { &[] };
            commands::run::run(&cwd, script_name, extra_args, None, false).await
        }
    };

    // Update check: show notice from previous check (instant, no network)
    if !cli.json
        && let Some(notice) = update_check::read_cached_notice()
    {
        eprint!("{notice}");
    }

    // Refresh update cache if stale (max 3s, once per 24h)
    update_check::refresh_cache_if_stale().await;

    // Handle ExitCode at the top level — the only place process::exit() should be called.
    // Library code returns Err(LpmError::ExitCode(code)) instead of calling process::exit()
    // directly, so Drop handlers run and the code remains testable.
    if let Err(e) = &result {
        // --json mode: output structured error JSON so LLMs/MCP servers can parse failures.
        // Without this, miette prints colored human-readable errors that can't be parsed.
        //
        // Skip for ExitCode errors — commands that return ExitCode (like `lpm run`)
        // have already emitted their own structured JSON output. Printing a second
        // generic error JSON would break the "single JSON result" contract.
        if cli.json && !matches!(e, lpm_common::LpmError::ExitCode(_)) {
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

    result.into_diagnostic()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // -- Finding #1: CLI parser must handle `lpm run build` without `--` --

    #[test]
    fn run_single_script_parses() {
        let cli = Cli::try_parse_from(["lpm", "run", "build"]).unwrap();
        match cli.command {
            Commands::Run { scripts, args, .. } => {
                assert_eq!(scripts, vec!["build"]);
                assert!(args.is_empty(), "args should be empty without --");
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn run_multiple_scripts_parses() {
        let cli = Cli::try_parse_from(["lpm", "run", "build", "test", "lint"]).unwrap();
        match cli.command {
            Commands::Run { scripts, args, .. } => {
                assert_eq!(scripts, vec!["build", "test", "lint"]);
                assert!(args.is_empty());
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn run_script_with_extra_args_after_separator() {
        let cli =
            Cli::try_parse_from(["lpm", "run", "build", "--", "--verbose", "--force"]).unwrap();
        match cli.command {
            Commands::Run { scripts, args, .. } => {
                assert_eq!(scripts, vec!["build"]);
                assert_eq!(args, vec!["--verbose", "--force"]);
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn run_script_with_flags_parses() {
        let cli = Cli::try_parse_from(["lpm", "run", "build", "--all", "--no-cache"]).unwrap();
        match cli.command {
            Commands::Run {
                scripts,
                all,
                no_cache,
                args,
                ..
            } => {
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
        match cli.command {
            Commands::Run {
                scripts,
                parallel,
                args,
                ..
            } => {
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
        match cli.command {
            Commands::Run { scripts, watch, .. } => {
                assert_eq!(scripts, vec!["dev"]);
                assert!(watch);
            }
            _ => panic!("expected Run command"),
        }
    }

    // ── Phase 32 Phase 1 M7: --filter as Vec<String> + --fail-if-no-match ──

    #[test]
    fn run_filter_flag_collects_into_vec() {
        let cli = Cli::try_parse_from([
            "lpm", "run", "build", "--filter", "foo", "--filter", "@ui/*",
        ])
        .unwrap();
        match cli.command {
            Commands::Run { filter, .. } => {
                assert_eq!(filter, vec!["foo".to_string(), "@ui/*".to_string()]);
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn run_fail_if_no_match_flag_parses() {
        let cli = Cli::try_parse_from([
            "lpm", "run", "build", "--filter", "foo", "--fail-if-no-match",
        ])
        .unwrap();
        match cli.command {
            Commands::Run {
                filter,
                fail_if_no_match,
                ..
            } => {
                assert_eq!(filter, vec!["foo".to_string()]);
                assert!(fail_if_no_match);
            }
            _ => panic!("expected Run command"),
        }
    }

    // ── Phase 32 Phase 1 M7: lpm filter subcommand ────────────────────────

    #[test]
    fn filter_command_parses_positional_exprs() {
        let cli = Cli::try_parse_from(["lpm", "filter", "@ui/*", "core"]).unwrap();
        match cli.command {
            Commands::Filter {
                exprs,
                explain,
                fail_if_no_match,
            } => {
                assert_eq!(exprs, vec!["@ui/*".to_string(), "core".to_string()]);
                assert!(!explain, "default mode is terse, not explain");
                assert!(!fail_if_no_match);
            }
            _ => panic!("expected Filter command"),
        }
    }

    #[test]
    fn filter_command_explain_flag_parses() {
        // GPT audit regression: --explain must be a real flag, not just
        // documented and rejected at runtime.
        let cli = Cli::try_parse_from(["lpm", "filter", "--explain", "foo"]).unwrap();
        match cli.command {
            Commands::Filter { exprs, explain, .. } => {
                assert_eq!(exprs, vec!["foo".to_string()]);
                assert!(explain, "--explain must enable explain mode");
            }
            _ => panic!("expected Filter command"),
        }
    }

    #[test]
    fn filter_command_explain_and_fail_if_no_match_compose() {
        let cli = Cli::try_parse_from([
            "lpm",
            "filter",
            "core",
            "--explain",
            "--fail-if-no-match",
        ])
        .unwrap();
        match cli.command {
            Commands::Filter {
                exprs,
                explain,
                fail_if_no_match,
            } => {
                assert_eq!(exprs, vec!["core".to_string()]);
                assert!(explain);
                assert!(fail_if_no_match);
            }
            _ => panic!("expected Filter command"),
        }
    }

    #[test]
    fn filter_command_requires_at_least_one_expr() {
        // exprs is `#[arg(required = true)]` so empty args is a parse error
        let result = Cli::try_parse_from(["lpm", "filter"]);
        assert!(result.is_err(), "empty exprs must be rejected");
    }

    // ── Phase 32 Phase 2 M2: install --filter / -w / --fail-if-no-match ──

    #[test]
    fn install_filter_flag_collects_into_vec() {
        let cli = Cli::try_parse_from([
            "lpm", "install", "react", "--filter", "web", "--filter", "@ui/*",
        ])
        .unwrap();
        match cli.command {
            Commands::Install {
                packages,
                filter,
                workspace_root,
                fail_if_no_match,
                ..
            } => {
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
        match cli.command {
            Commands::Install {
                packages,
                workspace_root,
                filter,
                ..
            } => {
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
        match cli.command {
            Commands::Install { workspace_root, .. } => {
                assert!(workspace_root, "--workspace-root must enable the flag");
            }
            _ => panic!("expected Install command"),
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
        match cli.command {
            Commands::Install {
                fail_if_no_match, ..
            } => {
                assert!(fail_if_no_match);
            }
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn install_save_dev_with_filter_composes() {
        let cli = Cli::try_parse_from([
            "lpm", "install", "-D", "vitest", "--filter", "./apps/*",
        ])
        .unwrap();
        match cli.command {
            Commands::Install {
                packages,
                save_dev,
                filter,
                ..
            } => {
                assert_eq!(packages, vec!["vitest".to_string()]);
                assert!(save_dev);
                assert_eq!(filter, vec!["./apps/*".to_string()]);
            }
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn install_bare_with_no_packages_and_no_phase2_flags_parses() {
        // Sanity: `lpm install` with no flags must still parse — Phase 2
        // does not break the bare-refresh path.
        let cli = Cli::try_parse_from(["lpm", "install"]).unwrap();
        match cli.command {
            Commands::Install {
                packages,
                filter,
                workspace_root,
                fail_if_no_match,
                ..
            } => {
                assert!(packages.is_empty());
                assert!(filter.is_empty());
                assert!(!workspace_root);
                assert!(!fail_if_no_match);
            }
            _ => panic!("expected Install command"),
        }
    }

    // ── Phase 32 Phase 2 M3: uninstall --filter / -w / --fail-if-no-match ──

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
        match cli.command {
            Commands::Uninstall {
                packages,
                filter,
                workspace_root,
                fail_if_no_match,
            } => {
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
        match cli.command {
            Commands::Uninstall { workspace_root, .. } => {
                assert!(workspace_root);
            }
            _ => panic!("expected Uninstall command"),
        }
    }

    #[test]
    fn uninstall_workspace_root_long_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "uninstall", "shared", "--workspace-root"]).unwrap();
        match cli.command {
            Commands::Uninstall { workspace_root, .. } => {
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
        match cli.command {
            Commands::Uninstall {
                fail_if_no_match, ..
            } => {
                assert!(fail_if_no_match);
            }
            _ => panic!("expected Uninstall command"),
        }
    }

    #[test]
    fn uninstall_visible_alias_un_still_works() {
        // The pre-Phase-2 visible alias `un` must continue to parse with
        // the new flags.
        let cli = Cli::try_parse_from(["lpm", "un", "foo", "-w"]).unwrap();
        match cli.command {
            Commands::Uninstall {
                packages,
                workspace_root,
                ..
            } => {
                assert_eq!(packages, vec!["foo".to_string()]);
                assert!(workspace_root);
            }
            _ => panic!("expected Uninstall command via `un` alias"),
        }
    }

    // ── Phase 32 Phase 3 M1: lpm deploy ────────────────────────────────────

    #[test]
    fn deploy_command_parses_required_output_and_filter() {
        let cli =
            Cli::try_parse_from(["lpm", "deploy", "/prod/api", "--filter", "api"]).unwrap();
        match cli.command {
            Commands::Deploy {
                output,
                filter,
                force,
                dry_run,
            } => {
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
        // The filter expression supports the full Phase 1 grammar.
        let cli = Cli::try_parse_from([
            "lpm",
            "deploy",
            "/prod/web",
            "--filter",
            "@scope/web",
        ])
        .unwrap();
        match cli.command {
            Commands::Deploy { filter, .. } => {
                assert_eq!(filter, vec!["@scope/web".to_string()]);
            }
            _ => panic!("expected Deploy command"),
        }
    }

    #[test]
    fn deploy_command_force_flag_parses() {
        let cli = Cli::try_parse_from([
            "lpm", "deploy", "/prod/api", "--filter", "api", "--force",
        ])
        .unwrap();
        match cli.command {
            Commands::Deploy { force, .. } => assert!(force),
            _ => panic!("expected Deploy command"),
        }
    }

    #[test]
    fn deploy_command_dry_run_flag_parses() {
        let cli = Cli::try_parse_from([
            "lpm",
            "deploy",
            "/prod/api",
            "--filter",
            "api",
            "--dry-run",
        ])
        .unwrap();
        match cli.command {
            Commands::Deploy { dry_run, .. } => assert!(dry_run),
            _ => panic!("expected Deploy command"),
        }
    }

    #[test]
    fn deploy_command_requires_filter() {
        // The Deploy command marks --filter as required = true. Missing it
        // is a parse error, NOT a runtime error. This guards against the
        // case where someone runs `lpm deploy /prod/api` and expects it to
        // somehow figure out which member to deploy.
        let result = Cli::try_parse_from(["lpm", "deploy", "/prod/api"]);
        assert!(
            result.is_err(),
            "deploy without --filter must be a parse error"
        );
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
        // flags. The single-member assertion happens in M2, not at parse time.
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
        match cli.command {
            Commands::Deploy { filter, .. } => {
                assert_eq!(filter.len(), 2);
            }
            _ => panic!("expected Deploy command"),
        }
    }

    // ── Phase 32 Phase 4: ApproveBuilds command flag parsing ──

    #[test]
    fn approve_builds_no_args_parses_to_interactive_default() {
        let cli = Cli::try_parse_from(["lpm", "approve-builds"]).unwrap();
        match cli.command {
            Commands::ApproveBuilds {
                package,
                yes,
                list,
            } => {
                assert!(package.is_none());
                assert!(!yes);
                assert!(!list);
            }
            _ => panic!("expected ApproveBuilds command"),
        }
    }

    #[test]
    fn approve_builds_with_pkg_argument_parses() {
        let cli = Cli::try_parse_from(["lpm", "approve-builds", "esbuild"]).unwrap();
        match cli.command {
            Commands::ApproveBuilds { package, .. } => {
                assert_eq!(package, Some("esbuild".to_string()));
            }
            _ => panic!("expected ApproveBuilds command"),
        }
    }

    #[test]
    fn approve_builds_with_versioned_pkg_argument_parses() {
        let cli =
            Cli::try_parse_from(["lpm", "approve-builds", "esbuild@0.25.1"]).unwrap();
        match cli.command {
            Commands::ApproveBuilds { package, .. } => {
                assert_eq!(package, Some("esbuild@0.25.1".to_string()));
            }
            _ => panic!("expected ApproveBuilds command"),
        }
    }

    #[test]
    fn approve_builds_yes_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "approve-builds", "--yes"]).unwrap();
        match cli.command {
            Commands::ApproveBuilds { yes, .. } => {
                assert!(yes);
            }
            _ => panic!("expected ApproveBuilds command"),
        }
    }

    #[test]
    fn approve_builds_list_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "approve-builds", "--list"]).unwrap();
        match cli.command {
            Commands::ApproveBuilds { list, .. } => {
                assert!(list);
            }
            _ => panic!("expected ApproveBuilds command"),
        }
    }

    #[test]
    fn approve_builds_yes_and_list_together_is_a_parse_error() {
        // The clap `conflicts_with` declaration on the field should make
        // this a parse-time error rather than a runtime error. Belt-and-
        // suspenders with the runtime check in approve_builds::run.
        let result =
            Cli::try_parse_from(["lpm", "approve-builds", "--yes", "--list"]);
        assert!(
            result.is_err(),
            "--yes and --list together must be a parse error"
        );
    }

    #[test]
    fn approve_builds_json_with_list_parses() {
        // --json is a top-level Cli flag, not on the subcommand. Verify
        // it composes with `--list` cleanly.
        let cli =
            Cli::try_parse_from(["lpm", "--json", "approve-builds", "--list"]).unwrap();
        assert!(cli.json);
        match cli.command {
            Commands::ApproveBuilds { list, .. } => assert!(list),
            _ => panic!("expected ApproveBuilds command"),
        }
    }

    // ── Dev command flag parsing ──

    #[test]
    fn dev_dashboard_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "dev", "--dashboard"]).unwrap();
        match cli.command {
            Commands::Dev { dashboard, .. } => {
                assert!(dashboard);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_quiet_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "dev", "-q"]).unwrap();
        match cli.command {
            Commands::Dev { quiet, .. } => {
                assert!(quiet);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_quiet_long_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "dev", "--quiet"]).unwrap();
        match cli.command {
            Commands::Dev { quiet, .. } => {
                assert!(quiet);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_dashboard_and_tunnel_flags_parse() {
        let cli = Cli::try_parse_from(["lpm", "dev", "--dashboard", "--tunnel"]).unwrap();
        match cli.command {
            Commands::Dev {
                dashboard, tunnel, ..
            } => {
                assert!(dashboard);
                assert!(tunnel);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_defaults_dashboard_false() {
        let cli = Cli::try_parse_from(["lpm", "dev"]).unwrap();
        match cli.command {
            Commands::Dev {
                dashboard, quiet, ..
            } => {
                assert!(!dashboard);
                assert!(!quiet);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_no_dashboard_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "dev", "--no-dashboard"]).unwrap();
        match cli.command {
            Commands::Dev {
                dashboard,
                no_dashboard,
                ..
            } => {
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
        match cli.command {
            Commands::Dev {
                https, no_https, ..
            } => {
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
        match cli.command {
            Commands::Dev {
                tunnel, no_tunnel, ..
            } => {
                assert!(tunnel);
                assert!(no_tunnel);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_tunnel_auth_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "dev", "--tunnel", "--tunnel-auth"]).unwrap();
        match cli.command {
            Commands::Dev {
                tunnel,
                tunnel_auth,
                ..
            } => {
                assert!(tunnel);
                assert!(tunnel_auth);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_tunnel_auth_defaults_false() {
        let cli = Cli::try_parse_from(["lpm", "dev"]).unwrap();
        match cli.command {
            Commands::Dev { tunnel_auth, .. } => {
                assert!(!tunnel_auth);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn tunnel_tunnel_auth_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "tunnel", "start", "--tunnel-auth"]).unwrap();
        match cli.command {
            Commands::Tunnel { tunnel_auth, .. } => {
                assert!(tunnel_auth);
            }
            _ => panic!("expected Tunnel command"),
        }
    }

    #[test]
    fn run_affected_with_base_parses() {
        let cli = Cli::try_parse_from(["lpm", "run", "build", "--affected", "--base", "develop"])
            .unwrap();
        match cli.command {
            Commands::Run {
                scripts,
                affected,
                base,
                ..
            } => {
                assert_eq!(scripts, vec!["build"]);
                assert!(affected);
                assert_eq!(base, "develop");
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn use_vars_global_json_before_command_sets_global_json_flag() {
        let cli = Cli::try_parse_from(["lpm", "--json", "use", "vars", "oidc", "list"])
            .unwrap();

        assert!(cli.json, "expected global --json to be parsed before use command");

        match cli.command {
            Commands::Use { spec, extra, .. } => {
                assert_eq!(spec.as_deref(), Some("vars"));
                assert_eq!(extra, vec!["oidc", "list"]);
            }
            _ => panic!("expected Use command"),
        }
    }

    #[test]
    fn use_vars_trailing_json_is_captured_as_raw_extra_arg() {
        let cli = Cli::try_parse_from(["lpm", "use", "vars", "oidc", "list", "--json"])
            .unwrap();

        assert!(
            !cli.json,
            "trailing --json after use should not be parsed as the global flag"
        );

        match cli.command {
            Commands::Use { spec, extra, .. } => {
                assert_eq!(spec.as_deref(), Some("vars"));
                assert_eq!(extra, vec!["oidc", "list", "--json"]);
            }
            _ => panic!("expected Use command"),
        }
    }
}
