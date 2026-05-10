use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use miette::{IntoDiagnostic, Result};
use owo_colors::OwoColorize;

mod auth;
pub mod build_state;
pub mod capability;
mod commands;
pub mod constraints;
pub mod doctor_catalog;
pub mod editor_skills;
pub mod engine_check;
pub mod engine_strict_config;
mod global_blocked_set;
mod graph_render;
mod import_rewriter;
pub mod install_state;
pub mod intelligence;
mod linker_config;
mod manifest_tx;
pub mod migration_warnings;
mod oidc;
mod output;
pub mod overrides_state;
pub mod patch_engine;
pub mod patch_state;
pub mod path_onboarding;
pub mod precedence;
mod prompt;
mod provenance;
mod provenance_fetch;
mod quality;
mod release_age_config;
mod release_lookup;
mod save_config;
mod save_spec;
mod script_policy_config;
pub mod security_check;
mod sigstore;
mod swift_manifest;
#[cfg(test)]
mod test_env;
mod tool_pin_validation;
mod trust_snapshot;
mod tsc_status;
mod update_check;
pub mod upgrade_engine;
pub mod version_diff;
pub mod workspace_select;
mod xcode_project;

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
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

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
    version_flag: bool,

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
    ///
    /// Long form only — `-v` was reclaimed for `--version` to match
    /// npm/pnpm/yarn convention.
    #[arg(long, global = true)]
    verbose: bool,

    /// Allow insecure HTTP connections to non-localhost registries.
    #[arg(long, global = true)]
    insecure: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutdatedRegistryScope {
    All,
    Lpm,
}

/// Linker mode as accepted by the `--linker` CLI flag. Clap clamps the input
/// at parse time so any unknown value fails before the command runs. Mirrors
/// `lpm_linker::LinkerMode::ACCEPTED_VALUES`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum LinkerCli {
    Isolated,
    Hoisted,
}

impl LinkerCli {
    fn into_linker_mode(self) -> lpm_linker::LinkerMode {
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
enum Commands {
    /// Show package information.
    Info {
        /// Package name (e.g., @lpm.dev/owner.package or owner.package)
        package: String,

        /// Show a specific version instead of latest.
        #[arg(long = "version")]
        package_version: Option<String>,
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
        #[arg(long = "version")]
        package_version: Option<String>,

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
    ///
    /// SAVE POLICY (Phase 33)
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

        /// **Phase 59.0 (F5)** — fail on tarball-URL deps that have no
        /// declared SRI integrity in the manifest. Without this flag,
        /// trust-on-first-use lets the first `lpm install` of a new
        /// tarball-URL dep accept whatever the URL returns and record
        /// the computed SRI in the lockfile; subsequent installs
        /// always verify. With `--strict-integrity`, that first-use
        /// path is disabled — manifests must declare the SRI inline
        /// (e.g. `"foo": "https://e.com/foo.tgz#sha512-…"`) to
        /// install. Recommended for CI to prevent supply-chain
        /// surprises on fresh installs.
        ///
        /// Lockfile-resident integrity is always trusted; the flag
        /// only affects the manifest-declaration boundary.
        #[arg(long)]
        strict_integrity: bool,

        /// Override the minimumReleaseAge cooldown for this install only.
        /// Accepts `<N>h` (hours), `<N>d` (days), or plain `<N>` seconds.
        /// Use `0` to disable the cooldown for this invocation; any other
        /// value tightens or loosens the window vs. the default 24h /
        /// `package.json > lpm > minimumReleaseAge` /
        /// `~/.lpm/config.toml` key `minimum-release-age-secs`.
        ///
        /// Phase 46 P3: the full precedence chain is
        /// `--min-release-age` (this flag, highest) → package.json →
        /// `~/.lpm/config.toml` → 24h default. `--allow-new` and this
        /// flag are independent escape hatches: `--allow-new` bypasses
        /// the check entirely; `--min-release-age=<dur>` adjusts the
        /// window that the check enforces.
        #[arg(long, value_name = "DUR")]
        min_release_age: Option<String>,

        /// Skip the Phase 46 P4 provenance-drift check for this
        /// specific package name (repeatable). The drift gate blocks
        /// on publisher identity changes between a prior approval
        /// and the candidate version; this flag opts out for a named
        /// package while keeping every other package's drift check
        /// live. Per D16, this is orthogonal to `--allow-new` — the
        /// cooldown and drift gates are independent.
        ///
        /// Prefer re-approving via `lpm approve-scripts` over
        /// ignoring the drift: re-approval captures the new
        /// publisher identity so the next install sees a clean
        /// reference. Use this flag only when the identity change
        /// is expected AND the user does not yet want to accept
        /// the new identity as the new approval baseline.
        #[arg(long, value_name = "PKG")]
        ignore_provenance_drift: Vec<String>,

        /// Blanket: skip the Phase 46 P4 provenance-drift check for
        /// every resolved package. Composes with
        /// `--ignore-provenance-drift <pkg>` by superseding it — if
        /// both are passed, `-all` wins and the per-package list is
        /// ignored (drift checks are suppressed entirely for this
        /// invocation).
        #[arg(long)]
        ignore_provenance_drift_all: bool,

        /// Linking mode: `hoisted` (default since Phase 66 4f — npm v3+
        /// flat layout) or `isolated` (pnpm-style strict isolation).
        /// Both materialize as project `node_modules/<dep>` symlinks
        /// into the global virtual store at `~/.lpm/store/v2/links/`,
        /// so warm-install latency is identical between modes; the
        /// distinction is whether transitive deps are reachable at the
        /// project root (hoisted: yes — npm-compat) or only through
        /// each consumer's own siblings (isolated: no — phantom-dep
        /// catcher). Unknown values are rejected by clap at parse
        /// time. Overrides `package.json > lpm > linker`,
        /// `~/.lpm/config.toml > linker`, and `LPM_LINKER`.
        #[arg(long, value_enum)]
        linker: Option<LinkerCli>,

        /// Skip skills auto-install.
        #[arg(long)]
        no_skills: bool,

        /// Skip editor auto-integration.
        #[arg(long)]
        no_editor_setup: bool,

        /// Disable post-install security summary (faster CI).
        #[arg(long)]
        no_security_summary: bool,

        /// Automatically run `lpm rebuild` for trusted packages after install.
        ///
        /// Phase 57: redundant under `--policy=allow` / `--yolo` (auto-build
        /// fires at install time when policy is allow, regardless of this
        /// flag). Still useful under the default `deny` policy when you
        /// have an established trust set and want to skip the explicit
        /// `lpm rebuild` step.
        #[arg(long)]
        auto_build: bool,

        /// Skip `engines.lpm` / `engines.node` enforcement for this
        /// invocation.
        ///
        /// LPM enforces `engines` constraints from the workspace root
        /// `package.json` by default, mismatches abort. Pass this flag
        /// to bypass — useful when running an older CLI in a project
        /// pinned to a newer one, or vice versa.
        ///
        /// Precedence: this flag > `package.json > lpm > engineStrict`
        /// > `~/.lpm/config.toml > engine-strict` > default (true).
        #[arg(long)]
        no_engine_strict: bool,

        /// Lifecycle-script policy override for this invocation.
        ///
        /// `deny` (default): scripts blocked; `lpm approve-scripts`
        /// required to run per package. `lpm install` does NOT run
        /// scripts; the install-time build hint lists candidates so
        /// you can review and approve before any code executes.
        ///
        /// `allow` (Phase 57): runs every lifecycle script during
        /// `lpm install`, without the tier gate. Matches `npm install`
        /// / `pnpm install` / `bun install` default semantics. The
        /// trust check is bypassed because you opted in explicitly.
        /// (Pre-Phase-57 this flag declared intent but required a
        /// second `--auto-build` flag to actually fire scripts; that
        /// two-step is now collapsed.)
        ///
        /// `triage`: four-layer tiered gate. Auto-runs when every
        /// unbuilt scripted package is trusted/green; if any amber or
        /// red remains, scripts defer to `lpm approve-scripts` review
        /// unless an explicit auto-build signal is set. On project
        /// installs that signal is `--auto-build` or
        /// `package.json > lpm > scripts.autoBuild = true`; on global
        /// installs (`-g`), only `--auto-build` applies — `-g` uses a
        /// synthesized package.json that does not project per-project
        /// script knobs. Greens auto-execute in the filesystem sandbox;
        /// ambers and reds never auto-execute. The LLM triage layer
        /// is not available yet.
        ///
        /// Precedence: this flag > `package.json > lpm > scriptPolicy`
        /// > `~/.lpm/config.toml` key `script-policy` > default (deny).
        ///
        /// On `-g` the `package.json` tier is N/A; the chain collapses to
        /// CLI flag > `~/.lpm/config.toml` > default.
        ///
        /// On `lpm install -g`, blocked scripts can only be re-executed
        /// by reinstalling the affected global(s) (`lpm uninstall -g
        /// <pkg> && lpm install -g <pkg>`) after `lpm approve-scripts
        /// --global`. `lpm rebuild --global` is a planned follow-up.
        ///
        /// Mutually exclusive with `--yolo` and `--triage`.
        #[arg(
            long,
            value_name = "deny|allow|triage",
            conflicts_with_all = ["yolo", "triage_alias"],
        )]
        policy: Option<String>,

        /// Alias for `--policy=allow`. Runs every lifecycle script
        /// during `lpm install` without the tier gate (Phase 57 —
        /// auto-build fires automatically; no separate `--auto-build`
        /// flag needed).
        ///
        /// See `--policy` for the global rerun caveat (`-g` blocked
        /// scripts require uninstall+reinstall after approval).
        ///
        /// Mutually exclusive with `--policy` and `--triage`.
        #[arg(long, conflicts_with_all = ["policy", "triage_alias"])]
        yolo: bool,

        /// Phase 46: alias for `--policy=triage`. Enables the
        /// tiered gate (Phase 46 P2–P6): greens auto-approve and
        /// run in the sandbox; ambers and reds route to
        /// `lpm approve-scripts` for manual review.
        ///
        /// See `--policy` for the global rerun caveat (`-g` blocked
        /// scripts require uninstall+reinstall after approval).
        ///
        /// Mutually exclusive with `--policy` and `--yolo`.
        #[arg(long = "triage", id = "triage_alias", conflicts_with_all = ["policy", "yolo"])]
        triage_alias: bool,

        /// Phase 32 Phase 2: filter workspace members. Same grammar as
        /// `lpm run --filter`. Only meaningful when adding packages — bare
        /// `lpm install` (no packages) ignores this flag.
        ///
        /// Example: `lpm install react --filter web` adds react to
        /// `packages/web/package.json` and runs the install pipeline at
        /// `packages/web/`.
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

        /// Phase 32 Phase 2 (D-impl-5, 2026-04-16): skip the interactive
        /// confirmation prompt when a filtered install will mutate more
        /// than one workspace member's `package.json`. Mirrors `lpm init`
        /// and `lpm publish` — JSON mode and non-TTY stdin already skip
        /// the prompt automatically; this flag covers the interactive-
        /// terminal-but-no-manual-review case (scripts, agents).
        #[arg(long, short = 'y')]
        yes: bool,

        /// Phase 33: save the exact resolved version to `package.json`
        /// instead of the default `^resolvedVersion`. Mutually exclusive
        /// with `--tilde` and `--save-prefix`.
        ///
        /// Example: `lpm install zod --exact` saves `"zod": "4.3.6"`.
        #[arg(long, conflicts_with_all = ["tilde", "save_prefix"])]
        exact: bool,

        /// Phase 33: save `~resolvedVersion` to `package.json` instead of
        /// the default `^resolvedVersion`. Mutually exclusive with
        /// `--exact` and `--save-prefix`.
        ///
        /// Example: `lpm install zod --tilde` saves `"zod": "~4.3.6"`.
        #[arg(long, conflicts_with_all = ["exact", "save_prefix"])]
        tilde: bool,

        /// Phase 33: override the manifest save prefix for this install.
        /// Valid values: `^`, `~`, or `""` (empty for exact, no prefix).
        /// `*` is not accepted — wildcards must be requested per-package
        /// via `pkg@*`. Mutually exclusive with `--exact` and `--tilde`.
        ///
        /// Example: `lpm install zod --save-prefix '~'` saves `"zod": "~4.3.6"`.
        #[arg(long, value_name = "PREFIX", conflicts_with_all = ["exact", "tilde"])]
        save_prefix: Option<String>,

        /// Phase 37: install the package globally into `~/.lpm/global/`
        /// instead of into a project's `node_modules/`. Exposes the
        /// package's bin entries on PATH via `~/.lpm/bin/`.
        ///
        /// The persistent install pipeline lands in M3; this M2 release
        /// only ships the flag surface so downstream work can wire to it.
        ///
        /// Example: `lpm install --global eslint`, `lpm install -g typescript`
        #[arg(long, short = 'g')]
        global: bool,

        /// Phase 37 M4: resolve a command-name collision by transferring
        /// ownership of `<CMD>` to the package being installed. The
        /// previous owner keeps their row but loses that command from
        /// PATH; the new shim points at this install.
        ///
        /// Repeatable. Only meaningful with `-g`.
        ///
        /// Example: `lpm install -g foo --replace-bin serve --replace-bin lint`
        #[arg(long = "replace-bin", value_name = "CMD")]
        replace_bin: Vec<String>,

        /// Phase 37 M4: install a declared bin under a different PATH
        /// name. Format: `<orig>=<alias>` — `<orig>` must be a bin the
        /// package declares, `<alias>` is the PATH name. Multiple
        /// mappings comma-separated or via repeated flags.
        ///
        /// When set, the declared `<orig>` name is NOT emitted as a
        /// shim; only `<alias>` is. Only meaningful with `-g`.
        ///
        /// Example: `lpm install -g foo --alias serve=foo-serve,lint=foo-lint`
        #[arg(long = "alias", value_name = "ORIG=ALIAS")]
        alias: Vec<String>,
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

        /// Phase 32 Phase 2 (D-impl-5, 2026-04-16): skip the interactive
        /// confirmation prompt when a filtered uninstall will mutate more
        /// than one workspace member's `package.json`. See the matching
        /// flag on `lpm install` for the full rationale.
        #[arg(long, short = 'y')]
        yes: bool,

        /// Phase 37 M3.3: remove a globally-installed package.
        /// Mutually exclusive with `--filter` / `-w` / `--fail-if-no-match`
        /// (those are project-scoped).
        ///
        /// Example: `lpm uninstall -g eslint`
        ///
        /// Equivalent to `lpm global remove <pkg>` — both invocations
        /// route through the same M3.3 implementation.
        #[arg(long, short = 'g')]
        global: bool,
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

        /// Skip `engines.lpm` / `engines.node` enforcement.
        ///
        /// `lpm add` runs the engine gate before mutating
        /// `package.json` so a constraint violation can't leave the
        /// project partially modified. See `lpm install --no-engine-strict`
        /// for the precedence chain.
        #[arg(long)]
        no_engine_strict: bool,
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

    /// Check for newer versions of direct dependencies.
    ///
    /// By default this checks both `@lpm.dev/*` and npm dependencies
    /// listed in `package.json`.
    Outdated {
        /// Limit checks to a single registry ecosystem.
        #[arg(long = "registry-only", value_enum, default_value_t = OutdatedRegistryScope::All)]
        registry_only: OutdatedRegistryScope,
    },

    /// Upgrade outdated LPM dependencies to latest versions.
    ///
    /// TTY-aware: at a terminal, shows an interactive multiselect so you
    /// can pick per-package. In CI / piped output, runs non-interactively
    /// (today's behavior). Use `-y` to force non-interactive in a TTY,
    /// or `-i` to force interactive in a non-TTY context.
    Upgrade {
        /// Upgrade to latest major versions (breaking changes).
        /// Non-interactive mode only; in interactive mode, major
        /// upgrades appear as separate rows you can toggle on.
        #[arg(long)]
        major: bool,
        /// Show what would be upgraded without making changes.
        #[arg(long)]
        dry_run: bool,
        /// Force interactive mode even without a TTY.
        #[arg(long, short = 'i')]
        interactive: bool,
        /// Skip interactive prompts (today's behavior). Useful to
        /// force non-interactive when at a TTY.
        #[arg(long, short = 'y')]
        yes: bool,
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

    /// Manage ephemeral caches under ~/.lpm/cache/ (metadata, tasks, dlx)
    /// and prune the global package store under ~/.lpm/store/.
    ///
    /// `lpm cache clean` wipes ephemeral caches only; `lpm cache prune`
    /// walks the global store and removes link entries + objects no
    /// longer reachable from any registered project, and sweeps any
    /// pending global-install tombstones from prior `lpm uninstall -g`
    /// runs. For a blunt store wipe, use `lpm store clean`.
    Cache {
        /// Action: clean, path, prune.
        action: String,

        /// Optional subcategory: metadata, tasks, or dlx.
        /// When omitted, `clean` clears all three and `path` prints the
        /// cache root. Ignored by `prune`.
        subcategory: Option<String>,

        /// `prune` only: actually remove orphan entries and sweep
        /// pending global-install tombstones. Default is dry-run.
        #[arg(long)]
        apply: bool,

        /// `prune` only: filter to entries whose `last_referenced_at`
        /// is older than this duration (`30d`, `24h`, etc.).
        #[arg(long)]
        max_age: Option<String>,

        /// `prune` only: manual repair mode. Walk only this project's
        /// `node_modules/` to collect roots; ignore the registry. Use
        /// when the registry is corrupt or after a machine restore.
        #[arg(long, value_name = "PATH")]
        project: Option<String>,
    },

    /// Manage the global content-addressable package store.
    ///
    /// Actions: verify, path, clean. For reachability-aware orphan
    /// cleanup, use `lpm cache prune`.
    Store {
        /// Action: verify, path, clean.
        action: String,

        /// Deep verification: parse package.json and validate name/version consistency.
        #[arg(long)]
        deep: bool,

        /// Auto-fix issues found during verify (e.g., refresh stale security caches).
        #[arg(long)]
        fix: bool,
    },

    /// Manage globally-installed CLI packages under ~/.lpm/global/.
    ///
    /// M2 ships read-only commands (`list`, `bin`, `path`). The full
    /// install / uninstall / update surface lands in M3 alongside the
    /// global install pipeline.
    Global {
        #[command(subcommand)]
        action: commands::global::GlobalCmd,
    },

    /// Inspect and manage `trustedDependencies` in package.json.
    ///
    /// Phase 46 P1: `lpm trust diff` shows how the current manifest's
    /// trust list differs from the last install's snapshot; `lpm trust
    /// prune` removes entries whose package is no longer installed.
    Trust {
        #[command(subcommand)]
        action: commands::trust::TrustCmd,
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

        /// CI exit code policy (`vuln`, `behavior`, or `all`).
        #[arg(
            long,
            value_name = "POLICY",
            long_help = "CI exit code policy: what triggers a non-zero exit code.\n\n\
  vuln     — only confirmed vulnerabilities (OSV/registry)\n\
  behavior — only critical/high behavioral flags\n\
  all      — either vulnerabilities or behavioral flags (default)"
        )]
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

        /// Show tag details for each match. Long form only — `-V`
        /// is reserved globally for `--version`; a duplicate short
        /// here trips a clap structural assertion under
        /// `clap_complete::generate`.
        #[arg(long)]
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
    /// `lpm rebuild` selectively runs lifecycle scripts based on the trust
    /// policy in `package.json`.
    ///
    /// Executed phases (in order): `preinstall`, `install`, `postinstall`.
    /// Other lifecycle names like `prepare` / `prepublishOnly` are recognized
    /// for detection and audit, but never executed by the install pipeline.
    ///
    /// Scripts run inside a filesystem sandbox by default — Seatbelt on
    /// macOS, landlock on Linux. The escape hatch is `--unsafe-full-env
    /// --no-sandbox`; `--no-sandbox` alone is rejected so disabling
    /// containment also requires acknowledging credential exposure.
    ///
    /// Matches `npm rebuild` / `pnpm rebuild`.
    Rebuild {
        /// Specific packages to rebuild. If omitted, rebuilds all trusted packages.
        packages: Vec<String>,

        /// Rebuild ALL packages with scripts (dangerous — bypasses trust policy).
        #[arg(long)]
        all: bool,

        /// Preview what would be rebuilt without executing scripts.
        #[arg(long)]
        dry_run: bool,

        /// Re-run scripts even for already-built packages.
        #[arg(long)]
        force: bool,

        /// Timeout per script in seconds (default: 300 = 5 minutes).
        #[arg(long)]
        timeout: Option<u64>,

        /// Pass full environment to scripts without stripping credentials.
        /// WARNING: Exposes LPM_TOKEN, NPM_TOKEN, GITHUB_TOKEN, etc. to scripts.
        ///
        /// Also required to pair with `--no-sandbox` — disabling the
        /// sandbox without this flag is rejected at parse time.
        #[arg(long)]
        unsafe_full_env: bool,

        /// Refuse to run ANY scripts, even trusted ones.
        #[arg(long)]
        deny_all: bool,

        /// Phase 46: lifecycle-script policy override (see
        /// `lpm install --policy` for the shared semantics).
        ///
        /// For `lpm rebuild` specifically, the policy governs which
        /// scripted packages enter the rebuild set at the default
        /// branch (no `--all`, no explicit package names).
        ///
        /// `deny` (default): filters to
        /// `trustedDependencies`-trusted packages only.
        ///
        /// `allow`: includes every scripted package regardless of
        /// trust (Phase 46 close-out).
        ///
        /// `triage`: filters to trusted-only, but greens are
        /// auto-promoted (Phase 46 P6) and appear in the rebuild
        /// set without explicit `trustedDependencies` entries.
        ///
        /// `--all` overrides the filter under every policy.
        ///
        /// Mutually exclusive with `--yolo` / `--triage`.
        #[arg(
            long,
            value_name = "deny|allow|triage",
            conflicts_with_all = ["rebuild_yolo", "rebuild_triage_alias"],
        )]
        policy: Option<String>,

        /// Phase 46: alias for `--policy=allow`. Includes every
        /// scripted package in the rebuild set regardless of trust
        /// (Phase 46 close-out). Equivalent to `--all` at the
        /// selection step.
        #[arg(long = "yolo", id = "rebuild_yolo", conflicts_with_all = ["policy", "rebuild_triage_alias"])]
        yolo: bool,

        /// Phase 46: alias for `--policy=triage`. Greens are
        /// auto-promoted into the rebuild set (Phase 46 P6);
        /// ambers and reds require `lpm approve-scripts`
        /// approval before they run.
        #[arg(long = "triage", id = "rebuild_triage_alias", conflicts_with_all = ["policy", "rebuild_yolo"])]
        triage_alias: bool,

        /// Phase 46 P5: run lifecycle scripts WITHOUT filesystem
        /// containment. Only reachable paired with `--unsafe-full-env`
        /// — using this alone errors. Scripts get full host access;
        /// reserve for debugging a sandbox false-positive that
        /// `sandboxWriteDirs` can't express. Mutually exclusive with
        /// `--sandbox-log`.
        #[arg(long, requires = "unsafe_full_env", conflicts_with = "sandbox_log")]
        no_sandbox: bool,

        /// Phase 46 P5 Chunk 4: run lifecycle scripts in diagnostic
        /// mode — rule triggers are logged via `sandboxd` but not
        /// enforced. **Not a safety signal.** A clean run under
        /// `--sandbox-log` does NOT indicate the script would pass
        /// under the full sandbox; it only means the logged
        /// accesses were visible for review. View reported accesses
        /// via `log show --last 5m --predicate 'senderImagePath
        /// CONTAINS "Sandbox"'` and filter by the script's PID.
        ///
        /// macOS only in Phase 46 P5: implemented via Seatbelt's
        /// `(allow (with report) default)` fallback. Linux landlock
        /// has no native observe-only primitive, so `--sandbox-log`
        /// on Linux errors at sandbox init with a remediation
        /// pointing at `--unsafe-full-env --no-sandbox`. Mutually
        /// exclusive with `--no-sandbox`.
        #[arg(long)]
        sandbox_log: bool,

        /// Skip `engines.lpm` / `engines.node` enforcement. See
        /// `lpm install --no-engine-strict` for the precedence chain.
        #[arg(long)]
        no_engine_strict: bool,
    },

    /// Health check: verify auth, registry, store, project state.
    ///
    /// Without a subcommand, runs the full check set against the
    /// current project. Subcommands target the inventory surface:
    ///
    ///   lpm doctor list                — dump every code doctor can emit
    ///   lpm doctor list --code <code>  — show one entry
    ///   lpm doctor list --category Tunnel  — filter by category
    Doctor {
        /// Auto-fix issues (install missing Node, run lpm install, run lpm fmt).
        ///
        /// Ignored when a subcommand is provided.
        #[arg(long)]
        fix: bool,

        /// Skip confirmation prompts for auto-fix actions (implies --fix).
        ///
        /// Ignored when a subcommand is provided.
        #[arg(long, short = 'y')]
        yes: bool,

        #[command(subcommand)]
        action: Option<DoctorAction>,
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
    #[command(name = "setup-npmrc")]
    SetupNpmrc {
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
        /// Node.js version spec (e.g., node@22, node@lts, 22.5.0), or "vars" to manage project env vars.
        spec: Option<String>,

        /// List installed runtime versions.
        #[arg(long)]
        list: bool,

        /// Pin only (skip install if already installed).
        #[arg(long)]
        pin: bool,
    },

    /// Manage project environment variables and secrets.
    ///
    /// Local-file management (`lpm env init`, `ls`, `set`, `get`, `delete`,
    /// `import`, `export`, `print`, `copy`, `check`) plus cloud sync
    /// (`pull`, `push`, `share`, `pair`, `diff`, `validate`), platform
    /// integrations (`push --to <platform>`, `pull --from <platform>`,
    /// `connect`, `status`), and OIDC policies (`oidc allow`, `oidc list`,
    /// `oidc pull`).
    Env {
        /// Subcommand and its arguments (e.g., `set KEY=VALUE`,
        /// `pull --org acme`, `oidc allow --provider=github …`).
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

        /// Run in all workspace packages (topological order). Mutually
        /// exclusive with `--filter` and `--affected`.
        #[arg(long, conflicts_with_all = ["filter", "affected"])]
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
    /// - `lpm approve-scripts`               — interactive walk
    /// - `lpm approve-scripts --list`        — read-only listing
    /// - `lpm approve-scripts --yes`         — bulk approve (loud)
    /// - `lpm approve-scripts <pkg>`         — approve a specific package
    /// - `lpm approve-scripts --json`        — structured output for agents
    /// - `lpm approve-scripts --global`      — review Phase-37 global installs
    #[command(name = "approve-scripts")]
    ApproveScripts {
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

        /// Phase 46 close-out: preview decisions without mutating state.
        ///
        /// In project mode, `package.json`'s `trustedDependencies` stays
        /// untouched. In global mode,
        /// `~/.lpm/global/trusted-dependencies.json` stays untouched.
        /// The review flow (card rendering, interactive prompts, version
        /// diff surfaces) runs normally; only the write step is skipped.
        /// JSON envelopes carry `"dry_run": true` so agents can detect
        /// the mode.
        ///
        /// No-op when combined with `--list` (already read-only).
        /// Combines with `--yes`, `<pkg>`, the interactive walk, and
        /// with `--global` / `--json`.
        #[arg(long)]
        dry_run: bool,

        /// Phase 37 M5: operate on the global blocked set (aggregated
        /// across every `lpm install -g` install root) instead of the
        /// current project. Approvals write to
        /// `~/.lpm/global/trusted-dependencies.json` rather than the
        /// project's `package.json`.
        #[arg(long)]
        global: bool,

        /// Phase 37 M5: when used with `--global`, group blocked rows by
        /// top-level globally-installed package during list and interactive
        /// review. Auto-enabled when the blocked set exceeds 10 entries.
        /// Persisted approvals still remain per dependency binding row.
        #[arg(long)]
        group: bool,
    },

    /// Generate a local patch for an installed package, `patch-package` style.
    ///
    /// Extracts a clean copy of the global store entry to a temp staging
    /// directory and prints the path. Edit the files in that directory,
    /// then run `lpm patch-commit <staging_dir>` to produce a unified
    /// diff under `patches/` and register it in `package.json` under
    /// `lpm.patchedDependencies`. The patch is bound to the original
    /// store integrity — drift on a future install is a hard error.
    #[command(name = "patch")]
    Patch {
        /// Package selector (`name@exact-version`). Only exact pins are
        /// accepted today; range selectors are not supported yet.
        key: String,
    },

    /// Finalize a patch staging directory created by `lpm patch`.
    ///
    /// Reads the staging breadcrumb, generates a unified diff against
    /// the store baseline, writes `patches/<key>.patch`, and updates
    /// `package.json :: lpm.patchedDependencies`.
    ///
    /// Phase 32 Phase 6.
    #[command(name = "patch-commit")]
    PatchCommit {
        /// The staging directory path printed by `lpm patch`.
        staging_dir: String,
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
        /// Run in all workspace packages. Mutually exclusive with `--filter`
        /// and `--affected` — pick one selection mode.
        #[arg(long, conflicts_with_all = ["filter", "affected"])]
        all: bool,
        /// Filter workspace packages with the Phase 32 grammar. Can be passed
        /// multiple times: `--filter foo --filter bar` unions the two sets.
        ///
        /// Grammar: exact name (`foo`), glob (`@scope/*`, `foo-*`),
        /// path glob (`./apps/*`), path exact (`{./apps/web}`),
        /// git ref (`[origin/main]`), forward closure (`foo...`, `foo^...`),
        /// reverse closure (`...foo`, `...^foo`), exclusion (`!foo`).
        #[arg(long)]
        filter: Vec<String>,
        /// Run only in packages affected by git changes (vs base branch).
        #[arg(long, conflicts_with = "all")]
        affected: bool,
        /// Git base ref for --affected (default: main).
        #[arg(long, default_value = "main")]
        base: String,
        /// Exit non-zero if no workspace package matches the filter set.
        /// Recommended in CI to catch typo'd filters early.
        #[arg(long)]
        fail_if_no_match: bool,
        /// Extra arguments passed to oxlint (e.g., --fix, src/).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Format source files (powered by Biome, lazy-downloaded on first use).
    Fmt {
        /// Check formatting without writing (CI mode, exits non-zero if unformatted).
        #[arg(long)]
        check: bool,
        /// Run in all workspace packages. Mutually exclusive with `--filter`
        /// and `--affected` — pick one selection mode.
        #[arg(long, conflicts_with_all = ["filter", "affected"])]
        all: bool,
        /// Filter workspace packages with the Phase 32 grammar. Can be passed
        /// multiple times: `--filter foo --filter bar` unions the two sets.
        #[arg(long)]
        filter: Vec<String>,
        /// Run only in packages affected by git changes (vs base branch).
        #[arg(long)]
        affected: bool,
        /// Git base ref for --affected (default: main).
        #[arg(long, default_value = "main")]
        base: String,
        /// Exit non-zero if no workspace package matches the filter set.
        #[arg(long)]
        fail_if_no_match: bool,
        /// Extra arguments passed to biome format.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Type-check the project (runs tsc --noEmit).
    Check {
        /// Run in all workspace packages. Mutually exclusive with `--filter`
        /// and `--affected` — pick one selection mode.
        #[arg(long, conflicts_with_all = ["filter", "affected"])]
        all: bool,
        /// Filter workspace packages with the Phase 32 grammar. Can be passed
        /// multiple times: `--filter foo --filter bar` unions the two sets.
        #[arg(long)]
        filter: Vec<String>,
        /// Run only in packages affected by git changes (vs base branch).
        #[arg(long)]
        affected: bool,
        /// Git base ref for --affected (default: main).
        #[arg(long, default_value = "main")]
        base: String,
        /// Exit non-zero if no workspace package matches the filter set.
        #[arg(long)]
        fail_if_no_match: bool,
        /// Extra arguments passed to tsc.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run tests (auto-detects vitest/jest/mocha).
    ///
    /// Workspace flags (`--all` / `--filter` / `--affected`) target the test
    /// suite across multiple workspace members. The trailing `args` are
    /// forwarded to the per-member runner. To pass `--all` / `--filter` etc.
    /// to the runner itself (e.g. bun's `--filter`), prefix with `--`:
    /// `lpm test -- --filter pattern`.
    Test {
        /// Run in all workspace packages. Mutually exclusive with `--filter`
        /// and `--affected` — pick one selection mode.
        #[arg(long, conflicts_with_all = ["filter", "affected"])]
        all: bool,
        /// Filter workspace packages with the Phase 32 grammar. Can be passed
        /// multiple times: `--filter foo --filter bar` unions the two sets.
        #[arg(long)]
        filter: Vec<String>,
        /// Run only in packages affected by git changes (vs base branch).
        #[arg(long)]
        affected: bool,
        /// Git base ref for --affected (default: main).
        #[arg(long, default_value = "main")]
        base: String,
        /// Exit non-zero if no workspace package matches the filter set.
        #[arg(long)]
        fail_if_no_match: bool,
        /// Extra arguments passed to the test runner.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run benchmarks (auto-detects vitest bench).
    ///
    /// Workspace flags behave the same as `lpm test`. To forward `--all`
    /// / `--filter` etc. to the bench runner itself, prefix with `--`.
    Bench {
        /// Run in all workspace packages. Mutually exclusive with `--filter`
        /// and `--affected` — pick one selection mode.
        #[arg(long, conflicts_with_all = ["filter", "affected"])]
        all: bool,
        /// Filter workspace packages with the Phase 32 grammar. Can be passed
        /// multiple times: `--filter foo --filter bar` unions the two sets.
        #[arg(long)]
        filter: Vec<String>,
        /// Run only in packages affected by git changes (vs base branch).
        #[arg(long)]
        affected: bool,
        /// Git base ref for --affected (default: main).
        #[arg(long, default_value = "main")]
        base: String,
        /// Exit non-zero if no workspace package matches the filter set.
        #[arg(long)]
        fail_if_no_match: bool,
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

        /// Disable the browser inspector that auto-starts alongside `--tunnel`.
        ///
        /// The inspector is the same surface as `lpm tunnel inspect --ui` —
        /// real-time webhook capture, replay, snapshots. The dashboard's `o`
        /// key opens it in a browser; pass `--no-inspect` to skip starting it
        /// entirely. No-op without `--tunnel`.
        #[arg(long)]
        no_inspect: bool,

        /// Port for the inspector UI (default: auto-pick a free ephemeral port).
        ///
        /// When omitted, the inspector binds `127.0.0.1:0` and the OS picks an
        /// unused port — race-free against the dev server's own port. Pass an
        /// explicit value to bind that exact port strictly. No-op without
        /// `--tunnel`.
        #[arg(long)]
        inspect_port: Option<u16>,

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

    /// Visualize the dependency graph (tree, DOT, Mermaid, JSON, stats, HTML).
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

        /// Truncate the graph to the given depth. The project root counts
        /// as level 1, direct deps as level 2. Applied at the graph level,
        /// so every output format (tree, dot, mermaid, json, stats, html)
        /// sees the same truncated set.
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

        /// With `--format html`: skip auto-opening the rendered file in the
        /// default browser. Useful in headless / CI environments where no
        /// display is available. The file is still written to
        /// `<project>/.lpm/graph.html`. No-op for other formats.
        #[arg(long)]
        no_open: bool,
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

        /// Port for the inspector UI (default: auto-pick a free ephemeral port).
        ///
        /// When omitted, the inspector binds `127.0.0.1:0` and the OS picks an
        /// unused port — race-free against `lpm dev`'s service ports or any
        /// other local server. Pass an explicit value to bind that exact port
        /// strictly (fails with a clear diagnostic if the port is in use).
        #[arg(long)]
        inspect_port: Option<u16>,

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

        /// Overwrite an existing lpm.lock.
        #[arg(long)]
        force: bool,

        /// Restore files from .backup copies created by a previous migration.
        #[arg(long)]
        rollback: bool,

        /// Reserved. The migrate flow is non-interactive today, so this
        /// flag is a no-op. It exists so scripts that already set `-y`
        /// continue to parse cleanly, and so the public CLI keeps the
        /// flag namespace once interactive prompts are wired in.
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
    ///
    /// Detects the installation channel from the executable path
    /// (npm, Homebrew, cargo, or standalone) and runs the matching
    /// upgrade command. Version discovery probes the npm registry
    /// first and falls back to GitHub Releases — no token required
    /// for either path on the common case.
    #[command(name = "self-update")]
    SelfUpdate {
        /// Bypass the 10-minute version-lookup cache and the
        /// post-failure cooldown. Forces a fresh probe regardless of
        /// recent state. Only affects the version check — not the
        /// upgrade itself, which always installs the resolved release.
        #[arg(long)]
        refresh: bool,
    },

    /// Phase 34.2: hidden subcommand for background update cache refresh.
    /// Spawned as a detached child process by the parent — never user-facing.
    #[command(name = "internal-update-check", hide = true)]
    InternalUpdateCheck,

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
    Completions {
        /// Target shell. One of: bash, zsh, fish, powershell, elvish.
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Emit the JSON Schema for an LPM config file.
    ///
    /// Auto-derived for typed schemas (`lpm.json`); hand-authored for
    /// the dynamic ones (`lpm.config.json`). The same schemas are
    /// served at `https://lpm.dev/schemas/<name>.json` for editor
    /// auto-discovery.
    ///
    /// Examples:
    /// ```bash
    /// lpm schema lpm.json                  # print to stdout
    /// lpm schema lpm.json -o schema.json   # write to file
    /// lpm schema lpm.config.json
    /// ```
    Schema {
        /// Which schema to emit. Accepts `lpm.json` or `lpm.config.json`.
        kind: String,
        /// Write to this path instead of stdout.
        #[arg(long, short = 'o')]
        out: Option<String>,
    },

    /// Catch-all: unknown subcommands are tried as package.json scripts.
    /// e.g., `lpm dev` runs the "dev" script if no built-in command matches.
    #[command(external_subcommand)]
    External(Vec<String>),
}

/// Subcommands of `lpm doctor`. Currently only `list` (the inventory
/// surface). Without a subcommand, `lpm doctor` runs the full check
/// set against the current project.
#[derive(Subcommand)]
enum DoctorAction {
    /// Dump the canonical catalog of every check `lpm doctor` can emit.
    ///
    /// Use `--json` for the structured form (suitable for piping into
    /// docs generators or automation). Filter with `--code <code>` for
    /// a single entry, or `--category <substring>` to scope by group.
    List {
        /// Filter by exact code match (e.g., `typescript_unavailable`).
        #[arg(long)]
        code: Option<String>,
        /// Filter by category — case-insensitive substring match
        /// against the catalog's category labels (e.g., `tunnel`,
        /// `manifest`).
        #[arg(long)]
        category: Option<String>,
    },
}

// `GlobalCmd` lives in `commands::global` so the subcommand type is in
// the same module as the run() handler. Imported via the dispatch site.

/// Phase 37 M3.1d: predicate that gates `lpm_global::recover()` at
/// startup. Returns `true` for any command that reads or writes
/// `~/.lpm/global/` state — recovery must run first so the manifest
/// is settled before the command sees it. Returns `false` for everything
/// else (including pure project commands, help, and version), keeping
/// the common-case startup overhead at zero.
///
/// The set is deliberately conservative: better to occasionally pay
/// for an empty-WAL scan than to skip recovery and let a destructive
/// command run against half-committed state.
/// Phase 37 M0 (rev 6): emit a one-time warning if `$LPM_HOME` lives on a
/// known-unreliable network filesystem (NFS/SMB/CIFS/AFP). Marker file
/// `~/.lpm/.network-fs-notice-shown` suppresses subsequent invocations so
/// CI / enterprise users in known-okay setups aren't nagged repeatedly.
///
/// Best-effort: if the marker check or detection fails we silently skip —
/// the warning is a courtesy, not load-bearing for correctness.
fn maybe_emit_network_fs_warning(root: &lpm_common::LpmRoot) {
    let marker = root.network_fs_notice_marker();
    if marker.exists() {
        return;
    }
    let kind = lpm_common::is_local_fs(root.root());
    if !matches!(kind, lpm_common::FsKind::Network) {
        return;
    }
    output::warn(&format!(
        "{} appears to be on a network filesystem.\n  \
         Global install concurrency guarantees require local storage — set\n  \
         LPM_HOME=/local/path to override, or expect occasional install\n  \
         serialization failures under heavy concurrent use.\n  \
         (This warning is shown once; delete {} to see it again.)",
        root.root().display(),
        marker.display(),
    ));
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::File::create(&marker);
}

/// Print `lpm <version>` followed (when applicable) by the cached
/// "update available" notice. Replaces clap's auto `--version` handler.
///
/// The notice is read from the same on-disk cache that the once-a-day
/// background refresh writes via the hidden `internal-update-check`
/// subcommand — no network call here. When the cache is missing,
/// stale-but-empty, or shows the user is already on the latest, only
/// the version line is printed (zero noise).
fn print_version_with_notice() {
    println!("lpm {}", env!("CARGO_PKG_VERSION"));
    if let Some(notice) = update_check::read_cached_notice() {
        // `read_cached_notice` already wraps the message with leading +
        // trailing newlines and colour, so we can print it as-is.
        print!("{notice}");
    }
}

fn argv_requests_top_level_version<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(flag) = args.next() else {
        return false;
    };

    if args.next().is_some() {
        return false;
    }

    flag.as_ref() == std::ffi::OsStr::new("--version")
}

fn command_needs_global_state(cmd: &Commands) -> bool {
    match cmd {
        // `install -g` (the actual install pipeline lands in M3.2 — for
        // now the dispatcher errors loudly, but recovery still runs so
        // a prior crashed install gets reconciled before the user
        // retries).
        Commands::Install { global: true, .. } => true,
        // `uninstall -g` (M3.3): same reasoning as `install -g` —
        // recovery must run first so an orphaned `[pending.<pkg>]` from
        // a crashed install gets cleaned up before uninstall sees it
        // and bails with the in-flight-install error message.
        Commands::Uninstall { global: true, .. } => true,
        // Every `lpm global *` subcommand reads at minimum the manifest.
        Commands::Global { .. } => true,
        // `store verify` needs the manifest settled so the walker sees
        // the right per-package state. `cache prune` covers the
        // reachability-aware union (which is itself listed below).
        Commands::Store { action, .. } if action == "verify" => true,
        // `cache prune --apply` walks every globally-installed package's
        // lockfile + sweeps deferred tombstones — the manifest must be
        // settled before either step runs.
        Commands::Cache { action, .. } if action == "prune" => true,
        // Any `cache clean` invocation, regardless of subcategory.
        // Bare `cache clean` cleans metadata + tasks + dlx, so the dlx
        // dir is always in scope; the per-subcategory form trivially
        // is too. Pre-fix this only triggered for `cache clean dlx`,
        // missing the bare form (audit Answer #2).
        Commands::Cache { action, .. } => action == "clean",
        // `doctor` reports on global state and may surface mid-tx
        // anomalies that recovery would have already cleaned up.
        Commands::Doctor { .. } => true,
        // Phase 37 M5: `approve-scripts --global` reads the global
        // manifest + aggregates per-install build-state files, both
        // of which need recovery to settle first.
        Commands::ApproveScripts { global: true, .. } => true,
        _ => false,
    }
}

/// Phase 68: assemble the per-invocation security overrides forwarded
/// from `lpm install -g` into the global install pipeline.
///
/// Centralizes three steps that previously lived inline in the
/// dispatcher arm:
///   1. Collapse the three mutually-exclusive policy aliases
///      (`--policy=<v>` / `--yolo` / `--triage`) into a single
///      `Option<ScriptPolicy>` via [`crate::script_policy_config::collapse_policy_flags`].
///   2. Resolve the effective policy through [`crate::script_policy_config::resolve_script_policy`]
///      with `ScriptPolicyConfig::default()` so the user-config tier
///      (`~/.lpm/config.toml`) and `force-security-floor` semantics
///      still fire — only the project-config tier (which doesn't apply
///      to `-g`, since the synthetic package.json never carries
///      `lpm.scriptPolicy`) is collapsed.
///   3. Parse `--min-release-age=<DUR>` and canonicalize the drift
///      flags via [`crate::provenance_fetch::DriftIgnorePolicy::from_cli`].
///
/// Extracted to make the wiring unit-testable: a regression that drops
/// any of the five overrides on the way to `install_global::run` is
/// caught by the tests in this module.
#[allow(clippy::too_many_arguments)]
fn build_install_global_overrides(
    allow_new: bool,
    auto_build: bool,
    policy: Option<&str>,
    yolo: bool,
    triage_alias: bool,
    min_release_age: Option<&str>,
    ignore_provenance_drift: Vec<String>,
    ignore_provenance_drift_all: bool,
) -> Result<commands::install_global::InstallGlobalOverrides, lpm_common::LpmError> {
    let cli_policy_override =
        crate::script_policy_config::collapse_policy_flags(policy, yolo, triage_alias)
            .map_err(lpm_common::LpmError::Script)?;
    let global_policy_cfg = crate::script_policy_config::ScriptPolicyConfig::default();
    let resolved_policy =
        crate::script_policy_config::resolve_script_policy(cli_policy_override, &global_policy_cfg);
    let min_release_age_override = match min_release_age {
        Some(s) => Some(crate::release_age_config::parse_duration(s)?),
        None => None,
    };
    let drift_ignore_policy = crate::provenance_fetch::DriftIgnorePolicy::from_cli(
        ignore_provenance_drift,
        ignore_provenance_drift_all,
    );
    Ok(commands::install_global::InstallGlobalOverrides {
        allow_new,
        min_release_age_override,
        drift_ignore_policy,
        // Forward the resolved policy as `Some(p)` so the inner
        // pipeline's resolver doesn't double-resolve against its own
        // (project-shape) chain.
        script_policy_override: Some(resolved_policy),
        auto_build,
    })
}

fn validate_global_install_project_scoped_flags(
    save_dev: bool,
    filter: &[String],
    workspace_root: bool,
    fail_if_no_match: bool,
    yes: bool,
) -> Result<(), lpm_common::LpmError> {
    // Phase 68: `--allow-new`, `--min-release-age`, and
    // `--ignore-provenance-drift[-all]` are now forwarded into the
    // global install pipeline (their gates fire end-to-end against the
    // synthetic project's package.json), so they are no longer rejected
    // here. The flags below remain genuinely project-scoped and have no
    // meaningful semantics on `-g`.
    if save_dev || !filter.is_empty() || workspace_root || fail_if_no_match || yes {
        return Err(lpm_common::LpmError::Script(
            "`-g` is mutually exclusive with `-D` / `--filter` / `-w` / \
             `--fail-if-no-match` / `-y` (those are project-scoped)."
                .into(),
        ));
    }
    Ok(())
}

fn validate_global_uninstall_project_scoped_flags(
    filter: &[String],
    workspace_root: bool,
    fail_if_no_match: bool,
    yes: bool,
) -> Result<(), lpm_common::LpmError> {
    if !filter.is_empty() || workspace_root || fail_if_no_match || yes {
        return Err(lpm_common::LpmError::Script(
            "`-g` is mutually exclusive with `--filter` / `-w` / \
             `--fail-if-no-match` / `-y` (those are project-scoped)."
                .into(),
        ));
    }

    Ok(())
}

/// Whether the trailing "update available" banner should be suppressed
/// for this invocation.
///
/// The banner is suppressed for every `lpm self-update` invocation,
/// regardless of outcome:
///
/// - Failure (cooldown, rate limit, transport error): the user already
///   saw the failure message; "run lpm self-update" sends them back
///   into the same loop they're trying to escape.
/// - Success: the running process is still the old version (the new
///   binary lives on disk but doesn't replace this PID), and the
///   on-disk cache now has the just-upgraded version stamped. The
///   banner predicate (`cache.latest > current`) therefore fires —
///   so the user would see `Updated to 0.38.0` immediately followed
///   by `Update available: 0.37.0 → 0.38.0 — run lpm self-update`.
///   That contradicts itself.
///
/// Suppression is per-invocation; the on-disk cache is unchanged, so
/// any other command still surfaces the banner on the next run.
fn should_suppress_update_banner(is_self_update_command: bool) -> bool {
    is_self_update_command
}

/// Phase 34.2: spawn a detached child process to refresh the update cache.
///
/// The child re-execs the current binary with `internal-update-check`.
/// The parent never waits — the child is fully detached (setsid on Unix)
/// so it survives the parent's exit and terminal signals don't propagate.
///
/// Silent on all failure paths: if `current_exe()` fails, if spawn fails,
/// etc. — the update check simply doesn't happen this time. The 24h
/// staleness gate limits spawns to at most ~1/day.
fn spawn_background_update_check() {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return,
    };

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("internal-update-check");
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.stdin(std::process::Stdio::null());

    // Detach from parent process group on Unix so terminal signals
    // (SIGINT, SIGHUP) don't propagate to the child.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid() is async-signal-safe and has no preconditions
        // beyond being called in a child process (guaranteed by pre_exec).
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    let _ = cmd.spawn(); // fire-and-forget
}

fn main() -> Result<()> {
    if argv_requests_top_level_version(std::env::args_os()) {
        print_version_with_notice();
        return Ok(());
    }

    // ── Phase 34.1: sync fast lane ──────────────────────────────────
    // If this is a bare `lpm install` (or `lpm i`) with no disqualifying
    // flags and the project is already up to date, exit immediately
    // without starting tokio, clap, tracing, or auth.
    //
    // Phase 44: package.json is read at most ONCE on the fast lane —
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
            .map(install_state::is_workspace_root_content)
            .unwrap_or(false);

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
                    output::print_header();
                    output::success(&format!("up to date ({elapsed_ms}ms)"));
                }
                std::process::exit(0);
            }
        }
    }

    // ── Normal async path ───────────────────────────────────────────
    // `LPM_MAX_BLOCKING_THREADS=<N>` is an opt-in diagnostic hook for
    // A/B benching the tokio blocking-pool size without a rebuild —
    // same pattern Phase 57 used for `LPM_SKIP_SECURITY=1`. Phase 57.1
    // measured this lever (n=20 paired, 3 cells) and found capping has
    // **no measurable wall-clock effect** on `bench/fixture-large`:
    // the parked-worker `__psynch_cvwait` samples in the close-out
    // flamegraph are off the critical path. Default behavior preserves
    // tokio's unbounded blocking pool. See the Phase 57.1 close-out doc
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

    // Set up tracing based on verbosity.
    //
    // **Phase 32 Phase 4 audit fix (D-impl-3, 2026-04-11):** the writer is
    // pinned to STDERR. Pre-fix this used `tracing_subscriber::fmt()`'s
    // default writer, which is STDOUT — meaning ANY `tracing::warn!` or
    // `tracing::info!` from anywhere in the CLI corrupted the `--json`
    // output stream by interleaving log lines with the JSON object. The
    // audit reproduced this end-to-end against `approve-scripts --yes --json`
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

    // Phase 35: lazy auth. Build the SessionManager from purely local
    // state — no network calls. Refresh is deferred to the first
    // auth-required operation, handled inside `RegistryClient` request
    // methods (Step 4). The eager `try_silent_refresh` + 24h `whoami`
    // block that lived here pre-Phase-35 is gone.
    //
    // `cli.token` carries either an explicit `--token` value or the
    // `LPM_TOKEN` env (clap merges them). When the value matches
    // `LPM_TOKEN` exactly, treat it as env-sourced so SessionManager
    // can classify it correctly; otherwise it's an explicit flag value.
    let explicit_flag_token = cli.token.clone().filter(|t| {
        std::env::var("LPM_TOKEN")
            .ok()
            .as_deref()
            .map(|env_v| env_v != t.as_str())
            .unwrap_or(true)
    });
    let session = std::sync::Arc::new(lpm_auth::SessionManager::new(
        registry_url.to_string(),
        explicit_flag_token,
    ));

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

    // Phase 37 M3.1d: run global recovery before any command that reads
    // or writes ~/.lpm/global/ state. Skipped for read-only commands
    // (`--help`, `--version`, plain project install) so path
    // construction stays side-effect-free for the common case. Idempotent
    // when no recovery is needed (empty WAL → fast no-op).
    if command_needs_global_state(&command)
        && let Ok(root) = lpm_common::LpmRoot::from_env()
    {
        // Phase 37 M0 (rev 6): one-time warning when $LPM_HOME sits on
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
                                // Manifest was at the committed state
                                // but the WAL never got the COMMIT
                                // record (Case A from the M3.1 audit).
                                // We just emitted the missing COMMIT —
                                // nothing user-visible changed.
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
                                // Surface deferred transactions to the
                                // user — they're typically transient
                                // (Windows AV holding a file) but the
                                // user should know there's pending
                                // cleanup. Audit Medium from M3.3.
                                output::warn(&format!(
                                    "global recovery deferred tx for '{}': {}",
                                    tx.package, reason
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
                return Err(e).into_diagnostic();
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

    let result = match command {
        Commands::Info {
            package,
            package_version,
        } => commands::info::run(&client, &package, package_version.as_deref(), cli.json).await,
        Commands::Search { query, limit } => {
            commands::search::run(&client, &query, limit, cli.json).await
        }
        Commands::Quality { package } => commands::quality::run(&client, &package, cli.json).await,
        Commands::Whoami => commands::whoami::run(&client, cli.json).await,
        Commands::Health => commands::health::run(&client, registry_url, cli.json).await,
        Commands::Download {
            package,
            package_version,
            output,
        } => {
            commands::download::run(
                &client,
                &package,
                package_version.as_deref(),
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
            strict_integrity,
            min_release_age,
            ignore_provenance_drift,
            ignore_provenance_drift_all,
            linker,
            no_skills,
            no_editor_setup,
            no_security_summary,
            auto_build,
            no_engine_strict,
            filter,
            workspace_root,
            fail_if_no_match,
            yes,
            exact,
            tilde,
            save_prefix,
            global,
            replace_bin,
            alias,
            policy,
            yolo,
            triage_alias,
        } => {
            // Phase 37 M3.2: route `lpm install --global` / `-g` to
            // the persistent IsolatedInstall pipeline. M3.2 ships
            // fresh-install only (no upgrade); upgrade lands in M3.4.
            // Collision resolution lands in M4. The pipeline takes
            // care of the three-phase tx (Intent + slow install +
            // commit) and the recovery hook above already handled
            // any prior crashed install for this command's package.
            if global {
                if packages.is_empty() {
                    return Err(lpm_common::LpmError::Script(
                        "`lpm install --global` requires a package spec (e.g. \
                         `lpm install -g eslint` or `lpm install -g typescript@^5`)"
                            .into(),
                    ))
                    .into_diagnostic();
                }
                if packages.len() > 1 {
                    return Err(lpm_common::LpmError::Script(format!(
                        "`lpm install --global` accepts a single package per invocation \
                         in M3.2 (got {}). Run it once per package, or wait for the M3.4 \
                         multi-target update path.",
                        packages.len()
                    )))
                    .into_diagnostic();
                }
                // Reject any project-install-only flag that's
                // meaningless for global. Keeps the surface honest.
                validate_global_install_project_scoped_flags(
                    save_dev,
                    &filter,
                    workspace_root,
                    fail_if_no_match,
                    yes,
                )
                .into_diagnostic()?;
                // Phase 37 M4: parse collision-resolution flags. Syntactic
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
                ); // M3.2 honors none of these yet; M3.4 will wire selected flags.

                let overrides = build_install_global_overrides(
                    allow_new,
                    auto_build,
                    policy.as_deref(),
                    yolo,
                    triage_alias,
                    min_release_age.as_deref(),
                    ignore_provenance_drift,
                    ignore_provenance_drift_all,
                )
                .into_diagnostic()?;

                return commands::install_global::run(
                    &client,
                    &packages[0],
                    resolution,
                    cli.json,
                    overrides,
                )
                .await
                .into_diagnostic();
            }

            // M4 audit Finding 2: reject collision-resolution flags on
            // the non-global install path. These flags only make sense
            // for `-g` installs (the global command-shim system is the
            // ONLY surface that can collide — project installs write
            // under `node_modules/.bin/` per-project with no global
            // scope). Accepting them silently would look successful
            // while dropping the user's resolution intent entirely.
            if !replace_bin.is_empty() || !alias.is_empty() {
                return Err(lpm_common::LpmError::Script(
                    "`--replace-bin` and `--alias` are collision-resolution flags for global \
                     installs (`-g`) only. Add `-g` to install globally, or drop the flags for \
                     a project install."
                        .into(),
                ))
                .into_diagnostic();
            }

            // Token expiry warnings (Feature 42)
            if !cli.json {
                for warning in auth::check_token_expiry_warnings() {
                    output::warn(&warning);
                }
            }
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            let cfg = commands::config::GlobalConfig::load();
            let eff_allow_new = allow_new || cfg.get_bool("allowNew").unwrap_or(false);

            // engines.lpm / engines.node enforcement (workspace root).
            // Runs before any install work so a constraint violation
            // exits cheaply with a structured error code. The gate
            // discovers the workspace root internally so a member-dir
            // invocation honors the root's `lpm.engineStrict` opt-out.
            engine_check::enforce(&cwd, no_engine_strict, cli.json)?;

            // Phase 46 P3: parse `--min-release-age=<dur>` once, at the
            // clap layer, so invalid input surfaces before any install
            // work starts. `None` means the flag was absent and the
            // resolver walks the full precedence chain inside
            // `run_with_options`.
            let min_release_age_override: Option<u64> = match min_release_age.as_deref() {
                Some(s) => Some(release_age_config::parse_duration(s)?),
                None => None,
            };

            // Phase 46 P4 Chunk 4: canonicalize
            // `--ignore-provenance-drift <pkg>` + `--ignore-provenance-drift-all`
            // into a single policy enum. Per Q2 of the P4 kickoff,
            // `-all` supersedes the per-package list — no clap
            // mutex, just collapse internally.
            let drift_ignore_policy = provenance_fetch::DriftIgnorePolicy::from_cli(
                ignore_provenance_drift,
                ignore_provenance_drift_all,
            );

            // Phase 46 P1: resolve the effective script-policy through
            // the precedence chain (CLI > package.json > global >
            // default). Clap enforces mutual exclusion between the
            // three flags, so `collapse_policy_flags` only needs to
            // validate the `--policy` string payload. In P1 the
            // resolved value is logged but not yet branched on — the
            // actual tier-aware execution change lands with the
            // sandbox in a later phase.
            //
            // Loading the config here (rather than inside
            // `resolve_script_policy`) lets us surface a typo in
            // `package.json > lpm > scriptPolicy` to the user: a
            // team-shared manifest must not silently fall through to
            // each developer's `~/.lpm/config.toml` on typos (see
            // audit Finding 2). The warning emission is deferred to
            // AFTER resolve so the user sees what actually took effect
            // (the CLI override may have superseded the project value
            // anyway — audit v3 Finding 1).
            let script_policy_cfg =
                script_policy_config::ScriptPolicyConfig::from_package_json(&cwd);
            // Phase 46 P2 Chunk 5: preserve the collapsed CLI override
            // separately so we can forward it to install entry points
            // that re-resolve against a workspace member's config.
            // `effective_script_policy` below is the CWD-level view
            // used for logging; each install target resolves its own.
            let cli_script_policy_override =
                script_policy_config::collapse_policy_flags(policy.as_deref(), yolo, triage_alias)
                    .map_err(lpm_common::LpmError::Script)?;
            let effective_script_policy = script_policy_config::resolve_script_policy(
                cli_script_policy_override,
                &script_policy_cfg,
            );
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

            // Phase 33: build the SaveFlags struct from the per-command CLI
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
                    // Top-level dispatch passes ONLY the CLI flag through;
                    // `~/.lpm/config.toml > linker`, `LPM_LINKER`, and
                    // `package.json > lpm > linker` are resolved inside the
                    // install pipeline so every internal caller (add /
                    // upgrade / dev / migrate / deploy / dlx / -g / global
                    // update / doctor) gets the same precedence chain
                    // without each call site re-implementing it.
                    let cli_linker = linker.map(LinkerCli::into_linker_mode);

                    commands::install::run_with_options(
                        &client,
                        &cwd,
                        cli.json,
                        offline,
                        force,
                        eff_allow_new,
                        strict_integrity,
                        cli_linker,
                        eff_no_skills,
                        eff_no_editor,
                        eff_no_sec,
                        eff_auto_build,
                        None, // target_set: bare-install path is single-target
                        None, // direct_versions_out: bare install does not finalize a manifest
                        cli_script_policy_override,
                        min_release_age_override,
                        drift_ignore_policy,
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
                    yes,
                    cli.json,
                    eff_allow_new,
                    force,
                    save_flags,
                    cli_script_policy_override,
                    min_release_age_override,
                    drift_ignore_policy,
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
                        yes,
                        cli.json,
                        eff_allow_new,
                        force,
                        save_flags,
                        cli_script_policy_override,
                        min_release_age_override,
                        drift_ignore_policy,
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
                        cli_script_policy_override,
                        min_release_age_override,
                        drift_ignore_policy,
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
            yes,
            global,
        } => {
            // Phase 37 M3.3: `lpm uninstall -g <pkg>` routes to the
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
                         in M3.3 (got {}). Run it once per package.",
                        packages.len()
                    )))
                } else if let Err(error) = validate_global_uninstall_project_scoped_flags(
                    &filter,
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
        Commands::Config { action, key, value } => {
            commands::config::run(&action, key.as_deref(), value.as_deref(), cli.json).await
        }
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
        Commands::Global { action } => commands::global::run(&client, action, cli.json).await,
        Commands::Trust { action } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::trust::run(&action, &cwd).await
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
        Commands::Rebuild {
            packages,
            all,
            dry_run,
            force,
            timeout,
            unsafe_full_env,
            deny_all,
            policy,
            yolo,
            triage_alias,
            no_sandbox,
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
            // Phase 46 P1: resolve the effective script-policy through
            // the precedence chain. Clap already enforced mutual-
            // exclusion between `--policy`, `--yolo`, `--triage`, so
            // at most one of the three is set per invocation.
            // `lpm rebuild` itself does not branch on the resolved value
            // in P1 — tier-aware execution lands with the sandbox in
            // a later phase. Loading the config here also surfaces
            // typos in `package.json > lpm > scriptPolicy` instead of
            // silently falling through (audit Finding 2). Warning
            // emission is deferred until after resolve so the user
            // sees what actually took effect — the CLI override may
            // have superseded the project value anyway (audit v3
            // Finding 1).
            let script_policy_cfg =
                script_policy_config::ScriptPolicyConfig::from_package_json(&cwd);
            let cli_override =
                script_policy_config::collapse_policy_flags(policy.as_deref(), yolo, triage_alias)
                    .map_err(lpm_common::LpmError::Script)?;
            let effective =
                script_policy_config::resolve_script_policy(cli_override, &script_policy_cfg);
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
                unsafe_full_env,
                deny_all,
                no_sandbox,
                sandbox_log,
                // Phase 46 P6 Chunk 1: pass the resolved effective
                // policy through. Previously `effective` was computed
                // only for the typo-warning + debug log above and
                // never reached `rebuild::run`; Chunk 1 closes that gap
                // so Chunk 2 can consult it for green-tier promotion
                // without another signature change.
                effective,
            )
            .await
        }
        Commands::Doctor { fix, yes, action } => match action {
            Some(DoctorAction::List { code, category }) => {
                commands::doctor::list(cli.json, code.as_deref(), category.as_deref())
            }
            None => {
                let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
                commands::doctor::run(&client, registry_url, &cwd, cli.json, fix || yes, yes).await
            }
        },
        Commands::SwiftRegistry { force } => {
            commands::swift_registry::run(registry_url, cli.json, force).await
        }
        Commands::Mcp { action, name } => {
            commands::mcp::run(&action, name.as_deref(), cli.json).await
        }
        Commands::Use { spec, list, pin } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            if list {
                commands::r#use::run("list", spec.as_deref(), &cwd, cli.json).await
            } else if pin {
                let s = spec.as_deref().ok_or_else(|| {
                    lpm_common::LpmError::Script(
                        "missing version. Usage: lpm use --pin node@22.5.0".into(),
                    )
                })?;
                commands::r#use::run("pin", Some(s), &cwd, cli.json).await
            } else if let Some(s) = &spec {
                // `lpm use node@20` = install + pin (one command does both)
                commands::r#use::run("install", Some(s.as_str()), &cwd, cli.json).await?;
                commands::r#use::run("pin", Some(s.as_str()), &cwd, cli.json).await
            } else {
                // No spec, no flags — show list
                commands::r#use::run("list", None, &cwd, cli.json).await
            }
        }
        Commands::Env { extra: _ } => {
            // Subcommand args are re-parsed from raw argv inside run().
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            commands::env::run(&client, &cwd, cli.json).await
        }
        Commands::SetupNpmrc {
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
                let bin_hint = commands::run::ensure_runtime(&cwd).await;
                commands::run::run_watch(&cwd, &scripts[0], &args, env.as_deref(), bin_hint)
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
            commands::run::dlx(&client, &cwd, &package, &args, refresh).await
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
            commands::deploy::run(
                &client,
                &cwd,
                &output_path,
                &filter,
                force,
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
                // Phase 37 M5: global-scoped approve-scripts reads the
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
                    ))
                    .into_diagnostic();
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
        Commands::Plugin { action, name } => {
            commands::plugin::run(&action, name.as_deref(), cli.json).await
        }
        Commands::Lint {
            all,
            filter,
            affected,
            base,
            fail_if_no_match,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            tool_pin_validation::warn_unsupported_tool_pins_once(&cwd);
            if all || affected || !filter.is_empty() {
                let affected_ref = if affected { Some(base.as_str()) } else { None };
                commands::tools::tool_workspace(
                    &cwd,
                    "lint",
                    &args,
                    false,
                    &filter,
                    affected_ref,
                    fail_if_no_match,
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
            affected,
            base,
            fail_if_no_match,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            tool_pin_validation::warn_unsupported_tool_pins_once(&cwd);
            if all || affected || !filter.is_empty() {
                let affected_ref = if affected { Some(base.as_str()) } else { None };
                commands::tools::tool_workspace(
                    &cwd,
                    "fmt",
                    &args,
                    check,
                    &filter,
                    affected_ref,
                    fail_if_no_match,
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
            affected,
            base,
            fail_if_no_match,
            args,
        } => {
            let cwd = std::env::current_dir().map_err(lpm_common::LpmError::Io)?;
            tool_pin_validation::warn_unsupported_tool_pins_once(&cwd);
            if all || affected || !filter.is_empty() {
                let affected_ref = if affected { Some(base.as_str()) } else { None };
                commands::tools::tool_workspace(
                    &cwd,
                    "check",
                    &args,
                    false,
                    &filter,
                    affected_ref,
                    fail_if_no_match,
                    cli.json,
                )
                .await
            } else {
                commands::tools::check(&cwd, &args, cli.json).await
            }
        }
        Commands::Test {
            all,
            filter,
            affected,
            base,
            fail_if_no_match,
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
                affected,
                &base,
                fail_if_no_match,
                cli.json,
            )
            .await
        }
        Commands::Bench {
            all,
            filter,
            affected,
            base,
            fail_if_no_match,
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
                affected,
                &base,
                fail_if_no_match,
                cli.json,
            )
            .await
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
            no_inspect,
            inspect_port,
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

            // Resolve token if tunnel is enabled. Phase 35: go through
            // the SessionManager attached to `client`, so the
            // refresh-only-state recovery (audit fix #1) and the
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
            // Phase 35: tunnel requires a session-backed login (same
            // contract as `dev --tunnel` above). The session is
            // attached to `client` from main.rs; ask it for a
            // `SessionRequired` bearer.
            let resolved_token = match client.session() {
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
            };
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
        Commands::Completions { shell } => commands::completions::run(shell),
        Commands::Schema { kind, out } => commands::schema::run(&kind, out.as_deref()),
        Commands::InternalUpdateCheck => {
            // Phase 34.2: hidden subcommand — unconditionally refresh the
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
            let script_name = &args[0];
            let extra_args = if args.len() > 1 { &args[1..] } else { &[] };
            let bin_hint = commands::run::ensure_runtime(&cwd).await;
            commands::run::run(&cwd, script_name, extra_args, None, false, &bin_hint).await
        }
    };

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

    // Phase 34.2: spawn a detached child process to refresh the update cache
    // if stale. The parent never waits for it — command exit is immediate.
    // The staleness check is sync (file stat + timestamp comparison).
    if update_check::is_stale() {
        spawn_background_update_check();
    }

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

    // ─── Phase 37 audit follow-up: -v / -V / --version + verbose ───
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

    /// Banner suppression: every `lpm self-update` invocation
    /// suppresses the trailing banner; everything else lets it through.
    ///
    /// Failure case: re-emitting "run lpm self-update" right after the
    /// command itself failed loops the user.
    ///
    /// Success case: the running PID is still the old binary while the
    /// on-disk cache has been stamped with the just-upgraded `latest`,
    /// so the banner predicate fires and produces the contradictory
    /// `Updated to X` + `Update available: <old> → X` pair.
    ///
    /// Other commands must NOT suppress: a transient failure on
    /// `lpm install` would otherwise swallow the user's "you're behind
    /// on releases" signal.
    #[test]
    fn should_suppress_update_banner_only_on_self_update() {
        assert!(
            should_suppress_update_banner(true),
            "self-update → suppress (covers both failure-loop and success-contradiction)"
        );
        assert!(
            !should_suppress_update_banner(false),
            "any other command → show banner"
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
    fn top_level_long_version_is_handled_before_clap() {
        assert!(argv_requests_top_level_version(["lpm", "--version"]));
        assert!(!argv_requests_top_level_version(["lpm", "info", "react"]));
        assert!(!argv_requests_top_level_version([
            "lpm",
            "info",
            "react",
            "--version",
            "1.0.0"
        ]));
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
    fn lowercase_v_after_subcommand_is_version_not_verbose() {
        // Intentional behaviour change: pre-Phase 37 audit, `-v` was
        // the short for `--verbose`. It is now `--version`'s alias,
        // matching npm/pnpm/yarn. Anyone scripting `lpm <cmd> -v`
        // for verbose output must switch to `--verbose`.
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
            Some(Commands::Info {
                package,
                package_version,
            }) => {
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
            Some(Commands::Download {
                package,
                package_version,
                output,
            }) => {
                assert_eq!(package, "react");
                assert_eq!(package_version.as_deref(), Some("1.0.0"));
                assert!(output.is_none());
            }
            _ => panic!("expected download command"),
        }
    }

    #[test]
    fn print_version_with_notice_does_not_panic() {
        // Smoke test: the version printer works even when no cache
        // file exists (the notice helper returns None silently).
        // We can't easily assert on stdout from a unit test without
        // a writer abstraction, but the smoke test catches obvious
        // breakage.
        print_version_with_notice();
    }

    // ─── Phase 37 M3.1d: command_needs_global_state predicate ─────

    fn parse(args: &[&str]) -> Commands {
        Cli::try_parse_from(args)
            .unwrap()
            .command
            .expect("test parse missing subcommand")
    }

    #[test]
    fn predicate_true_for_install_global() {
        let cmd = parse(&["lpm", "install", "-g", "eslint"]);
        assert!(command_needs_global_state(&cmd));
    }

    #[test]
    fn predicate_false_for_install_without_global() {
        let cmd = parse(&["lpm", "install", "eslint"]);
        assert!(!command_needs_global_state(&cmd));
    }

    #[test]
    fn predicate_true_for_uninstall_global() {
        let cmd = parse(&["lpm", "uninstall", "-g", "eslint"]);
        assert!(command_needs_global_state(&cmd));
    }

    #[test]
    fn predicate_false_for_uninstall_without_global() {
        let cmd = parse(&["lpm", "uninstall", "eslint"]);
        assert!(!command_needs_global_state(&cmd));
    }

    #[test]
    fn predicate_true_for_every_global_subcommand() {
        for args in [
            &["lpm", "global", "list"][..],
            &["lpm", "global", "bin"][..],
            &["lpm", "global", "path", "eslint"][..],
        ] {
            assert!(
                command_needs_global_state(&parse(args)),
                "expected true for {args:?}"
            );
        }
    }

    #[test]
    fn predicate_true_for_store_verify_and_cache_prune() {
        // `store verify` reads per-package state from the manifest;
        // `cache prune --apply` walks every globally-installed package's
        // lockfile + sweeps deferred tombstones. Both need the manifest
        // settled before they run.
        assert!(command_needs_global_state(&parse(&[
            "lpm", "store", "verify"
        ])));
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "prune"
        ])));
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "prune", "--apply"
        ])));
    }

    #[test]
    fn predicate_false_for_store_clean_and_path() {
        // Destructive `store clean` doesn't read the global manifest;
        // `store path` is read-only print. Neither needs recovery.
        assert!(!command_needs_global_state(&parse(&[
            "lpm", "store", "clean"
        ])));
        assert!(!command_needs_global_state(&parse(&[
            "lpm", "store", "path"
        ])));
    }

    #[test]
    fn predicate_true_for_every_cache_clean_form() {
        // Any `cache clean` invocation can touch the shared dlx dir
        // (bare form cleans all three subcategories), so all forms
        // gate on recovery. Audit Answer #2.
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "clean"
        ])));
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "clean", "dlx"
        ])));
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "clean", "metadata"
        ])));
        assert!(command_needs_global_state(&parse(&[
            "lpm", "cache", "clean", "tasks"
        ])));
        // Read-only `cache path` does not.
        assert!(!command_needs_global_state(&parse(&[
            "lpm", "cache", "path"
        ])));
    }

    #[test]
    fn predicate_true_for_doctor() {
        assert!(command_needs_global_state(&parse(&["lpm", "doctor"])));
    }

    #[test]
    fn predicate_false_for_help_and_pure_project_commands() {
        // Plain `lpm install` / `lpm run build` / `lpm version` should
        // never trigger recovery — common-case startup must stay zero
        // overhead.
        assert!(!command_needs_global_state(&parse(&["lpm", "install"])));
        assert!(!command_needs_global_state(&parse(&[
            "lpm", "run", "build"
        ])));
    }

    // -- Finding #1: CLI parser must handle `lpm run build` without `--` --

    #[test]
    fn run_single_script_parses() {
        let cli = Cli::try_parse_from(["lpm", "run", "build"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
            Commands::Run { filter, .. } => {
                assert_eq!(filter, vec!["foo".to_string(), "@ui/*".to_string()]);
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

    // ── Phase 32 Phase 1 M7: lpm filter subcommand ────────────────────────

    #[test]
    fn filter_command_parses_positional_exprs() {
        let cli = Cli::try_parse_from(["lpm", "filter", "@ui/*", "core"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
            Commands::Filter { exprs, explain, .. } => {
                assert_eq!(exprs, vec!["foo".to_string()]);
                assert!(explain, "--explain must enable explain mode");
            }
            _ => panic!("expected Filter command"),
        }
    }

    #[test]
    fn filter_command_explain_and_fail_if_no_match_compose() {
        let cli = Cli::try_parse_from(["lpm", "filter", "core", "--explain", "--fail-if-no-match"])
            .unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        let cli =
            Cli::try_parse_from(["lpm", "install", "typescript", "--workspace-root"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
            Commands::Install {
                fail_if_no_match, ..
            } => {
                assert!(fail_if_no_match);
            }
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn install_yes_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "install", "react", "-y"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Install { packages, yes, .. } => {
                assert_eq!(packages, vec!["react".to_string()]);
                assert!(yes, "-y must set the install confirmation bypass flag");
            }
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn install_save_dev_with_filter_composes() {
        let cli = Cli::try_parse_from(["lpm", "install", "-D", "vitest", "--filter", "./apps/*"])
            .unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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

    #[test]
    fn install_global_rejects_project_scoped_yes_flag() {
        let cli = Cli::try_parse_from(["lpm", "install", "-g", "eslint", "-y"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Install {
                save_dev,
                filter,
                workspace_root,
                fail_if_no_match,
                yes,
                global,
                ..
            } => {
                assert!(global);
                assert!(yes);

                let err = validate_global_install_project_scoped_flags(
                    save_dev,
                    &filter,
                    workspace_root,
                    fail_if_no_match,
                    yes,
                )
                .unwrap_err();

                match err {
                    lpm_common::LpmError::Script(message) => {
                        assert!(message.contains("`-y`"));
                        assert!(message.contains("project-scoped"));
                    }
                    other => panic!("expected Script error, got {other:?}"),
                }
            }
            _ => panic!("expected Install command"),
        }
    }

    // Phase 68: the previous Phase 46 P3/P4 tests that pinned validator
    // rejections for `--allow-new`, `--min-release-age`, and
    // `--ignore-provenance-drift[-all]` on `-g` are removed because
    // those flags are now FORWARDED into the global install pipeline.
    // End-to-end coverage that they actually take effect on `-g` lives
    // in `tests/workflows/tests/install_global_drift.rs` and
    // `tests/workflows/tests/install_global_policy.rs`.

    /// Confirm the Phase 68 contract on the validator's surface area:
    /// the four flags previously rejected on `-g` are now accepted by
    /// the validator, and `-y` remains the project-only flag it
    /// rejects.
    #[test]
    fn install_global_validator_only_rejects_project_scoped_grouping_flags() {
        // Genuine project-only flag: still rejected.
        let err = validate_global_install_project_scoped_flags(true, &[], false, false, false)
            .unwrap_err();
        match err {
            lpm_common::LpmError::Script(message) => {
                assert!(message.contains("project-scoped"));
            }
            other => panic!("expected Script error, got {other:?}"),
        }

        // No project-only flags set → accept.
        validate_global_install_project_scoped_flags(false, &[], false, false, false).unwrap();
    }

    // ── Phase 68 forwarding regression tests ─────────────────────────
    //
    // These tests pin the wiring between CLI args and
    // `InstallGlobalOverrides`. A regression that drops any of the
    // five overrides on the way to `install_global::run` is caught
    // here. Validator acceptance (above) is necessary but not
    // sufficient — without these, a future refactor that silently
    // hardcoded e.g. `allow_new: false` inside the bundle constructor
    // would still leave the validator-acceptance suite green.

    use crate::provenance_fetch::DriftIgnorePolicy;
    use crate::script_policy_config::ScriptPolicy;

    #[test]
    fn build_install_global_overrides_threads_allow_new_and_auto_build_bools() {
        let o = build_install_global_overrides(true, true, None, false, false, None, vec![], false)
            .unwrap();
        assert!(
            o.allow_new,
            "allow_new must reach the bundle so the cooldown gate is bypassed"
        );
        assert!(
            o.auto_build,
            "auto_build must reach the bundle so triage greens auto-execute"
        );

        let o =
            build_install_global_overrides(false, false, None, false, false, None, vec![], false)
                .unwrap();
        assert!(!o.allow_new);
        assert!(!o.auto_build);
    }

    #[test]
    fn build_install_global_overrides_parses_min_release_age_duration() {
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            Some("72h"),
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(
            o.min_release_age_override,
            Some(72 * 3600),
            "72h must parse to 259_200 seconds and reach the bundle"
        );

        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            Some("0"),
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(
            o.min_release_age_override,
            Some(0),
            "explicit zero must reach the bundle (disables cooldown for this invocation)"
        );

        // No override → None reaches the bundle (fallback to chain default).
        let o =
            build_install_global_overrides(false, false, None, false, false, None, vec![], false)
                .unwrap();
        assert!(o.min_release_age_override.is_none());
    }

    #[test]
    fn build_install_global_overrides_rejects_garbage_min_release_age() {
        let err = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            Some("garbage"),
            vec![],
            false,
        )
        .unwrap_err();
        // Don't pin the exact wording (owned by release_age_config),
        // but the parser MUST surface an error rather than silently
        // dropping the override.
        assert!(
            err.to_string().contains("garbage"),
            "garbage min-release-age must surface a parser error: {err}"
        );
    }

    #[test]
    fn build_install_global_overrides_canonicalizes_drift_ignore_policy() {
        // Per-package list → IgnoreNames.
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec!["axios".to_string(), "lodash".to_string()],
            false,
        )
        .unwrap();
        match o.drift_ignore_policy {
            DriftIgnorePolicy::IgnoreNames(set) => {
                assert!(set.contains("axios") && set.contains("lodash"));
            }
            other => panic!("expected IgnoreNames, got {other:?}"),
        }

        // -all wins over per-package list.
        let o = build_install_global_overrides(
            false,
            false,
            None,
            false,
            false,
            None,
            vec!["axios".to_string()],
            true,
        )
        .unwrap();
        assert!(matches!(
            o.drift_ignore_policy,
            DriftIgnorePolicy::IgnoreAll
        ));

        // Empty + false → EnforceAll.
        let o =
            build_install_global_overrides(false, false, None, false, false, None, vec![], false)
                .unwrap();
        assert!(matches!(
            o.drift_ignore_policy,
            DriftIgnorePolicy::EnforceAll
        ));
    }

    #[test]
    fn build_install_global_overrides_resolves_script_policy_aliases() {
        // --policy=allow → resolved Allow.
        let o = build_install_global_overrides(
            false,
            false,
            Some("allow"),
            false,
            false,
            None,
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(o.script_policy_override, Some(ScriptPolicy::Allow));

        // --yolo → Allow.
        let o =
            build_install_global_overrides(false, false, None, true, false, None, vec![], false)
                .unwrap();
        assert_eq!(o.script_policy_override, Some(ScriptPolicy::Allow));

        // --triage → Triage.
        let o =
            build_install_global_overrides(false, false, None, false, true, None, vec![], false)
                .unwrap();
        assert_eq!(o.script_policy_override, Some(ScriptPolicy::Triage));

        // --policy=deny → Deny (explicit; not ambient default).
        let o = build_install_global_overrides(
            false,
            false,
            Some("deny"),
            false,
            false,
            None,
            vec![],
            false,
        )
        .unwrap();
        assert_eq!(o.script_policy_override, Some(ScriptPolicy::Deny));

        // No flag → resolves to the default (Deny) via the resolver.
        // Use a scoped HOME so the developer's ~/.lpm/config.toml
        // doesn't leak into the test (the resolver consults the
        // user-config tier).
        let _env = crate::test_env::ScopedEnv::set([(
            "HOME",
            std::ffi::OsString::from(std::env::temp_dir().to_str().unwrap()),
        )]);
        let o =
            build_install_global_overrides(false, false, None, false, false, None, vec![], false)
                .unwrap();
        // The resolver returns the default — Some(Deny). We forward
        // it as `Some` so the inner pipeline's resolver doesn't
        // double-resolve.
        assert!(o.script_policy_override.is_some());
    }

    #[test]
    fn build_install_global_overrides_rejects_unknown_policy_value() {
        let err = build_install_global_overrides(
            false,
            false,
            Some("yolo"), // Not a canonical --policy value (the alias is `--yolo`, not `--policy=yolo`).
            false,
            false,
            None,
            vec![],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("yolo"),
            "unknown policy value must surface a parser error: {err}"
        );
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
        match cli.command.expect("test parse missing subcommand") {
            Commands::Uninstall {
                packages,
                filter,
                workspace_root,
                fail_if_no_match,
                ..
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
        match cli.command.expect("test parse missing subcommand") {
            Commands::Uninstall { workspace_root, .. } => {
                assert!(workspace_root);
            }
            _ => panic!("expected Uninstall command"),
        }
    }

    #[test]
    fn uninstall_workspace_root_long_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "uninstall", "shared", "--workspace-root"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
            Commands::Uninstall {
                fail_if_no_match, ..
            } => {
                assert!(fail_if_no_match);
            }
            _ => panic!("expected Uninstall command"),
        }
    }

    #[test]
    fn uninstall_yes_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "uninstall", "lodash", "-y"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Uninstall { packages, yes, .. } => {
                assert_eq!(packages, vec!["lodash".to_string()]);
                assert!(yes, "-y must set the uninstall confirmation bypass flag");
            }
            _ => panic!("expected Uninstall command"),
        }
    }

    #[test]
    fn uninstall_global_rejects_project_scoped_yes_flag() {
        let cli = Cli::try_parse_from(["lpm", "uninstall", "-g", "eslint", "-y"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Uninstall {
                filter,
                workspace_root,
                fail_if_no_match,
                yes,
                global,
                ..
            } => {
                assert!(global);
                assert!(yes);

                let err = validate_global_uninstall_project_scoped_flags(
                    &filter,
                    workspace_root,
                    fail_if_no_match,
                    yes,
                )
                .unwrap_err();

                match err {
                    lpm_common::LpmError::Script(message) => {
                        assert!(message.contains("`-y`"));
                        assert!(message.contains("project-scoped"));
                    }
                    other => panic!("expected Script error, got {other:?}"),
                }
            }
            _ => panic!("expected Uninstall command"),
        }
    }

    #[test]
    fn uninstall_visible_alias_un_still_works() {
        // The pre-Phase-2 visible alias `un` must continue to parse with
        // the new flags.
        let cli = Cli::try_parse_from(["lpm", "un", "foo", "-w"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
        let cli = Cli::try_parse_from(["lpm", "deploy", "/prod/api", "--filter", "api"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
        let cli =
            Cli::try_parse_from(["lpm", "deploy", "/prod/web", "--filter", "@scope/web"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Deploy { filter, .. } => {
                assert_eq!(filter, vec!["@scope/web".to_string()]);
            }
            _ => panic!("expected Deploy command"),
        }
    }

    #[test]
    fn deploy_command_force_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "deploy", "/prod/api", "--filter", "api", "--force"])
            .unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Deploy { force, .. } => assert!(force),
            _ => panic!("expected Deploy command"),
        }
    }

    #[test]
    fn deploy_command_dry_run_flag_parses() {
        let cli =
            Cli::try_parse_from(["lpm", "deploy", "/prod/api", "--filter", "api", "--dry-run"])
                .unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
            Commands::Deploy { filter, .. } => {
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
            Commands::ApproveScripts {
                package,
                yes,
                list,
                global,
                group,
                dry_run,
            } => {
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
            Commands::ApproveScripts { package, .. } => {
                assert_eq!(package, Some("esbuild".to_string()));
            }
            _ => panic!("expected ApproveScripts command"),
        }
    }

    #[test]
    fn approve_scripts_with_versioned_pkg_argument_parses() {
        let cli = Cli::try_parse_from(["lpm", "approve-scripts", "esbuild@0.25.1"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::ApproveScripts { package, .. } => {
                assert_eq!(package, Some("esbuild@0.25.1".to_string()));
            }
            _ => panic!("expected ApproveScripts command"),
        }
    }

    #[test]
    fn approve_scripts_yes_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "approve-scripts", "--yes"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::ApproveScripts { yes, .. } => {
                assert!(yes);
            }
            _ => panic!("expected ApproveScripts command"),
        }
    }

    #[test]
    fn approve_scripts_list_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "approve-scripts", "--list"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::ApproveScripts { list, .. } => {
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
            Commands::ApproveScripts { list, .. } => assert!(list),
            _ => panic!("expected ApproveScripts command"),
        }
    }

    #[test]
    fn approve_scripts_global_group_list_parses() {
        let cli = Cli::try_parse_from(["lpm", "approve-scripts", "--global", "--group", "--list"])
            .unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::ApproveScripts {
                global,
                group,
                list,
                ..
            } => {
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
            Commands::Rebuild {
                force, packages, ..
            } => {
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
    fn rebuild_no_sandbox_requires_unsafe_full_env() {
        // Disabling the sandbox alone must fail at parse time so the
        // user can't silently drop containment without also opting into
        // the highly-visible credential-exposure flag. Pairing is
        // enforced via clap `requires = "unsafe_full_env"` at the
        // `--no-sandbox` arg site; this test guards against accidental
        // removal of that constraint.
        let result = Cli::try_parse_from(["lpm", "rebuild", "--no-sandbox"]);
        assert!(
            result.is_err(),
            "`--no-sandbox` must require `--unsafe-full-env`; standalone use should fail"
        );

        // The paired form parses cleanly.
        let cli = Cli::try_parse_from(["lpm", "rebuild", "--unsafe-full-env", "--no-sandbox"])
            .expect("paired flags should parse");
        match cli.command.expect("test parse missing subcommand") {
            Commands::Rebuild {
                no_sandbox,
                unsafe_full_env,
                ..
            } => {
                assert!(no_sandbox, "--no-sandbox should set no_sandbox=true");
                assert!(
                    unsafe_full_env,
                    "--unsafe-full-env should set unsafe_full_env=true"
                );
            }
            _ => panic!("expected Rebuild command"),
        }
    }

    #[test]
    fn graph_no_open_flag_parses() {
        // --no-open suppresses the auto-open browser side effect on
        // `--format html` for headless / CI use.
        let cli = Cli::try_parse_from(["lpm", "graph", "--format", "html", "--no-open"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Graph {
                no_open, format, ..
            } => {
                assert!(no_open, "--no-open should set no_open=true");
                assert_eq!(format, "html");
            }
            _ => panic!("expected Graph command"),
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
                Commands::Completions { .. } => {}
                _ => panic!("expected Completions command for shell '{shell}'"),
            }
        }
    }

    // ── Dev command flag parsing ──

    #[test]
    fn dev_dashboard_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "dev", "--dashboard"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Dev { dashboard, .. } => {
                assert!(dashboard);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_quiet_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "dev", "-q"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Dev { quiet, .. } => {
                assert!(quiet);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_quiet_long_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "dev", "--quiet"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Dev { quiet, .. } => {
                assert!(quiet);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn dev_dashboard_and_tunnel_flags_parse() {
        let cli = Cli::try_parse_from(["lpm", "dev", "--dashboard", "--tunnel"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
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
        match cli.command.expect("test parse missing subcommand") {
            Commands::Dev { tunnel_auth, .. } => {
                assert!(!tunnel_auth);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn tunnel_tunnel_auth_flag_parses() {
        let cli = Cli::try_parse_from(["lpm", "tunnel", "start", "--tunnel-auth"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Tunnel { tunnel_auth, .. } => {
                assert!(tunnel_auth);
            }
            _ => panic!("expected Tunnel command"),
        }
    }

    #[test]
    fn tunnel_inspect_port_default_is_none() {
        // No `--inspect-port` → `None` → call site auto-picks via bind(0).
        // Distinguishing "user didn't pass" from "user passed 4400" is the
        // contract change behind #16.
        let cli = Cli::try_parse_from(["lpm", "tunnel", "3000"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Tunnel { inspect_port, .. } => {
                assert_eq!(inspect_port, None);
            }
            _ => panic!("expected Tunnel command"),
        }
    }

    #[test]
    fn tunnel_inspect_port_explicit_is_some() {
        let cli = Cli::try_parse_from(["lpm", "tunnel", "3000", "--inspect-port", "4500"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Tunnel { inspect_port, .. } => {
                assert_eq!(inspect_port, Some(4500));
            }
            _ => panic!("expected Tunnel command"),
        }
    }

    #[test]
    fn dev_inspect_port_default_is_none() {
        let cli = Cli::try_parse_from(["lpm", "dev"]).unwrap();
        match cli.command.expect("test parse missing subcommand") {
            Commands::Dev {
                inspect_port,
                no_inspect,
                ..
            } => {
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
            Commands::Dev {
                inspect_port,
                no_inspect,
                ..
            } => {
                assert_eq!(inspect_port, Some(4500));
                assert!(no_inspect);
            }
            _ => panic!("expected Dev command"),
        }
    }

    #[test]
    fn run_affected_with_base_parses() {
        let cli = Cli::try_parse_from(["lpm", "run", "build", "--affected", "--base", "develop"])
            .unwrap();
        match cli.command.expect("test parse missing subcommand") {
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
    fn env_global_json_before_command_sets_global_json_flag() {
        let cli = Cli::try_parse_from(["lpm", "--json", "env", "oidc", "list"]).unwrap();

        assert!(
            cli.json,
            "expected global --json to be parsed before env command"
        );

        match cli.command.expect("test parse missing subcommand") {
            Commands::Env { extra } => {
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
            Commands::Env { extra } => {
                assert_eq!(extra, vec!["oidc", "list", "--json"]);
            }
            _ => panic!("expected Env command"),
        }
    }

    // ── Phase 37 M4.1: install -g collision-resolution flags ───────────

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
            Commands::Install {
                global,
                replace_bin,
                alias,
                ..
            } => {
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
            Commands::Install {
                global,
                alias,
                replace_bin,
                ..
            } => {
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
            Commands::Install {
                global,
                replace_bin,
                alias,
                ..
            } => {
                assert!(global);
                assert_eq!(replace_bin, vec!["serve".to_string()]);
                assert_eq!(alias, vec!["lint=foo-lint".to_string()]);
            }
            _ => panic!("expected Install command"),
        }
    }

    /// M4 audit pass 1 Finding 2: clap must still ACCEPT the flags on
    /// the non-global path (we reject them at dispatch, not at parse).
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
            Commands::Install {
                global,
                replace_bin,
                alias,
                ..
            } => {
                assert!(!global, "no -g → global should be false");
                assert_eq!(replace_bin, vec!["serve".to_string()]);
                assert_eq!(alias, vec!["lint=foo-lint".to_string()]);
            }
            _ => panic!("expected Install command"),
        }
    }
}
