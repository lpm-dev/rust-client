use super::parsers::parse_advisor_slug;
use super::{InstallOmitCli, LinkerCli, OutdatedRegistryScope};
use crate::commands;
use clap::Args;

#[derive(Args)]
pub(crate) struct FetchArgs {
    /// Target platform for OS/CPU/libc package filters, e.g. linux/x64/glibc.
    #[arg(long, value_name = "OS/ARCH[/LIBC]")]
    pub(crate) platform: Option<String>,
}

#[derive(Args)]
pub(crate) struct TidyArgs {
    /// Remove unused dependency entries and reconcile lpm.lock/node_modules.
    #[arg(long)]
    pub(crate) fix: bool,
}

#[derive(Args)]
pub(crate) struct ResolveArgs {
    /// Packages to resolve (e.g., @lpm.dev/owner.package@^1.0.0)
    pub(crate) packages: Vec<String>,
}

#[derive(Args)]
pub(crate) struct InstallArgs {
    /// Packages to install (e.g., express@^4.0.0, @lpm.dev/neo.highlight).
    /// If omitted, installs all dependencies from package.json.
    pub(crate) packages: Vec<String>,

    /// Save as devDependencies instead of dependencies.
    #[arg(long, short = 'D')]
    pub(crate) save_dev: bool,

    /// Omit dependency types from node_modules.
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) omit: Vec<InstallOmitCli>,

    /// Install production dependencies only.
    #[arg(long, alias = "production")]
    pub(crate) prod: bool,

    /// Install without network (use lockfile + global store only).
    #[arg(long)]
    pub(crate) offline: bool,

    /// Refuse to update lpm.lock; fail if package.json and lpm.lock differ.
    #[arg(long, conflicts_with = "no_frozen_lockfile")]
    pub(crate) frozen_lockfile: bool,

    /// Disable the CI default frozen-lockfile behavior for this install.
    #[arg(long, conflicts_with = "frozen_lockfile")]
    pub(crate) no_frozen_lockfile: bool,

    /// Force full re-install: bypass the fast-exit hash check, skip the
    /// lockfile (force fresh resolution from registry), re-download all
    /// packages (even if already in the global store), and re-link
    /// node_modules from scratch.
    #[arg(long)]
    pub(crate) force: bool,

    /// Allow recently published packages (skip minimumReleaseAge check).
    #[arg(long)]
    pub(crate) allow_new: bool,

    /// Fail on tarball-URL deps that have no declared SRI integrity
    /// in the manifest. Without this flag,
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
    pub(crate) strict_integrity: bool,

    /// Fail install when peer-dependency warnings or best-effort
    /// peer conflicts are detected. Default is warn-only, matching
    /// pnpm's current `strict-peer-dependencies=false` default.
    ///
    /// Precedence: this flag / `--no-strict-peer-dependencies` >
    /// `package.json > lpm > strictPeerDependencies` >
    /// `~/.lpm/config.toml > strict-peer-dependencies` > default
    /// (false).
    #[arg(long, conflicts_with = "no_strict_peer_dependencies")]
    pub(crate) strict_peer_dependencies: bool,

    /// Disable strict peer-dependency failures for this install,
    /// overriding project or user config.
    #[arg(long, conflicts_with = "strict_peer_dependencies")]
    pub(crate) no_strict_peer_dependencies: bool,

    /// Override the minimumReleaseAge cooldown for this install only.
    /// Accepts `<N>h` (hours), `<N>d` (days), or plain `<N>` seconds.
    /// Use `0` to disable the cooldown for this invocation; any other
    /// value tightens or loosens the window vs. the default 24h /
    /// `package.json > lpm > minimumReleaseAge` /
    /// `~/.lpm/config.toml` key `minimum-release-age-secs`.
    ///
    /// The full precedence chain is `--min-release-age` (this flag,
    /// highest) → package.json →
    /// `~/.lpm/config.toml` → 24h default. `--allow-new` and this
    /// flag are independent escape hatches: `--allow-new` bypasses
    /// the check entirely; `--min-release-age=<dur>` adjusts the
    /// window that the check enforces.
    #[arg(long, value_name = "DUR")]
    pub(crate) min_release_age: Option<String>,

    /// Exempt one exact package name from minimumReleaseAge for this install only.
    /// Repeatable. Aliases must be excluded by their canonical target name.
    #[arg(long, value_name = "PKG")]
    pub(crate) min_release_age_exclude: Vec<String>,

    /// Skip the provenance-drift check for this
    /// specific package name (repeatable). The drift gate blocks
    /// on publisher identity changes between a prior approval
    /// and the candidate version; this flag opts out for a named
    /// package while keeping every other package's drift check
    /// live. Orthogonal to `--allow-new` — the cooldown and drift
    /// gates are independent.
    ///
    /// Prefer re-approving via `lpm approve-scripts` over
    /// ignoring the drift: re-approval captures the new
    /// publisher identity so the next install sees a clean
    /// reference. Use this flag only when the identity change
    /// is expected AND the user does not yet want to accept
    /// the new identity as the new approval baseline.
    #[arg(long, value_name = "PKG")]
    pub(crate) ignore_provenance_drift: Vec<String>,

    /// Blanket: skip the provenance-drift check for
    /// every resolved package. Composes with
    /// `--ignore-provenance-drift <pkg>` by superseding it — if
    /// both are passed, `-all` wins and the per-package list is
    /// ignored (drift checks are suppressed entirely for this
    /// invocation).
    #[arg(long)]
    pub(crate) ignore_provenance_drift_all: bool,

    /// Skip the cryptographic Sigstore verification step for this
    /// specific package name (repeatable). The Sigstore verifier
    /// (DSSE / Rekor body / Rekor SET / SCT / X.509 chain /
    /// identity-pin) is bypassed; the legacy identity-only parser
    /// still extracts the publisher / workflow_path / workflow_ref
    /// from the bundle so the drift gate has something to compare
    /// against. The trust binding records this observation as
    /// "unverified" (not "verified") so the audit trail captures
    /// the operator's downgrade.
    ///
    /// Orthogonal to `--ignore-provenance-drift`: one suppresses
    /// the *crypto* layer, the other suppresses the *drift* layer.
    /// Composing them is legal and may be appropriate when an
    /// upstream registry's bundle shape briefly drifts; the
    /// preferred remediation is to wait for the registry to fix it
    /// rather than persist this flag in CI.
    #[arg(long, value_name = "PKG")]
    pub(crate) unverified_provenance: Vec<String>,

    /// Blanket: skip the Sigstore verifier for every resolved
    /// package on this invocation. Composes with
    /// `--unverified-provenance <pkg>` by superseding it — if both
    /// are passed, `-all` wins and the per-package list is ignored
    /// (verification is suppressed entirely for this invocation).
    ///
    /// This is the **per-invocation** opt-out and is loud at
    /// install time (`tracing::warn`). For a persistent fleet-
    /// wide posture (corporate-firewalled Rekor egress, air-
    /// gapped environments), prefer the operator-scoped knob:
    /// `[sigstore] verify = "off"` in `~/.lpm/config.toml`, or
    /// `lpm config sigstore --set off`. Those persisted knobs
    /// surface the degraded posture in `lpm doctor` so it
    /// isn't forgotten.
    #[arg(long)]
    pub(crate) unverified_provenance_all: bool,

    /// Linking mode: `hoisted` (default — v2 hoisted virtual-store layout)
    /// or `isolated` (pnpm-style strict isolation).
    /// Both materialize as project `node_modules/<dep>` symlinks
    /// into the global virtual store at `~/.lpm/store/v2/links/`,
    /// so warm-install latency is identical between modes; the
    /// distinction is whether transitive deps are hoisted within shared
    /// link entries (hoisted) or only through each consumer's own siblings
    /// (isolated). v2 hoisted mode does not flatten every transitive to
    /// the project root. Unknown values are rejected by clap at parse
    /// time. Overrides `package.json > lpm > linker`,
    /// `~/.lpm/config.toml > linker`, and `LPM_LINKER`.
    #[arg(long, value_enum)]
    pub(crate) linker: Option<LinkerCli>,

    /// Skip skills auto-install.
    #[arg(long)]
    pub(crate) no_skills: bool,

    /// Skip editor auto-integration.
    #[arg(long)]
    pub(crate) no_editor_setup: bool,

    /// Disable post-install security summary (faster CI).
    #[arg(long)]
    pub(crate) no_security_summary: bool,

    /// Include install timing diagnostics in `--json` output.
    #[arg(long)]
    pub(crate) timing: bool,

    /// Automatically run `lpm rebuild` for trusted packages after install.
    ///
    /// Redundant under `--policy=allow` / `--yolo` (auto-build fires
    /// at install time when policy is allow, regardless of this flag).
    /// Still useful under the default `deny` policy when you have an
    /// established trust set and want to skip the explicit
    /// `lpm rebuild` step.
    #[arg(long)]
    pub(crate) auto_build: bool,

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
    pub(crate) no_engine_strict: bool,

    /// Run `lpm audit` once after a successful install and surface
    /// a one-line summary (`! Audited N packages, V vulnerabilities,
    /// S suspicious in Tms — run \`lpm audit\``).
    ///
    /// The summary is informational only — vulnerabilities found
    /// here NEVER fail the install. Run `lpm audit --fail-on=...`
    /// explicitly if you want a gating audit.
    ///
    /// Precedence chain (highest first):
    ///   1. `--audit-after-install` / `--no-audit-after-install`
    ///      (this flag pair, mutually exclusive)
    ///   2. `LPM_AUDIT_AFTER_INSTALL` env (`1`/`true` → on,
    ///      `0`/`false` → off)
    ///   3. `~/.lpm/config.toml > audit-after-install = true`
    ///   4. Default: off
    #[arg(long, conflicts_with = "no_audit_after_install")]
    pub(crate) audit_after_install: bool,

    /// Suppress audit-after-install for this invocation regardless
    /// of env / config. The feature is off by default, so this flag
    /// is only meaningful when a global config or env setting has
    /// turned it on — it lets an operator opt out for a single run
    /// without editing the persistent setting.
    #[arg(long, conflicts_with = "audit_after_install")]
    pub(crate) no_audit_after_install: bool,

    /// Lifecycle-script policy override for this invocation.
    ///
    /// `deny` (default): scripts blocked; `lpm approve-scripts`
    /// required to run per package. `lpm install` does NOT run
    /// scripts; the install-time build hint lists candidates so
    /// you can review and approve before any code executes.
    ///
    /// `allow`: runs every lifecycle script during
    /// `lpm install`, without the tier gate. Matches `npm install`
    /// / `pnpm install` / `bun install` default semantics. The
    /// trust check is bypassed because you opted in explicitly.
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
    /// ambers and reds never auto-execute. The portable layers run
    /// every time; the LLM advisor is consulted only when configured
    /// (see `--advisor`).
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
    pub(crate) policy: Option<String>,

    /// Alias for `--policy=allow`. Runs every lifecycle script
    /// during `lpm install` without the tier gate — auto-build
    /// fires automatically; no separate `--auto-build` flag needed.
    ///
    /// See `--policy` for the global rerun caveat (`-g` blocked
    /// scripts require uninstall+reinstall after approval).
    ///
    /// Mutually exclusive with `--policy` and `--triage`.
    #[arg(long, conflicts_with_all = ["policy", "triage_alias"])]
    pub(crate) yolo: bool,

    /// Alias for `--policy=triage`. Enables the tiered gate: greens
    /// auto-approve and run in the sandbox; ambers and reds route
    /// to `lpm approve-scripts` for manual review.
    ///
    /// See `--policy` for the global rerun caveat (`-g` blocked
    /// scripts require uninstall+reinstall after approval).
    ///
    /// Mutually exclusive with `--policy` and `--yolo`.
    #[arg(long = "triage", id = "triage_alias", conflicts_with_all = ["policy", "yolo"])]
    pub(crate) triage_alias: bool,

    /// Override the triage advisor for this run.
    /// Valid values: `none` | `claude-cli` | `codex` | `ollama`.
    ///
    /// Precedence (highest first): this flag → `lpm.triageAdvisor`
    /// in `package.json` → `triage-advisor` in `~/.lpm/config.toml`
    /// → default `none`. Only consulted when the effective
    /// script-policy is `triage`; under `deny` / `allow` the
    /// advisor is never invoked.
    ///
    /// Unknown slugs are rejected at parse time (rather than
    /// silently degrading) so a typo never produces a portable-only
    /// run while the user thinks they configured an uplift.
    #[arg(
        long,
        value_name = "none|claude-cli|codex|ollama",
        value_parser = parse_advisor_slug,
    )]
    pub(crate) advisor: Option<String>,

    /// Filter workspace members. Same grammar as `lpm run --filter`.
    /// Only meaningful when adding packages — bare `lpm install`
    /// (no packages) ignores this flag.
    ///
    /// Example: `lpm install react --filter web` adds react to
    /// `packages/web/package.json` and runs the install pipeline at
    /// `packages/web/`.
    ///
    /// Mutually exclusive with `-w`.
    #[arg(long)]
    pub(crate) filter: Vec<String>,

    /// Filter workspace members with production dependency closures.
    /// Same grammar as `--filter`, but `...` and `^...` do not walk
    /// `devDependencies` edges.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,

    /// Ignore changed files matching this git-diff glob when evaluating
    /// `[git-ref]` filters. Can be passed multiple times.
    #[arg(long = "changed-files-ignore-pattern")]
    pub(crate) changed_files_ignore_pattern: Vec<String>,

    /// Treat changed files matching this git-diff glob as tests, so
    /// reverse git-ref closures do not fan out to dependents from them.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,

    /// Target the workspace root `package.json` instead of the
    /// current member. Mutually exclusive with `--filter`. Use when
    /// adding tooling packages that belong at the root rather than
    /// in a specific member (e.g., shared dev dependencies).
    #[arg(short = 'w', long = "workspace-root")]
    pub(crate) workspace_root: bool,

    /// Exit non-zero if `--filter` matches no members. Recommended
    /// in CI to catch typo'd filters.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,

    /// Skip the interactive confirmation prompt when a filtered
    /// install will mutate more than one workspace member's
    /// `package.json`. Mirrors `lpm init` and `lpm publish` —
    /// JSON mode and non-TTY stdin already skip the prompt
    /// automatically; this flag covers the interactive-terminal-
    /// but-no-manual-review case (scripts, agents).
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,

    /// Save the exact resolved version to `package.json` instead of
    /// the default `^resolvedVersion`. Mutually exclusive with
    /// `--tilde` and `--save-prefix`.
    ///
    /// Example: `lpm install zod --exact` saves `"zod": "4.3.6"`.
    #[arg(long, conflicts_with_all = ["tilde", "save_prefix"])]
    pub(crate) exact: bool,

    /// Save `~resolvedVersion` to `package.json` instead of the
    /// default `^resolvedVersion`. Mutually exclusive with `--exact`
    /// and `--save-prefix`.
    ///
    /// Example: `lpm install zod --tilde` saves `"zod": "~4.3.6"`.
    #[arg(long, conflicts_with_all = ["exact", "save_prefix"])]
    pub(crate) tilde: bool,

    /// Override the manifest save prefix for this install. Valid
    /// values: `^`, `~`, or `""` (empty for exact, no prefix).
    /// `*` is not accepted — wildcards must be requested per-package
    /// via `pkg@*`. Mutually exclusive with `--exact` and `--tilde`.
    ///
    /// Example: `lpm install zod --save-prefix '~'` saves `"zod": "~4.3.6"`.
    #[arg(long, value_name = "PREFIX", conflicts_with_all = ["exact", "tilde"])]
    pub(crate) save_prefix: Option<String>,

    /// Save matching package specs through the root catalog instead of
    /// writing a direct range. `--catalog` uses the default catalog and
    /// writes `"catalog:"`; `--catalog=<name>` uses a named catalog and
    /// writes `"catalog:<name>"`. The package must already exist in that
    /// catalog and the resolved version must satisfy the catalog range.
    #[arg(
        long,
        value_name = "NAME",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "default",
        conflicts_with_all = ["exact", "tilde", "save_prefix"],
    )]
    pub(crate) catalog: Option<String>,

    /// Install the package globally into `~/.lpm/global/` instead of
    /// into a project's `node_modules/`. Exposes the package's bin
    /// entries on PATH via `~/.lpm/bin/`.
    ///
    /// Example: `lpm install --global eslint`, `lpm install -g typescript`
    #[arg(long, short = 'g')]
    pub(crate) global: bool,

    /// Resolve a command-name collision by transferring ownership of
    /// `<CMD>` to the package being installed. The previous owner
    /// keeps their row but loses that command from PATH; the new
    /// shim points at this install.
    ///
    /// Repeatable. Only meaningful with `-g`.
    ///
    /// Example: `lpm install -g foo --replace-bin serve --replace-bin lint`
    #[arg(long = "replace-bin", value_name = "CMD")]
    pub(crate) replace_bin: Vec<String>,

    /// Install a declared bin under a different PATH name.
    /// Format: `<orig>=<alias>` — `<orig>` must be a bin the package
    /// declares, `<alias>` is the PATH name. Multiple mappings
    /// comma-separated or via repeated flags.
    ///
    /// When set, the declared `<orig>` name is NOT emitted as a
    /// shim; only `<alias>` is. Only meaningful with `-g`.
    ///
    /// Example: `lpm install -g foo --alias serve=foo-serve,lint=foo-lint`
    #[arg(long = "alias", value_name = "ORIG=ALIAS")]
    pub(crate) alias: Vec<String>,

    /// Engage strict sandbox for this install's lifecycle scripts —
    /// filesystem containment, env scrubbing, and outbound network
    /// denial. Overrides any persistent `[sandbox] mode` config for
    /// this command only. Auto-build (`--auto-build` and the
    /// `package.json` key `lpm.scripts.autoBuild`) honors the same
    /// strict mode.
    ///
    /// Mutually exclusive with `--no-sandbox` and `--paranoid`
    /// (the alias).
    #[arg(
        long = "strict-sandbox",
        id = "install_strict_sandbox",
        conflicts_with_all = ["install_no_sandbox", "install_paranoid"],
    )]
    pub(crate) strict_sandbox: bool,

    /// Alias for `--strict-sandbox`. Same behaviour; ergonomic
    /// spelling. Mutually exclusive with `--no-sandbox` and
    /// `--strict-sandbox`.
    #[arg(
        long = "paranoid",
        id = "install_paranoid",
        conflicts_with_all = ["install_no_sandbox", "install_strict_sandbox"],
    )]
    pub(crate) paranoid: bool,

    /// Drop ALL containment for this install's lifecycle scripts.
    /// Scripts run with full host access — filesystem open, full
    /// env (credentials included), outbound network allowed. Reserve
    /// for debugging a sandbox false-positive. Persistent off-mode
    /// goes through `lpm config sandbox --set none` instead.
    ///
    /// Mutually exclusive with `--strict-sandbox` and `--paranoid`.
    #[arg(
        long = "no-sandbox",
        id = "install_no_sandbox",
        conflicts_with_all = ["install_strict_sandbox", "install_paranoid"],
    )]
    pub(crate) no_sandbox: bool,
}

#[derive(Args)]
pub(crate) struct UninstallArgs {
    /// Packages to remove (e.g., express, @lpm.dev/neo.highlight).
    pub(crate) packages: Vec<String>,

    /// filter workspace members. Same grammar as
    /// `lpm run --filter`. Mutually exclusive with `-w`.
    ///
    /// Example: `lpm uninstall lodash --filter web` removes lodash from
    /// `packages/web/package.json` only.
    #[arg(long)]
    pub(crate) filter: Vec<String>,

    /// Filter workspace members with production dependency closures.
    /// Same grammar as `--filter`, but `...` and `^...` do not walk
    /// `devDependencies` edges.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,

    /// Ignore changed files matching this git-diff glob when evaluating
    /// `[git-ref]` filters. Can be passed multiple times.
    #[arg(long = "changed-files-ignore-pattern")]
    pub(crate) changed_files_ignore_pattern: Vec<String>,

    /// Treat changed files matching this git-diff glob as tests, so
    /// reverse git-ref closures do not fan out to dependents from them.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,

    /// target the workspace root `package.json` instead
    /// of the current member.
    #[arg(short = 'w', long = "workspace-root")]
    pub(crate) workspace_root: bool,

    /// exit non-zero if `--filter` matches no members.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,

    /// (): skip the interactive
    /// confirmation prompt when a filtered uninstall will mutate more
    /// than one workspace member's `package.json`. See the matching
    /// flag on `lpm install` for the full rationale.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,

    /// remove a globally-installed package.
    /// Mutually exclusive with `--filter` / `-w` / `--fail-if-no-match`
    /// (those are project-scoped).
    ///
    /// Example: `lpm uninstall -g eslint`
    ///
    /// Equivalent to `lpm global remove <pkg>` — both invocations
    /// route through the same `uninstall_global` implementation.
    #[arg(long, short = 'g')]
    pub(crate) global: bool,
}

#[derive(Args)]
pub(crate) struct AddArgs {
    /// Package to add (e.g. `@lpm.dev/owner.package`, `react`).
    pub(crate) package: String,

    /// Target directory for extracted files.
    #[arg(long)]
    pub(crate) path: Option<String>,

    /// Skip interactive prompts, use defaults.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,

    /// Force overwrite existing files without prompting.
    #[arg(long)]
    pub(crate) force: bool,

    /// Show what would be done without making changes.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Skip dependency installation after adding.
    #[arg(long)]
    pub(crate) no_install_deps: bool,

    /// Skip skills auto-install.
    #[arg(long)]
    pub(crate) no_skills: bool,

    /// Skip editor auto-integration.
    #[arg(long)]
    pub(crate) no_editor_setup: bool,

    /// Package manager for dependency installation (lpm, npm, pnpm, yarn, bun, auto).
    #[arg(long, default_value = "lpm")]
    pub(crate) pm: String,

    /// Import alias prefix (e.g., @/components). Overrides auto-detection.
    #[arg(long)]
    pub(crate) alias: Option<String>,

    /// Swift SPM target name (e.g., MyAppTarget).
    #[arg(long)]
    pub(crate) target: Option<String>,

    /// Skip `engines.lpm` / `engines.node` enforcement.
    ///
    /// `lpm add` runs the engine gate before mutating
    /// `package.json` so a constraint violation can't leave the
    /// project partially modified. See `lpm install --no-engine-strict`
    /// for the precedence chain.
    #[arg(long)]
    pub(crate) no_engine_strict: bool,
}

#[derive(Args)]
pub(crate) struct OutdatedArgs {
    /// Limit checks to a single registry ecosystem.
    #[arg(long = "registry-only", value_enum, default_value_t = OutdatedRegistryScope::All)]
    pub(crate) registry_only: OutdatedRegistryScope,
}

#[derive(Args)]
pub(crate) struct UpgradeArgs {
    /// Only upgrade the named direct dependency package(s).
    #[arg(value_name = "PACKAGE")]
    pub(crate) packages: Vec<String>,
    /// Upgrade to latest major versions (breaking changes).
    /// Non-interactive mode only; in interactive mode, major
    /// upgrades appear as separate rows you can toggle on.
    #[arg(long)]
    pub(crate) major: bool,
    /// Show what would be upgraded without making changes.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Force interactive mode even without a TTY.
    #[arg(long, short = 'i')]
    pub(crate) interactive: bool,
    /// Skip interactive prompts (today's behavior). Useful to
    /// force non-interactive when at a TTY.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,
}

#[derive(Args)]
pub(crate) struct InitArgs {
    /// Skip prompts, use defaults.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,
    /// Create an lpm.dev package (`@lpm.dev/<owner>.<name>`).
    #[arg(long, conflicts_with = "npm")]
    pub(crate) lpm: bool,
    /// Create an npm-compatible package name and publish config.
    #[arg(long, conflicts_with = "lpm")]
    pub(crate) npm: bool,
    /// Package name to write. For lpm.dev, this is the package half unless
    /// an `@lpm.dev/<owner>.<name>` value is provided.
    #[arg(long)]
    pub(crate) name: Option<String>,
    /// lpm.dev owner or organization slug. Used only for lpm.dev packages.
    #[arg(long)]
    pub(crate) owner: Option<String>,
    /// Do not create or update AGENTS.md.
    #[arg(long)]
    pub(crate) no_agents: bool,
}

#[derive(Args)]
pub(crate) struct CacheArgs {
    /// Action: clean, path, status, prune.
    pub(crate) action: String,

    /// Optional subcategory: metadata, tasks, or dlx.
    /// When omitted, `clean` clears all three and `path` prints the
    /// cache root. Ignored by `prune`.
    pub(crate) subcategory: Option<String>,

    /// `prune` only: actually remove orphan entries and sweep
    /// pending global-install tombstones. Default is dry-run.
    #[arg(long)]
    pub(crate) apply: bool,

    /// `prune` only: filter to entries whose `last_referenced_at`
    /// is older than this duration (`30d`, `24h`, etc.).
    #[arg(long)]
    pub(crate) max_age: Option<String>,

    /// `prune` only: manual repair mode. Walk only this project's
    /// `node_modules/` to collect roots; ignore the registry. Use
    /// when the registry is corrupt or after a machine restore.
    #[arg(long, value_name = "PATH")]
    pub(crate) project: Option<String>,
}

#[derive(Args)]
pub(crate) struct StoreArgs {
    /// Action: verify, path, clean.
    pub(crate) action: String,

    /// Deep verification: parse package.json and validate name/version consistency.
    #[arg(long)]
    pub(crate) deep: bool,

    /// Auto-fix issues found during verify (e.g., refresh stale security caches).
    #[arg(long)]
    pub(crate) fix: bool,
}

#[derive(Args)]
pub(crate) struct CatalogArgs {
    #[command(subcommand)]
    pub(crate) action: commands::catalog::CatalogCmd,
}

#[derive(Args)]
pub(crate) struct GlobalArgs {
    #[command(subcommand)]
    pub(crate) action: commands::global::GlobalCmd,
}

#[derive(Args)]
pub(crate) struct SkillsArgs {
    #[command(subcommand)]
    pub(crate) action: crate::commands::skills::SkillsCmd,
}

#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// Package to remove.
    pub(crate) package: String,
}

#[derive(Args)]
pub(crate) struct RebuildArgs {
    /// Specific packages to rebuild. If omitted, rebuilds all trusted packages.
    pub(crate) packages: Vec<String>,

    /// Rebuild ALL packages with scripts (dangerous — bypasses trust policy).
    #[arg(long)]
    pub(crate) all: bool,

    /// Preview what would be rebuilt without executing scripts.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Re-run scripts even for already-built packages.
    #[arg(long)]
    pub(crate) force: bool,

    /// Timeout per script in seconds (default: 300 = 5 minutes).
    #[arg(long)]
    pub(crate) timeout: Option<u64>,

    /// Refuse to run ANY scripts, even trusted ones.
    #[arg(long)]
    pub(crate) deny_all: bool,

    /// lifecycle-script policy override (see
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
    /// trust (close-out).
    ///
    /// `triage`: filters to trusted-only, but greens are
    /// auto-promoted  and appear in the rebuild
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
    pub(crate) policy: Option<String>,

    /// alias for `--policy=allow`. Includes every
    /// scripted package in the rebuild set regardless of trust
    /// (close-out). Equivalent to `--all` at the
    /// selection step.
    #[arg(long = "yolo", id = "rebuild_yolo", conflicts_with_all = ["policy", "rebuild_triage_alias"])]
    pub(crate) yolo: bool,

    /// alias for `--policy=triage`. Greens are
    /// auto-promoted into the rebuild set ;
    /// ambers and reds require `lpm approve-scripts`
    /// approval before they run.
    #[arg(long = "triage", id = "rebuild_triage_alias", conflicts_with_all = ["policy", "rebuild_yolo"])]
    pub(crate) triage_alias: bool,

    /// drop ALL containment for
    /// this command. Scripts run with full host access — filesystem
    /// open, full env (credentials included), outbound network
    /// allowed. Reserve for debugging a sandbox false-positive
    /// that no other escape covers. Mutually exclusive with
    /// `--strict-sandbox` / `--paranoid` (both forms of opting
    /// INTO containment) and `--sandbox-log`.
    ///
    /// Persistent off-mode goes through `lpm config sandbox --set
    /// none` instead; this flag is the per-command escape only.
    #[arg(
        long,
        conflicts_with_all = ["sandbox_log", "rebuild_strict_sandbox", "rebuild_paranoid"]
    )]
    pub(crate) no_sandbox: bool,

    /// engage strict containment
    /// for this command — filesystem-write containment + env
    /// scrubbing + outbound network denial. Overrides any
    /// persistent `[sandbox] mode` config. Mutually exclusive
    /// with `--no-sandbox` and `--paranoid` (alias).
    #[arg(
        long = "strict-sandbox",
        id = "rebuild_strict_sandbox",
        conflicts_with_all = ["no_sandbox", "rebuild_paranoid"],
    )]
    pub(crate) strict_sandbox: bool,

    /// Alias for `--strict-sandbox`. Same
    /// behaviour; ergonomic spelling for "I always want this
    /// strict". Mutually exclusive with `--no-sandbox` and
    /// `--strict-sandbox`.
    #[arg(
        long = "paranoid",
        id = "rebuild_paranoid",
        conflicts_with_all = ["no_sandbox", "rebuild_strict_sandbox"],
    )]
    pub(crate) paranoid: bool,

    /// Run lifecycle scripts in diagnostic
    /// mode — rule triggers are logged via `sandboxd` but not
    /// enforced. **Not a safety signal.** A clean run under
    /// `--sandbox-log` does NOT indicate the script would pass
    /// under the full sandbox; it only means the logged
    /// accesses were visible for review. View reported accesses
    /// via `log show --last 5m --predicate 'senderImagePath
    /// CONTAINS "Sandbox"'` and filter by the script's PID.
    ///
    /// macOS only in: implemented via Seatbelt's
    /// `(allow (with report) default)` fallback. Linux landlock
    /// has no native observe-only primitive, so `--sandbox-log`
    /// on Linux errors at sandbox init with a remediation
    /// pointing at `--no-sandbox`. Mutually exclusive with
    /// `--no-sandbox`.
    #[arg(long)]
    pub(crate) sandbox_log: bool,

    /// Skip `engines.lpm` / `engines.node` enforcement. See
    /// `lpm install --no-engine-strict` for the precedence chain.
    #[arg(long)]
    pub(crate) no_engine_strict: bool,
}

#[derive(Args)]
pub(crate) struct UseArgs {
    /// Runtime spec or explicit action, e.g. `node@22`, `remove node@20`.
    pub(crate) args: Vec<String>,

    /// List installed runtime versions.
    #[arg(long, conflicts_with_all = ["pin", "remove"])]
    pub(crate) list: bool,

    /// Pin only (skip install if already installed).
    #[arg(long, conflicts_with_all = ["list", "remove"])]
    pub(crate) pin: bool,

    /// Remove installed managed runtimes matching a spec.
    #[arg(long, conflicts_with_all = ["list", "pin"])]
    pub(crate) remove: bool,
}

#[derive(Args)]
pub(crate) struct DeployArgs {
    /// Output directory (e.g., `/prod/api`). Must be outside the workspace.
    pub(crate) output: String,

    /// Filter expression identifying the member to deploy. Must match
    /// exactly one workspace member. Same grammar as `lpm run --filter`.
    #[arg(long)]
    pub(crate) filter: Vec<String>,

    /// Filter expression using production dependency closures. May be
    /// used instead of or alongside `--filter`; the combined result must
    /// still match exactly one workspace member.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,

    /// Ignore changed files matching this git-diff glob when evaluating
    /// `[git-ref]` filters. Can be passed multiple times.
    #[arg(long = "changed-files-ignore-pattern")]
    pub(crate) changed_files_ignore_pattern: Vec<String>,

    /// Treat changed files matching this git-diff glob as tests, so
    /// reverse git-ref closures do not fan out to dependents from them.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,

    /// Overwrite the output directory if it is non-empty. Without this
    /// flag, deploy refuses to write into a non-empty directory.
    #[arg(long)]
    pub(crate) force: bool,

    /// Deploy production dependencies. This is the default.
    #[arg(long, conflicts_with = "dev")]
    pub(crate) prod: bool,

    /// Deploy devDependencies instead of production dependencies.
    #[arg(long, conflicts_with = "prod")]
    pub(crate) dev: bool,

    /// Omit optionalDependencies from the deploy output and resolver graph.
    #[arg(long = "no-optional")]
    pub(crate) no_optional: bool,

    /// Show what would be deployed without making any filesystem changes.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub(crate) struct PatchArgs {
    /// Package selector: bare name (`lodash`), exact pin
    /// (`lodash@4.17.21`), or semver range (`lodash@^4.0.0`). The
    /// resolved exact pin is persisted in `package.json`. Dist-tags
    /// (`latest`, `next`) are not accepted.
    pub(crate) key: String,
}

#[derive(Args)]
pub(crate) struct PatchCommitArgs {
    /// The staging directory path printed by `lpm patch`.
    pub(crate) staging_dir: String,
}

#[derive(Args)]
pub(crate) struct PatchRemoveArgs {
    /// Patched package selector(s). Exact pins (`lodash@4.17.21`) match
    /// one manifest entry; bare names (`lodash`) are accepted only when
    /// they uniquely match one patched version.
    #[arg(required = true, num_args = 1..)]
    pub(crate) selectors: Vec<String>,

    /// Preview the manifest/file changes without writing anything.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Remove manifest entries but leave patch files on disk.
    #[arg(long = "keep-file")]
    pub(crate) keep_file: bool,
}

#[derive(Args)]
pub(crate) struct FilterArgs {
    /// Filter expressions. Multiple expressions union; use `!expr` to
    /// exclude. Same grammar as `lpm run --filter`.
    pub(crate) exprs: Vec<String>,

    /// Filter expressions evaluated with production dependency closures.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,

    /// Ignore changed files matching this git-diff glob when evaluating
    /// `[git-ref]` filters. Can be passed multiple times.
    #[arg(long = "changed-files-ignore-pattern")]
    pub(crate) changed_files_ignore_pattern: Vec<String>,

    /// Treat changed files matching this git-diff glob as tests, so
    /// reverse git-ref closures do not fan out to dependents from them.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,

    /// Show the full structured selection trace (which filter matched
    /// each package and how). Without this flag, output is a terse name
    /// list suitable for piping into shell tools.
    #[arg(long)]
    pub(crate) explain: bool,

    /// Exit non-zero if no packages matched.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,
}

#[derive(Args)]
pub(crate) struct WhyArgs {
    /// Package to trace from the project root.
    #[arg(value_name = "PACKAGE")]
    pub(crate) package: String,
}

#[derive(Args)]
pub(crate) struct GraphArgs {
    /// Package to show subtree for (optional — shows full graph if omitted).
    #[arg(value_name = "PACKAGE")]
    pub(crate) package: Option<String>,

    /// Output format: tree (default), dot, mermaid, json, stats, html.
    #[arg(long, default_value = "tree", value_parser = ["tree", "dot", "mermaid", "json", "stats", "html"])]
    pub(crate) format: String,

    /// Explain why a package is in your tree (show all paths from root).
    #[arg(long, name = "WHY")]
    pub(crate) why: Option<String>,

    /// Truncate the graph to the given depth. The project root counts
    /// as level 1, direct deps as level 2. Applied at the graph level,
    /// so every output format (tree, dot, mermaid, json, stats, html)
    /// sees the same truncated set.
    #[arg(long)]
    pub(crate) depth: Option<usize>,

    /// Only show subtrees containing this package name.
    #[arg(long)]
    pub(crate) filter: Option<String>,

    /// Only show production dependencies.
    #[arg(long, conflicts_with = "dev")]
    pub(crate) prod: bool,

    /// Only show devDependencies.
    #[arg(long)]
    pub(crate) dev: bool,

    /// With `--format html`: skip auto-opening the rendered file in the
    /// default browser. Useful in headless / CI environments where no
    /// display is available. The file is still written to
    /// `<project>/.lpm/graph.html`. No-op for other formats.
    #[arg(long)]
    pub(crate) no_open: bool,
}

#[derive(Args)]
pub(crate) struct MigrateArgs {
    /// Skip build+test verification after migration.
    #[arg(long)]
    pub(crate) skip_verify: bool,

    /// Don't configure .npmrc for the LPM registry.
    #[arg(long)]
    pub(crate) no_npmrc: bool,

    /// Don't show CI template hint (or generate with --ci).
    #[arg(long)]
    pub(crate) no_ci: bool,

    /// Generate a CI workflow template for the detected platform.
    #[arg(long)]
    pub(crate) ci: bool,

    /// Don't run `lpm install` after conversion (lockfile-only migration).
    #[arg(long)]
    pub(crate) no_install: bool,

    /// Parse and convert only, don't write any files.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Overwrite an existing lpm.lock.
    #[arg(long)]
    pub(crate) force: bool,

    /// Restore files from .backup copies created by a previous migration.
    #[arg(long)]
    pub(crate) rollback: bool,

    /// Reserved. The migrate flow is non-interactive today, so this
    /// flag is a no-op. It exists so scripts that already set `-y`
    /// continue to parse cleanly, and so the public CLI keeps the
    /// flag namespace once interactive prompts are wired in.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,
}
