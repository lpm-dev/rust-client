use crate::commands;
use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct ConfigArgs {
    /// Action: get, set, delete, list, scripts, triage, sandbox,
    /// sigstore, signatures, trust-policy, typosquat, firewall, integrity,
    /// release-age, release-age-policy, lpm-skills.
    /// Omit to open the guided configuration editor.
    pub(crate) action: Option<String>,
    /// Config key (for get/set/delete).
    pub(crate) key: Option<String>,
    /// Config value (for set).
    pub(crate) value: Option<String>,
    /// Non-interactive value for the `scripts` / `triage` /
    /// `sandbox` / `sigstore` / `signatures` / `trust-policy` /
    /// `typosquat` / `firewall` / `integrity` / `release-age` /
    /// `release-age-policy` / `lpm-skills` wizards. Required when stdin
    /// is not a TTY. Examples:
    ///   `lpm config scripts --set triage`
    ///   `lpm config triage --set claude-cli`
    ///   `lpm config sandbox --set strict`
    ///   `lpm config sigstore --set deny`
    ///   `lpm config signatures --set true`
    ///   `lpm config trust-policy --set no-downgrade`
    ///   `lpm config typosquat --set default`
    ///   `lpm config firewall --set enforce`
    ///   `lpm config integrity --set tree`
    ///   `lpm config release-age --set 3d`
    ///   `lpm config release-age-policy --set strict`
    ///   `lpm config lpm-skills --set false`
    #[arg(long = "set", value_name = "VALUE")]
    pub(crate) set: Option<String>,
}

#[derive(Args)]
pub(crate) struct PolicyArgs {
    #[command(subcommand)]
    pub(crate) action: commands::policy::PolicyCmd,
}

#[derive(Args)]
pub(crate) struct SecurityArgs {
    #[command(subcommand)]
    pub(crate) action: commands::security::SecurityCmd,
}

#[derive(Args)]
pub(crate) struct TrustArgs {
    #[command(subcommand)]
    pub(crate) action: commands::trust::TrustCmd,
}

#[derive(Args)]
pub(crate) struct AuditArgs {
    #[command(subcommand)]
    pub(crate) action: Option<commands::audit::AuditCmd>,

    /// Minimum severity level to report (info, moderate, high).
    #[arg(long)]
    pub(crate) level: Option<String>,

    /// CI exit code policy (`vuln`, `behavior`, or `all`).
    #[arg(
        long,
        value_name = "POLICY",
        long_help = "CI exit code policy: what triggers a non-zero exit code.\n\n\
  vuln     — only confirmed vulnerabilities (OSV/registry)\n\
  behavior — only critical/high behavioral flags\n\
  secrets  — only hardcoded secret findings from --secrets mode\n\
  all      — vulnerabilities, behavioral flags, or secrets (default)"
    )]
    pub(crate) fail_on: Option<String>,

    /// Scan installed packages for hardcoded secrets (API keys, tokens, private keys).
    #[arg(long)]
    pub(crate) secrets: bool,

    /// Alias for `lpm audit fix`.
    #[arg(long, conflicts_with = "secrets")]
    pub(crate) fix: bool,

    /// With `--fix`, show the fixes that would be applied without changing files.
    #[arg(long, requires = "fix")]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub(crate) struct QueryArgs {
    /// Selector expression (e.g., ":eval", ":scripts:not(:built)", ":root > :network").
    pub(crate) selector: Option<String>,

    /// Show tag counts across all packages, grouped by severity.
    #[arg(long)]
    pub(crate) count: bool,

    /// Show tag details for each match. Long form only — `-V`
    /// is reserved globally for `--version`; a duplicate short
    /// here trips a clap structural assertion under
    /// `clap_complete::generate`.
    #[arg(long)]
    pub(crate) query_verbose: bool,

    /// Exit with code 1 if ANY packages match (CI gate).
    #[arg(long)]
    pub(crate) assert_none: bool,

    /// Output format: list (default) or mermaid (dependency subgraph diagram).
    #[arg(long, default_value = "list")]
    pub(crate) format: String,
}

#[derive(Args)]
pub(crate) struct LicensesArgs {
    /// Fail when a package has the selected license condition.
    ///
    /// Repeatable and comma-separated: `--fail-on copyleft,missing`.
    #[arg(long = "fail-on", value_enum, value_delimiter = ',')]
    pub(crate) fail_on: Vec<commands::licenses::LicenseFailOn>,

    /// Fail when a package declares this exact license expression.
    ///
    /// Repeatable and comma-separated: `--deny GPL-3.0 --deny AGPL-3.0`.
    #[arg(long, value_name = "LICENSE", value_delimiter = ',')]
    pub(crate) deny: Vec<String>,
}

#[derive(Args)]
pub(crate) struct DoctorArgs {
    /// Run every catalog row, including registry/auth probes,
    /// tunnel lookup, lint+fmt subprocesses, TypeScript +
    /// plugin reachability, global-install hygiene, sandbox
    /// probe, and the full manifest-compat sweep. Default
    /// `lpm doctor` runs only the fast local-health preset.
    ///
    /// Ignored when a subcommand is provided.
    #[arg(long)]
    pub(crate) all: bool,

    /// Auto-fix issues (install missing Node, run lpm install, run lpm fmt).
    ///
    /// Ignored when a subcommand is provided.
    #[arg(long)]
    pub(crate) fix: bool,

    /// Skip confirmation prompts for auto-fix actions (implies --fix).
    ///
    /// Ignored when a subcommand is provided.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,

    #[command(subcommand)]
    pub(crate) action: Option<DoctorAction>,
}

#[derive(Args)]
pub(crate) struct McpArgs {
    /// Action: setup, remove, status.
    pub(crate) action: String,
    /// Server name (for setup/remove).
    pub(crate) name: Option<String>,
}

#[derive(Args)]
pub(crate) struct ApproveScriptsArgs {
    /// Approve a specific package directly. Accepts `name` or
    /// `name@version`. Skips the interactive walk for that package.
    pub(crate) package: Option<String>,

    /// Bulk-approve every blocked package without per-package review.
    /// Loud — emits a warning banner. Mutually exclusive with `--list`.
    #[arg(long, conflicts_with = "list")]
    pub(crate) yes: bool,

    /// Read-only listing of the blocked set. No prompts, no mutations.
    /// Mutually exclusive with `--yes` and with the `package` argument.
    #[arg(long, conflicts_with = "yes")]
    pub(crate) list: bool,

    /// close-out: preview decisions without mutating state.
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
    pub(crate) dry_run: bool,

    /// operate on the global blocked set (aggregated
    /// across every `lpm install -g` install root) instead of the
    /// current project. Approvals write to
    /// `~/.lpm/global/trusted-dependencies.json` rather than the
    /// project's `package.json`.
    #[arg(long)]
    pub(crate) global: bool,

    /// when used with `--global`, group blocked rows by
    /// top-level globally-installed package during list and interactive
    /// review. Auto-enabled when the blocked set exceeds 10 entries.
    /// Persisted approvals still remain per dependency binding row.
    #[arg(long)]
    pub(crate) group: bool,
}

#[derive(Args)]
pub(crate) struct SbomArgs {
    /// SBOM output format.
    #[arg(long, value_enum, default_value_t = commands::sbom::SbomFormat::Cyclonedx)]
    pub(crate) format: commands::sbom::SbomFormat,

    /// Write the SBOM to a file instead of stdout.
    #[arg(short, long)]
    pub(crate) output: Option<std::path::PathBuf>,

    /// Fetch registry metadata and provenance attestations instead of
    /// using only local install metadata and cached provenance.
    #[arg(long = "registry-metadata")]
    pub(crate) registry_metadata: bool,
}

#[derive(Args)]
pub(crate) struct CertArgs {
    /// Action: status, trust, uninstall, generate, rotate, reconcile.
    pub(crate) action: String,

    /// Extra hostnames to include in the certificate SAN.
    #[arg(long)]
    pub(crate) host: Vec<String>,

    /// Additional project directories to reissue leaves for during rotate.
    #[arg(long = "project")]
    pub(crate) project: Vec<std::path::PathBuf>,

    /// Defer uninstalling the old CA for this many days (rotate only).
    /// Capped at 90.
    #[arg(long = "keep-old-trusted")]
    pub(crate) keep_old_trusted: Option<u32>,

    /// On rotate, exit non-zero instead of skipping projects whose dirs
    /// have disappeared from disk.
    #[arg(long = "fail-on-missing")]
    pub(crate) fail_on_missing: bool,

    /// Dry run for reconcile: report what would happen without mutating.
    #[arg(long = "dry-run")]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub(crate) struct VaultArgs {
    /// Action: open (default), update, version.
    #[arg(default_value = "")]
    pub(crate) action: String,
}

/// Subcommands of `lpm doctor`. Currently only `list` (the inventory
/// surface). Without a subcommand, `lpm doctor` runs the full check
/// set against the current project.
#[derive(Subcommand)]
pub(crate) enum DoctorAction {
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
