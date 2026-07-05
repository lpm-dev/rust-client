use std::path::PathBuf;

use clap::{Args, Subcommand};
use lpm_semver::VersionBump;

use super::parsers::parse_version_bump;

#[derive(Args)]
pub(crate) struct ReleaseArgs {
    #[command(subcommand)]
    pub(crate) command: ReleaseCommands,
}

#[derive(Args, Clone, Debug)]
pub(crate) struct ReleaseSelectionArgs {
    /// Select every workspace member.
    #[arg(long, conflicts_with_all = ["affected", "filter", "filter_prod"])]
    pub(crate) all: bool,

    /// Select packages changed since --base plus dependents.
    #[arg(long)]
    pub(crate) affected: bool,

    /// Git base ref for --affected.
    #[arg(long, default_value = "main")]
    pub(crate) base: String,

    /// Filter workspace members. Same grammar as `lpm run --filter`.
    #[arg(long)]
    pub(crate) filter: Vec<String>,

    /// Filter workspace members with production dependency closures.
    #[arg(long = "filter-prod")]
    pub(crate) filter_prod: Vec<String>,

    /// Ignore changed files matching this git-diff glob when evaluating affected packages.
    #[arg(long = "changed-files-ignore-pattern")]
    pub(crate) changed_files_ignore_pattern: Vec<String>,

    /// Treat changed files matching this git-diff glob as tests for affected package fanout.
    #[arg(long = "test-pattern")]
    pub(crate) test_pattern: Vec<String>,

    /// Exit non-zero if the selection matches no members.
    #[arg(long)]
    pub(crate) fail_if_no_match: bool,
}

#[derive(Subcommand)]
pub(crate) enum ReleaseCommands {
    /// Print the workspace release plan without mutating files.
    Plan {
        #[command(flatten)]
        selection: ReleaseSelectionArgs,

        /// Bump level to use for every selected package unless .lpm/changes overrides it.
        #[arg(long, value_parser = parse_version_bump)]
        bump: Option<VersionBump>,
    },

    /// Apply a workspace release plan to package.json files.
    Apply {
        #[command(flatten)]
        selection: ReleaseSelectionArgs,

        /// Bump level to use for every selected package unless .lpm/changes overrides it.
        #[arg(long, value_parser = parse_version_bump)]
        bump: Option<VersionBump>,

        /// Preview the plan without writing package.json files.
        #[arg(long)]
        dry_run: bool,
    },

    /// Publish selected workspace members in dependency order.
    Publish {
        #[command(flatten)]
        selection: ReleaseSelectionArgs,

        /// Preview publish order and skips without uploading.
        #[arg(long)]
        dry_run: bool,

        /// Skip confirmation prompts.
        #[arg(long, short = 'y')]
        yes: bool,

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

        /// Publish to GitLab Packages.
        #[arg(long)]
        gitlab: bool,

        /// Publish to a custom npm-compatible registry.
        #[arg(long = "publish-registry", value_name = "URL")]
        publish_registry: Option<String>,

        /// Generate and require Sigstore provenance.
        #[arg(long, conflicts_with_all = ["no_provenance", "provenance_file"])]
        provenance: bool,

        /// Disable provenance even when npm config enables it.
        #[arg(long = "no-provenance", conflicts_with_all = ["provenance", "provenance_file"])]
        no_provenance: bool,

        /// Attach a pre-generated Sigstore provenance bundle.
        #[arg(
            long = "provenance-file",
            value_name = "PATH",
            conflicts_with = "no_provenance"
        )]
        provenance_file: Option<PathBuf>,
    },
}
