use super::parsers::parse_version_bump;
use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct InfoArgs {
    /// Package name (e.g., @lpm.dev/owner.package or owner.package)
    pub(crate) package: String,

    /// Show a specific version instead of latest.
    #[arg(long = "version")]
    pub(crate) package_version: Option<String>,
}

#[derive(Args)]
pub(crate) struct SearchArgs {
    /// Search query.
    pub(crate) query: String,

    /// Maximum results (1-20).
    #[arg(long, default_value = "20")]
    pub(crate) limit: u32,
}

#[derive(Args)]
pub(crate) struct QualityArgs {
    /// Package name (e.g., owner.package)
    pub(crate) package: String,
}

#[derive(Args)]
pub(crate) struct DownloadArgs {
    /// Package name (e.g., @lpm.dev/owner.package or owner.package)
    pub(crate) package: String,

    /// Version to download (default: latest).
    #[arg(long = "version")]
    pub(crate) package_version: Option<String>,

    /// Directory to extract into (default: current directory).
    #[arg(long, short)]
    pub(crate) output: Option<String>,

    /// Proceed even when the registry returns no integrity hash
    /// for the tarball. By default `lpm download` refuses to
    /// extract an unverified tarball — the command is documented
    /// for audit use, where silently accepting bytes without an
    /// SRI defeats the purpose. Use this flag for sources
    /// (legacy mirrors, GitHub release assets) that genuinely
    /// don't ship integrity, accepting that you take on the
    /// verification burden yourself.
    #[arg(long = "allow-unverified")]
    pub(crate) allow_unverified: bool,
}

#[derive(Args)]
pub(crate) struct PublishArgs {
    /// Preview without uploading.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Prepare and validate locally without publishing: pack files, validate skills and provenance files, run quality checks, and scan for secrets.
    #[arg(long)]
    pub(crate) check: bool,

    /// Skip confirmation prompt.
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,

    /// Generate and require Sigstore provenance (CI with OIDC only). Fails if provenance cannot be produced.
    #[arg(long, conflicts_with_all = ["no_provenance", "provenance_file"])]
    pub(crate) provenance: bool,

    /// Disable provenance even when npm config enables it.
    #[arg(long = "no-provenance", conflicts_with_all = ["provenance", "provenance_file"])]
    pub(crate) no_provenance: bool,

    /// Attach a pre-generated Sigstore provenance bundle.
    #[arg(
        long = "provenance-file",
        value_name = "PATH",
        conflicts_with = "no_provenance"
    )]
    pub(crate) provenance_file: Option<std::path::PathBuf>,

    /// Minimum quality score required to publish (0-100).
    #[arg(long)]
    pub(crate) min_score: Option<u32>,

    /// Skip pre-publish secret scanning (not recommended).
    #[arg(long)]
    pub(crate) allow_secrets: bool,

    /// Publish to npm registry.
    #[arg(long)]
    pub(crate) npm: bool,

    /// Publish to LPM registry (default if no other registry specified).
    #[arg(long)]
    pub(crate) lpm: bool,

    /// Publish to GitHub Packages.
    #[arg(long)]
    pub(crate) github: bool,

    /// Publish to GitLab Packages (requires publish.gitlab.projectId in lpm.json).
    #[arg(long)]
    pub(crate) gitlab: bool,

    /// Publish to a custom npm-compatible registry.
    #[arg(long = "publish-registry", value_name = "URL")]
    pub(crate) publish_registry: Option<String>,
}

#[derive(Args)]
pub(crate) struct VersionArgs {
    /// Version bump: patch, minor, major, prepatch, preminor, premajor, prerelease, or an exact version.
    #[arg(value_parser = parse_version_bump)]
    pub(crate) bump: lpm_semver::VersionBump,

    /// Preview the plan without writing files, committing, or tagging.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Update package.json without creating a git commit or tag.
    #[arg(long = "no-git-tag-version")]
    pub(crate) no_git_tag_version: bool,

    /// Prefix for the created git tag.
    #[arg(long = "tag-prefix", default_value = "v")]
    pub(crate) tag_prefix: String,

    /// Commit message. `%s` is replaced with the new version.
    #[arg(long, short = 'm')]
    pub(crate) message: Option<String>,
}

#[derive(Args)]
pub(crate) struct StageArgs {
    #[command(subcommand)]
    pub(crate) command: StageCommands,
}

#[derive(Args)]
pub(crate) struct LoginArgs {
    /// Log in to npm registry with npm web auth.
    #[arg(long)]
    pub(crate) npm: bool,

    /// Use GitHub CLI auth or store an explicit GitHub Packages token.
    #[arg(long)]
    pub(crate) github: bool,

    /// Use GitLab CLI auth or store an explicit GitLab Packages token.
    #[arg(long)]
    pub(crate) gitlab: bool,

    /// Log in to a custom npm-compatible registry.
    #[arg(long = "login-registry", value_name = "URL")]
    pub(crate) login_registry: Option<String>,

    /// Explicit token fallback for npm, GitHub Packages, GitLab Packages, or a custom registry.
    #[arg(long)]
    pub(crate) token: Option<String>,
}

#[derive(Args)]
pub(crate) struct LogoutArgs {
    /// Also revoke browser pairings and the current refresh-backed LPM.dev CLI session.
    #[arg(long)]
    pub(crate) revoke: bool,

    /// Log out from npm registry.
    #[arg(long)]
    pub(crate) npm: bool,

    /// Log out from GitHub Packages.
    #[arg(long)]
    pub(crate) github: bool,

    /// Log out from GitLab Packages.
    #[arg(long)]
    pub(crate) gitlab: bool,

    /// Log out from all registries (LPM + npm + GitHub + GitLab + custom).
    #[arg(long)]
    pub(crate) all: bool,

    /// Log out from a custom npm-compatible registry.
    #[arg(long = "logout-registry", value_name = "URL")]
    pub(crate) logout_registry: Option<String>,
}

#[derive(Args)]
pub(crate) struct SetupArgs {
    #[command(subcommand)]
    pub(crate) action: SetupAction,
}

#[derive(Args)]
pub(crate) struct SwiftRegistryArgs {
    /// Force re-download the signing certificate (useful for cert rotation).
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Subcommand)]
pub(crate) enum StageCommands {
    /// Stage the current package on the npm registry.
    Publish {
        /// npm dist-tag for the staged version.
        #[arg(long)]
        tag: Option<String>,

        /// npm package access.
        #[arg(long, value_parser = ["public", "restricted"])]
        access: Option<String>,

        /// Preview without uploading.
        #[arg(long)]
        dry_run: bool,

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
        provenance_file: Option<std::path::PathBuf>,

        /// Minimum quality score required to stage (0-100).
        #[arg(long)]
        min_score: Option<u32>,

        /// Skip pre-publish secret scanning.
        #[arg(long)]
        allow_secrets: bool,

        /// Skip confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,

        /// Override the npm registry URL.
        #[arg(long = "npm-registry", value_name = "URL")]
        npm_registry: Option<String>,
    },

    /// List staged npm package versions.
    List {
        /// Optional package-name filter.
        package: Option<String>,

        /// Override the npm registry URL.
        #[arg(long = "npm-registry", value_name = "URL")]
        npm_registry: Option<String>,
    },

    /// View one staged npm package version.
    View {
        /// Staged package UUID.
        stage_id: String,

        /// Override the npm registry URL.
        #[arg(long = "npm-registry", value_name = "URL")]
        npm_registry: Option<String>,
    },

    /// Approve a staged npm package version.
    Approve {
        /// Staged package UUID.
        stage_id: String,

        /// One-time password for npm 2FA.
        #[arg(long)]
        otp: Option<String>,

        /// Override the npm registry URL.
        #[arg(long = "npm-registry", value_name = "URL")]
        npm_registry: Option<String>,
    },

    /// Reject a staged npm package version.
    Reject {
        /// Staged package UUID.
        stage_id: String,

        /// One-time password for npm 2FA.
        #[arg(long)]
        otp: Option<String>,

        /// Override the npm registry URL.
        #[arg(long = "npm-registry", value_name = "URL")]
        npm_registry: Option<String>,
    },

    /// Download a staged npm package tarball for inspection.
    Download {
        /// Staged package UUID.
        stage_id: String,

        /// Override the npm registry URL.
        #[arg(long = "npm-registry", value_name = "URL")]
        npm_registry: Option<String>,
    },
}

/// Subcommands of `lpm setup`.
#[derive(Subcommand)]
pub(crate) enum SetupAction {
    /// Generate `.npmrc` for CI/CD.
    Ci {
        /// Setup target: npmrc, github-actions, gitlab.
        target: Option<String>,

        /// Environment name for workflow snippets (default: production).
        #[arg(long)]
        env: Option<String>,

        /// Override the registry URL for `.npmrc` (default: current `--registry` or `LPM_REGISTRY_URL`).
        #[arg(short = 'r', long)]
        registry: Option<String>,

        /// Use OIDC token exchange instead of stored token.
        #[arg(long)]
        oidc: bool,
    },

    /// Generate a read-only `.npmrc` token for local development.
    Local {
        /// Token validity in days (default: 30).
        #[arg(
            short = 'd',
            long,
            default_value = "30",
            value_parser = clap::value_parser!(u32).range(1..=90)
        )]
        days: u32,
    },
}
