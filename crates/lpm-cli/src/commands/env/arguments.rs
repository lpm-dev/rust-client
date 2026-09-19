use clap::{Args, Parser, Subcommand};
use lpm_common::LpmError;

#[derive(Args)]
pub(super) struct Environment {
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub env: Option<String>,
}

#[derive(Parser)]
#[command(name = "lpm env", disable_help_flag = true)]
struct LocalCommand {
    #[command(subcommand)]
    action: LocalAction,
}

#[derive(Subcommand)]
pub(super) enum LocalAction {
    Set {
        #[command(flatten)]
        environment: Environment,
        #[arg(required = true, num_args = 1.., value_name = "KEY=VALUE")]
        assignments: Vec<String>,
    },
    Get {
        #[command(flatten)]
        environment: Environment,
        key: String,
        #[arg(long)]
        reveal: bool,
    },
    List {
        #[command(flatten)]
        environment: Environment,
        #[arg(long)]
        reveal: bool,
    },
    Delete {
        #[command(flatten)]
        environment: Environment,
        #[arg(required = true, num_args = 1..)]
        keys: Vec<String>,
    },
    Import {
        #[command(flatten)]
        environment: Environment,
        file: String,
        #[arg(long)]
        overwrite: bool,
    },
    Export {
        #[command(flatten)]
        environment: Environment,
        file: String,
        #[arg(long)]
        ci: bool,
    },
    Print {
        #[command(flatten)]
        environment: Environment,
        #[arg(long, value_parser = print_format)]
        format: Option<lpm_env::PrintFormat>,
        #[arg(long)]
        schema_only: bool,
        #[arg(long, conflicts_with_all = ["format", "schema_only"])]
        ci: bool,
    },
    Example {
        #[command(flatten)]
        environment: Environment,
    },
    Check,
    Validate {
        #[arg(long)]
        strict: bool,
    },
    Init {
        #[arg(long)]
        force: bool,
    },
    Ls,
    Log,
    Unpair,
    Diff {
        #[arg(num_args = 0..=2)]
        environments: Vec<String>,
    },
    #[command(alias = "cp")]
    Copy {
        source: String,
        target: String,
        #[arg(long)]
        overwrite: bool,
    },
}

pub(super) fn parse(args: &[&str]) -> Result<Option<LocalAction>, LpmError> {
    if !matches!(
        args.first().copied(),
        Some(
            "set"
                | "get"
                | "list"
                | "delete"
                | "import"
                | "export"
                | "print"
                | "example"
                | "check"
                | "validate"
                | "init"
                | "ls"
                | "copy"
                | "cp"
                | "log"
                | "unpair"
                | "diff"
        )
    ) {
        return Ok(None);
    }
    LocalCommand::try_parse_from(std::iter::once("lpm env").chain(args.iter().copied()))
        .map(|command| Some(command.action))
        .map_err(|error| LpmError::Script(error.to_string()))
}

fn print_format(value: &str) -> Result<lpm_env::PrintFormat, String> {
    lpm_env::PrintFormat::parse(value).ok_or_else(|| {
        format!(
            "unknown format: '{value}'. Available: {}",
            lpm_env::PrintFormat::all_names()
        )
    })
}
