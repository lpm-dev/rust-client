mod canonical;
mod compare;
mod error;
mod lpm;
mod pnpm;
mod report;
mod workspace;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::canonical::CanonicalGraph;
use crate::error::{Result, VerifierError};

#[derive(Debug, Parser)]
#[command(version, about = "Normalize and compare installer lock graphs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    NormalizeLpm {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    NormalizePnpm {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    DiscoverImporters {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Compare {
        #[arg(long)]
        reference: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        compatibility: Option<PathBuf>,
        #[arg(long)]
        json: PathBuf,
        #[arg(long)]
        markdown: PathBuf,
    },
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::NormalizeLpm { workspace, output } => {
            let graph = lpm::normalize(&workspace)?;
            write_json(&output, &graph)
        }
        Command::NormalizePnpm { workspace, output } => {
            let graph = pnpm::normalize(&workspace)?;
            write_json(&output, &graph)
        }
        Command::DiscoverImporters { workspace, output } => {
            let inventory = workspace::discover_recursive_importers(&workspace)?;
            write_json(&output, &inventory)
        }
        Command::Compare {
            reference,
            candidate,
            compatibility,
            json,
            markdown,
        } => {
            let reference = read_graph(&reference)?;
            let candidate = read_graph(&candidate)?;
            let compatibility = compatibility
                .as_deref()
                .map(read_compatibility)
                .transpose()?
                .unwrap_or_default();
            let comparison = compare::compare_with_policy(&reference, &candidate, &compatibility);
            write_json(&json, &comparison)?;
            report::write_markdown(&markdown, &comparison)
        }
    }
}

fn read_compatibility(path: &std::path::Path) -> Result<compare::CompatibilityPolicy> {
    let bytes = std::fs::read(path).map_err(|source| VerifierError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|source| VerifierError::JsonRead {
            path: path.to_path_buf(),
            source,
        })?;
    let compatibility = value
        .pointer("/policy_normalization/unsupported")
        .unwrap_or(&value)
        .clone();
    serde_json::from_value(compatibility).map_err(|source| VerifierError::JsonRead {
        path: path.to_path_buf(),
        source,
    })
}

fn read_graph(path: &std::path::Path) -> Result<CanonicalGraph> {
    let bytes = std::fs::read(path).map_err(|source| VerifierError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| VerifierError::JsonRead {
        path: path.to_path_buf(),
        source,
    })
}

fn write_json(path: &std::path::Path, value: &impl serde::Serialize) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| VerifierError::InvalidOutputPath {
            path: path.to_path_buf(),
        })?;
    std::fs::create_dir_all(parent).map_err(|source| VerifierError::Write {
        path: parent.to_path_buf(),
        source,
    })?;
    let mut bytes = serde_json::to_vec_pretty(value).map_err(VerifierError::JsonWrite)?;
    bytes.push(b'\n');
    std::fs::write(path, bytes).map_err(|source| VerifierError::Write {
        path: path.to_path_buf(),
        source,
    })
}
