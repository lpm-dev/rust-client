use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, VerifierError>;

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("workspace path does not exist or is not a directory: {path}", path = .path.display())]
    InvalidWorkspace { path: PathBuf },
    #[error("failed to discover workspace importers below {path}: {message}", path = .path.display())]
    WorkspaceDiscovery { path: PathBuf, message: String },
    #[error("output path has no parent: {path}", path = .path.display())]
    InvalidOutputPath { path: PathBuf },
    #[error("failed to read {path}: {source}", path = .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write {path}: {source}", path = .path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse JSON {path}: {source}", path = .path.display())]
    JsonRead {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize JSON: {0}")]
    JsonWrite(#[source] serde_json::Error),
    #[error("failed to parse YAML {path}: {source}", path = .path.display())]
    YamlRead {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("failed to parse LPM lockfile {path}: {message}", path = .path.display())]
    LpmLockfile { path: PathBuf, message: String },
    #[error("unsupported pnpm lockfile version {version:?} in {path}", path = .path.display())]
    UnsupportedPnpmLockfile { path: PathBuf, version: String },
    #[error("invalid pnpm package reference {reference:?}: {reason}")]
    InvalidPnpmReference { reference: String, reason: String },
    #[error("no lpm.lock files were found below {path}", path = .path.display())]
    NoLpmLockfiles { path: PathBuf },
    #[error("pnpm-lock.yaml was not found at {path}", path = .path.display())]
    NoPnpmLockfile { path: PathBuf },
}
