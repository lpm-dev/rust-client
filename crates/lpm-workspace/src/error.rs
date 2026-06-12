#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("IO error: {0}")]
    Io(String),

    #[error("parse error: {0}")]
    Parse(String),
}
