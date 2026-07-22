#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("parse error: {0}")]
    Parse(String),
}
