#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(super) use unix::{CompletedFile, Identity, OutputTree, PendingFile};
#[cfg(any(test, not(unix)))]
mod portable;
#[cfg(not(unix))]
pub(super) use portable::{CompletedFile, Identity, OutputTree, PendingFile};
