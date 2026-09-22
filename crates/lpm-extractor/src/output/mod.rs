#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(super) use unix::OutputTree;
#[cfg(any(test, not(unix)))]
mod portable;
#[cfg(not(unix))]
pub(super) use portable::OutputTree;
