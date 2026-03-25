//! File watching for `--watch` mode.
//!
//! Uses the `notify` crate for cross-platform file system events.
//! Debounces events by 200ms and filters by input globs.

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Callback invoked when watched files change.
pub type OnChange = Box<dyn Fn() + Send>;

/// Watch a directory for file changes and invoke a callback on change.
///
/// Blocks the current thread. The callback is called after debouncing
/// (200ms of quiet after the last event).
///
/// Only fires for modify/create/remove events — ignores access events.
pub fn watch_and_run(
	watch_dir: &Path,
	on_change: OnChange,
) -> Result<(), String> {
	let (tx, rx) = mpsc::channel();

	let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
		if let Ok(event) = res {
			let _ = tx.send(event);
		}
	})
	.map_err(|e| format!("failed to create file watcher: {e}"))?;

	watcher
		.watch(watch_dir, RecursiveMode::Recursive)
		.map_err(|e| format!("failed to watch directory: {e}"))?;

	let debounce = Duration::from_millis(200);
	let mut last_event = Instant::now() - debounce;

	// Run once initially
	on_change();

	loop {
		match rx.recv_timeout(Duration::from_millis(100)) {
			Ok(event) => {
				// Filter: only care about modifications, creates, removes
				if is_relevant_event(&event.kind) {
					last_event = Instant::now();
				}
			}
			Err(mpsc::RecvTimeoutError::Timeout) => {
				// Check if debounce period has passed since last event
				if last_event.elapsed() < debounce
					&& last_event.elapsed() >= Duration::from_millis(100)
				{
					// Debounce expired — enough quiet time after last change
					// But we need to wait until debounce has fully passed
				}

				if last_event.elapsed() >= debounce
					&& last_event.elapsed() < debounce + Duration::from_millis(150)
				{
					// Fire the callback once after debounce
					on_change();
				}
			}
			Err(mpsc::RecvTimeoutError::Disconnected) => {
				return Err("file watcher disconnected".into());
			}
		}
	}
}

/// Check if a file event kind is relevant (not just access/metadata).
fn is_relevant_event(kind: &EventKind) -> bool {
	matches!(
		kind,
		EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
	)
}

/// Filter file paths against input glob patterns.
/// Returns true if the path matches any of the patterns.
pub fn matches_input_globs(path: &Path, project_dir: &Path, globs: &[String]) -> bool {
	let rel = path
		.strip_prefix(project_dir)
		.unwrap_or(path)
		.to_string_lossy();

	for pattern in globs {
		if let Ok(glob) = globset::Glob::new(pattern) {
			let matcher = glob.compile_matcher();
			if matcher.is_match(rel.as_ref()) {
				return true;
			}
		}
	}

	false
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::PathBuf;

	#[test]
	fn relevant_event_filtering() {
		assert!(is_relevant_event(&EventKind::Modify(
			notify::event::ModifyKind::Data(notify::event::DataChange::Content)
		)));
		assert!(is_relevant_event(&EventKind::Create(
			notify::event::CreateKind::File
		)));
		assert!(is_relevant_event(&EventKind::Remove(
			notify::event::RemoveKind::File
		)));
		assert!(!is_relevant_event(&EventKind::Access(
			notify::event::AccessKind::Read
		)));
	}

	#[test]
	fn glob_matching() {
		let project = PathBuf::from("/project");

		assert!(matches_input_globs(
			&PathBuf::from("/project/src/index.js"),
			&project,
			&["src/**".into()]
		));

		assert!(!matches_input_globs(
			&PathBuf::from("/project/dist/output.js"),
			&project,
			&["src/**".into()]
		));

		assert!(matches_input_globs(
			&PathBuf::from("/project/package.json"),
			&project,
			&["package.json".into()]
		));
	}
}
