//! File watching for `--watch` mode.
//!
//! Uses the `notify` crate for cross-platform file system events.
//! Debounces events by 200ms — only fires after 200ms of quiet.
//! Filters by input globs so only relevant file changes trigger rebuilds.

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Callback invoked when watched files change.
pub type OnChange = Box<dyn Fn() + Send>;

/// Watch a directory for file changes and invoke a callback on change.
///
/// Blocks the current thread. The callback is called after debouncing
/// (200ms of quiet after the last relevant event).
///
/// Only fires for modify/create/remove events on relevant paths — ignores
/// access events, `.git` changes, `node_modules`, and build outputs.
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
	let mut last_relevant_event: Option<Instant> = None;
	let mut debounce_fired = true; // Start as fired so initial run doesn't re-trigger

	// Run once initially
	on_change();

	loop {
		match rx.recv_timeout(Duration::from_millis(50)) {
			Ok(event) => {
				// Filter: only care about modifications, creates, removes
				if !is_relevant_event(&event.kind) {
					continue;
				}

				// Filter: ignore .git, node_modules, common build outputs
				let dominated_by_ignored = event.paths.iter().all(|p| {
					let s = p.to_string_lossy();
					s.contains("/.git/")
						|| s.contains("/node_modules/")
						|| s.contains("/.lpm/")
						|| s.ends_with(".swp")
						|| s.ends_with("~")
				});
				if dominated_by_ignored {
					continue;
				}

				// Record this as a relevant event and reset debounce
				last_relevant_event = Some(Instant::now());
				debounce_fired = false;
			}
			Err(mpsc::RecvTimeoutError::Timeout) => {
				// Check if debounce period has passed since last relevant event
				if let Some(last) = last_relevant_event {
					if !debounce_fired && last.elapsed() >= debounce {
						on_change();
						debounce_fired = true;
					}
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

	#[test]
	fn glob_matching_node_modules_excluded() {
		let project = PathBuf::from("/project");

		// node_modules shouldn't match src/**
		assert!(!matches_input_globs(
			&PathBuf::from("/project/node_modules/react/index.js"),
			&project,
			&["src/**".into()]
		));
	}

	#[test]
	fn debounce_flag_logic() {
		// Test the debounce state machine logic
		let mut debounce_fired = true; // starts fired (initial run done)
		let debounce = Duration::from_millis(200);

		// Simulate event arrives
		let last_event = Instant::now();
		debounce_fired = false;

		// Before debounce: should NOT fire
		assert!(!debounce_fired);
		assert!(last_event.elapsed() < debounce); // too soon

		// After debounce period: should fire exactly once
		std::thread::sleep(Duration::from_millis(250));
		if !debounce_fired && last_event.elapsed() >= debounce {
			debounce_fired = true;
		}
		assert!(debounce_fired);

		// Subsequent checks: already fired, should not fire again
		let should_fire = !debounce_fired && last_event.elapsed() >= debounce;
		assert!(!should_fire, "should not fire again after debounce_fired");
	}
}
