//! Persistent JSONL webhook logging with body storage.
//!
//! Writes compact log entries to `.lpm/webhook-log.jsonl` and stores full
//! request/response bodies in `.lpm/webhooks/{id}.json`. Supports filtering,
//! pagination (newest-first reads), and automatic log rotation at 10 MB.

use crate::webhook::CapturedWebhook;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Maximum JSONL log file size before rotation (10 MB).
const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum number of rotated log files to keep.
const MAX_ROTATED_FILES: usize = 3;

/// Persistent webhook logger that writes to `.lpm/` in the project directory.
pub struct WebhookLogger {
	/// The `.lpm/` directory.
	log_dir: PathBuf,
	/// Path to the active JSONL log file.
	log_file: PathBuf,
	/// Directory for full webhook body storage.
	bodies_dir: PathBuf,
}

/// Compact log entry stored in the JSONL file (no bodies).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookLogEntry {
	pub id: String,
	pub ts: String,
	pub method: String,
	pub path: String,
	pub status: u16,
	pub ms: u64,
	pub provider: Option<String>,
	pub summary: String,
	pub req_size: usize,
	pub res_size: usize,
}

/// Filter criteria for reading log entries.
pub struct WebhookFilter {
	/// Filter by provider name (case-insensitive).
	pub provider: Option<String>,
	/// Filter by response status.
	pub status: Option<StatusFilter>,
}

/// Status code filter variants.
pub enum StatusFilter {
	/// Exact status code match (e.g., 200).
	Exact(u16),
	/// Inclusive range (e.g., 400..=499).
	Range(u16, u16),
	/// Status class: 2 = 2xx, 4 = 4xx, 5 = 5xx.
	Class(u16),
}

impl StatusFilter {
	/// Check if a status code matches this filter.
	fn matches(&self, status: u16) -> bool {
		match self {
			Self::Exact(code) => status == *code,
			Self::Range(lo, hi) => status >= *lo && status <= *hi,
			Self::Class(class) => status / 100 == *class,
		}
	}
}

/// Check if a webhook ID is safe to use in a file path.
/// Only allows alphanumeric characters, hyphens, and underscores.
fn is_safe_id(id: &str) -> bool {
	!id.is_empty()
		&& id.len() <= 256
		&& id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

impl WebhookLogger {
	/// Create a new logger rooted at `project_dir/.lpm/`.
	///
	/// Does not create directories eagerly; they are created on first write.
	pub fn new(project_dir: &Path) -> Self {
		let log_dir = project_dir.join(".lpm");
		let log_file = log_dir.join("webhook-log.jsonl");
		let bodies_dir = log_dir.join("webhooks");
		Self {
			log_dir,
			log_file,
			bodies_dir,
		}
	}

	/// Append a captured webhook to the JSONL log and store its full bodies.
	///
	/// Creates directories if they don't exist. Rotates the log file if it
	/// exceeds [`MAX_LOG_SIZE`].
	pub fn append(&self, webhook: &CapturedWebhook) -> std::io::Result<()> {
		// Ensure directories exist
		std::fs::create_dir_all(&self.log_dir)?;
		std::fs::create_dir_all(&self.bodies_dir)?;

		// Set restrictive permissions on log file and bodies dir
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let _ = std::fs::set_permissions(&self.bodies_dir, std::fs::Permissions::from_mode(0o700));
		}

		// Rotate if the log file is too large
		self.rotate_if_needed()?;

		// Write compact entry to JSONL
		let entry = WebhookLogEntry {
			id: webhook.id.clone(),
			ts: webhook.timestamp.clone(),
			method: webhook.method.clone(),
			path: webhook.path.clone(),
			status: webhook.response_status,
			ms: webhook.duration_ms,
			provider: webhook.provider.map(|p| p.to_string()),
			summary: webhook.summary.clone(),
			req_size: webhook.request_body.len(),
			res_size: webhook.response_body.len(),
		};

		let mut line = serde_json::to_string(&entry)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
		line.push('\n');

		let mut file = std::fs::OpenOptions::new()
			.create(true)
			.append(true)
			.open(&self.log_file)?;
		file.write_all(line.as_bytes())?;

		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let _ = std::fs::set_permissions(&self.log_file, std::fs::Permissions::from_mode(0o600));
		}

		// Sanitize webhook ID before using in file path
		if !is_safe_id(&webhook.id) {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidInput,
				format!("unsafe webhook ID: {}", webhook.id),
			));
		}

		// Store full webhook with bodies
		let body_path = self.bodies_dir.join(format!("{}.json", webhook.id));
		let full_json = serde_json::to_string(webhook)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
		std::fs::write(&body_path, full_json)?;

		Ok(())
	}

	/// Read recent log entries, newest first.
	///
	/// If `filter` is provided, only matching entries are returned.
	/// Returns at most `count` entries.
	pub fn read_recent(
		&self,
		count: usize,
		filter: Option<&WebhookFilter>,
	) -> Vec<WebhookLogEntry> {
		let content = match std::fs::read_to_string(&self.log_file) {
			Ok(c) => c,
			Err(_) => return Vec::new(),
		};

		let mut entries: Vec<WebhookLogEntry> = content
			.lines()
			.filter(|line| !line.is_empty())
			.filter_map(|line| serde_json::from_str(line).ok())
			.collect();

		// Reverse to get newest-first order
		entries.reverse();

		// Apply filters
		if let Some(f) = filter {
			entries.retain(|entry| {
				if let Some(ref provider) = f.provider {
					let entry_provider = entry.provider.as_deref().unwrap_or("");
					if !entry_provider.eq_ignore_ascii_case(provider) {
						return false;
					}
				}
				if let Some(ref status) = f.status {
					if !status.matches(entry.status) {
						return false;
					}
				}
				true
			});
		}

		entries.truncate(count);
		entries
	}

	/// Load the full webhook (including bodies) by ID.
	pub fn load_full(&self, id: &str) -> Option<CapturedWebhook> {
		if !is_safe_id(id) {
			return None;
		}
		let body_path = self.bodies_dir.join(format!("{id}.json"));
		let content = std::fs::read_to_string(&body_path).ok()?;
		serde_json::from_str(&content).ok()
	}

	/// Rotate the log file if it exceeds [`MAX_LOG_SIZE`].
	///
	/// Renames `webhook-log.jsonl` → `webhook-log.1.jsonl`,
	/// `webhook-log.1.jsonl` → `webhook-log.2.jsonl`, etc.
	/// Deletes the oldest file if more than [`MAX_ROTATED_FILES`] exist.
	pub fn rotate_if_needed(&self) -> std::io::Result<()> {
		let metadata = match std::fs::metadata(&self.log_file) {
			Ok(m) => m,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
			Err(e) => return Err(e),
		};

		if metadata.len() < MAX_LOG_SIZE {
			return Ok(());
		}

		// Shift existing rotated files: .3 → delete, .2 → .3, .1 → .2
		for i in (1..=MAX_ROTATED_FILES).rev() {
			let from = self.rotated_path(i);
			if i == MAX_ROTATED_FILES {
				// Delete the oldest rotated file
				let _ = std::fs::remove_file(&from);
			} else {
				let to = self.rotated_path(i + 1);
				if from.exists() {
					std::fs::rename(&from, &to)?;
				}
			}
		}

		// Move current log to .1
		std::fs::rename(&self.log_file, self.rotated_path(1))?;

		Ok(())
	}

	/// Clear all logs and body files.
	pub fn clear(&self) -> std::io::Result<()> {
		// Remove the JSONL log and rotated copies
		let _ = std::fs::remove_file(&self.log_file);
		for i in 1..=MAX_ROTATED_FILES {
			let _ = std::fs::remove_file(self.rotated_path(i));
		}

		// Remove the bodies directory
		if self.bodies_dir.exists() {
			std::fs::remove_dir_all(&self.bodies_dir)?;
		}

		Ok(())
	}

	/// Path for a rotated log file (e.g., `webhook-log.1.jsonl`).
	fn rotated_path(&self, index: usize) -> PathBuf {
		self.log_dir.join(format!("webhook-log.{index}.jsonl"))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::webhook::{CapturedWebhook, WebhookProvider};
	use std::collections::HashMap;

	fn make_webhook(id: &str) -> CapturedWebhook {
		CapturedWebhook {
			id: id.to_string(),
			timestamp: "2026-01-15T10:30:00Z".to_string(),
			method: "POST".to_string(),
			path: "/api/webhook".to_string(),
			request_headers: HashMap::new(),
			request_body: b"request body".to_vec(),
			response_status: 200,
			response_headers: HashMap::new(),
			response_body: b"ok".to_vec(),
			duration_ms: 42,
			provider: None,
			summary: "POST /api/webhook (12B)".to_string(),
			signature_diagnostic: None,
		}
	}

	#[test]
	fn append_and_read_back() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());

		logger.append(&make_webhook("wh-1")).unwrap();
		logger.append(&make_webhook("wh-2")).unwrap();
		logger.append(&make_webhook("wh-3")).unwrap();

		let entries = logger.read_recent(10, None);
		assert_eq!(entries.len(), 3);
		// Newest first
		assert_eq!(entries[0].id, "wh-3");
		assert_eq!(entries[1].id, "wh-2");
		assert_eq!(entries[2].id, "wh-1");
	}

	#[test]
	fn read_recent_respects_count() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());

		for i in 0..10 {
			logger.append(&make_webhook(&format!("wh-{i}"))).unwrap();
		}

		let entries = logger.read_recent(3, None);
		assert_eq!(entries.len(), 3);
		assert_eq!(entries[0].id, "wh-9");
	}

	#[test]
	fn filter_by_provider() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());

		let mut stripe_wh = make_webhook("stripe-1");
		stripe_wh.provider = Some(WebhookProvider::Stripe);
		stripe_wh.summary = "Stripe: payment_intent.succeeded".to_string();
		logger.append(&stripe_wh).unwrap();

		let mut github_wh = make_webhook("github-1");
		github_wh.provider = Some(WebhookProvider::GitHub);
		github_wh.summary = "GitHub: push".to_string();
		logger.append(&github_wh).unwrap();

		let filter = WebhookFilter {
			provider: Some("Stripe".to_string()),
			status: None,
		};
		let entries = logger.read_recent(10, Some(&filter));
		assert_eq!(entries.len(), 1);
		assert_eq!(entries[0].id, "stripe-1");
	}

	#[test]
	fn filter_by_status_class() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());

		let mut ok_wh = make_webhook("ok-1");
		ok_wh.response_status = 200;
		logger.append(&ok_wh).unwrap();

		let mut err_wh = make_webhook("err-1");
		err_wh.response_status = 500;
		logger.append(&err_wh).unwrap();

		let filter = WebhookFilter {
			provider: None,
			status: Some(StatusFilter::Class(5)),
		};
		let entries = logger.read_recent(10, Some(&filter));
		assert_eq!(entries.len(), 1);
		assert_eq!(entries[0].id, "err-1");
	}

	#[test]
	fn filter_by_status_exact() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());

		let mut wh1 = make_webhook("a");
		wh1.response_status = 200;
		logger.append(&wh1).unwrap();

		let mut wh2 = make_webhook("b");
		wh2.response_status = 201;
		logger.append(&wh2).unwrap();

		let filter = WebhookFilter {
			provider: None,
			status: Some(StatusFilter::Exact(201)),
		};
		let entries = logger.read_recent(10, Some(&filter));
		assert_eq!(entries.len(), 1);
		assert_eq!(entries[0].id, "b");
	}

	#[test]
	fn filter_by_status_range() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());

		for status in [200, 301, 400, 404, 500] {
			let mut wh = make_webhook(&format!("s-{status}"));
			wh.response_status = status;
			logger.append(&wh).unwrap();
		}

		let filter = WebhookFilter {
			provider: None,
			status: Some(StatusFilter::Range(400, 499)),
		};
		let entries = logger.read_recent(10, Some(&filter));
		assert_eq!(entries.len(), 2);
		// Newest first: 404, then 400
		assert_eq!(entries[0].id, "s-404");
		assert_eq!(entries[1].id, "s-400");
	}

	#[test]
	fn load_full_with_bodies() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());

		let mut wh = make_webhook("full-1");
		wh.request_body = b"detailed request".to_vec();
		wh.response_body = b"detailed response".to_vec();
		logger.append(&wh).unwrap();

		let loaded = logger.load_full("full-1").unwrap();
		assert_eq!(loaded.id, "full-1");
		assert_eq!(loaded.request_body, b"detailed request");
		assert_eq!(loaded.response_body, b"detailed response");
	}

	#[test]
	fn load_full_returns_none_for_missing() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());
		assert!(logger.load_full("nonexistent").is_none());
	}

	#[test]
	fn rotation_at_size_limit() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());

		// Create directories
		std::fs::create_dir_all(&logger.log_dir).unwrap();

		// Write a file that exceeds MAX_LOG_SIZE
		let large_content = "x".repeat(MAX_LOG_SIZE as usize + 1);
		std::fs::write(&logger.log_file, &large_content).unwrap();

		logger.rotate_if_needed().unwrap();

		// Original should not exist (it was rotated)
		assert!(!logger.log_file.exists());
		// Rotated file .1 should exist
		assert!(logger.rotated_path(1).exists());
		let rotated = std::fs::read_to_string(logger.rotated_path(1)).unwrap();
		assert_eq!(rotated, large_content);
	}

	#[test]
	fn rotation_shifts_existing_files() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());

		std::fs::create_dir_all(&logger.log_dir).unwrap();

		// Create existing rotated files
		std::fs::write(logger.rotated_path(1), "old-1").unwrap();
		std::fs::write(logger.rotated_path(2), "old-2").unwrap();

		// Create a large current log
		let large_content = "x".repeat(MAX_LOG_SIZE as usize + 1);
		std::fs::write(&logger.log_file, &large_content).unwrap();

		logger.rotate_if_needed().unwrap();

		// .1 is the new rotation (was current)
		assert_eq!(
			std::fs::read_to_string(logger.rotated_path(1)).unwrap(),
			large_content
		);
		// .2 is the old .1
		assert_eq!(
			std::fs::read_to_string(logger.rotated_path(2)).unwrap(),
			"old-1"
		);
		// .3 is the old .2
		assert_eq!(
			std::fs::read_to_string(logger.rotated_path(3)).unwrap(),
			"old-2"
		);
	}

	#[test]
	fn clear_removes_everything() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());

		logger.append(&make_webhook("c-1")).unwrap();
		logger.append(&make_webhook("c-2")).unwrap();

		// Verify files exist
		assert!(logger.log_file.exists());
		assert!(logger.bodies_dir.exists());

		logger.clear().unwrap();

		assert!(!logger.log_file.exists());
		assert!(!logger.bodies_dir.exists());
	}

	#[test]
	fn read_empty_log() {
		let dir = tempfile::tempdir().unwrap();
		let logger = WebhookLogger::new(dir.path());
		let entries = logger.read_recent(10, None);
		assert!(entries.is_empty());
	}
}
