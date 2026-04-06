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

/// Maximum age of the oldest log entry before rotation (7 days).
const MAX_LOG_AGE_SECS: i64 = 7 * 24 * 60 * 60;

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
        && id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

/// Remove body files referenced by entries in a JSONL log file.
///
/// Called during rotation to clean up orphaned `.json` body files
/// when their corresponding log entries are being discarded.
fn cleanup_bodies_for_log(log_path: &Path, bodies_dir: &Path) {
    if let Ok(content) = std::fs::read_to_string(log_path) {
        for line in content.lines() {
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line)
                && let Some(id) = entry.get("id").and_then(|v| v.as_str())
            {
                let body_file = bodies_dir.join(format!("{id}.json"));
                let _ = std::fs::remove_file(&body_file);
            }
        }
    }
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
        // Validate webhook ID before any writes to prevent path traversal
        if !is_safe_id(&webhook.id) {
            tracing::warn!("skipping webhook with unsafe ID: {}", webhook.id);
            return Ok(());
        }

        // Ensure directories exist
        std::fs::create_dir_all(&self.log_dir)?;
        std::fs::create_dir_all(&self.bodies_dir)?;

        // Set restrictive permissions on log file and bodies dir
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&self.bodies_dir, std::fs::Permissions::from_mode(0o700));
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

        let mut line = serde_json::to_string(&entry).map_err(std::io::Error::other)?;
        line.push('\n');

        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
        }
        let mut file = open_opts.open(&self.log_file)?;
        file.write_all(line.as_bytes())?;

        // Store full webhook with bodies (restrictive permissions on Unix)
        let body_path = self.bodies_dir.join(format!("{}.json", webhook.id));
        let full_json = serde_json::to_string(webhook).map_err(std::io::Error::other)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&body_path)?;
            f.write_all(full_json.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&body_path, &full_json)?;
        }

        Ok(())
    }

    /// Read recent log entries, newest first.
    ///
    /// If `filter` is provided, only matching entries are returned.
    /// Returns at most `count` entries.
    /// Maximum bytes to read from the tail of a large log file.
    /// For files larger than this, only the last 1 MB is parsed, which
    /// should contain hundreds of recent entries — more than enough
    /// for any reasonable `count`.
    const MAX_TAIL_READ: u64 = 1_024 * 1_024;

    pub fn read_recent(
        &self,
        count: usize,
        filter: Option<&WebhookFilter>,
    ) -> Vec<WebhookLogEntry> {
        let mut entries: Vec<WebhookLogEntry> = Vec::new();

        // Read active log first, then rotated files (.1, .2, .3) until we
        // have enough entries. Each file's entries are added newest-first.
        let mut files_to_read: Vec<&Path> = vec![&self.log_file];
        let rotated_paths: Vec<PathBuf> = (1..=MAX_ROTATED_FILES)
            .map(|i| self.rotated_path(i))
            .collect();
        for path in &rotated_paths {
            files_to_read.push(path);
        }

        for path in files_to_read {
            let content = match Self::read_file_content(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut file_entries: Vec<WebhookLogEntry> = content
                .lines()
                .filter(|line| !line.is_empty())
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();

            // Newest-first within this file
            file_entries.reverse();

            // Apply filters before adding
            if let Some(f) = filter {
                file_entries.retain(|entry| {
                    if let Some(ref provider) = f.provider {
                        let entry_provider = entry.provider.as_deref().unwrap_or("");
                        if !entry_provider.eq_ignore_ascii_case(provider) {
                            return false;
                        }
                    }
                    if let Some(ref status) = f.status
                        && !status.matches(entry.status)
                    {
                        return false;
                    }
                    true
                });
            }

            entries.extend(file_entries);

            // Stop reading more files once we have enough
            if entries.len() >= count {
                break;
            }
        }

        entries.truncate(count);
        entries
    }

    /// Read a log file's content, with tail-reading optimization for large files.
    ///
    /// For files <= `MAX_TAIL_READ` bytes, reads the entire file. For larger
    /// files, seeks to `file_size - MAX_TAIL_READ` and reads from there,
    /// skipping the first (likely partial) line.
    fn read_file_content(path: &Path) -> std::io::Result<String> {
        use std::io::{Read, Seek, SeekFrom};

        let metadata = std::fs::metadata(path)?;
        let file_size = metadata.len();

        if file_size <= Self::MAX_TAIL_READ {
            return std::fs::read_to_string(path);
        }

        // Read only the tail of the file
        let mut file = std::fs::File::open(path)?;
        let offset = file_size - Self::MAX_TAIL_READ;
        file.seek(SeekFrom::Start(offset))?;

        let mut buf = String::with_capacity(Self::MAX_TAIL_READ as usize);
        file.read_to_string(&mut buf)?;

        // Skip the first partial line (we likely landed mid-line)
        if let Some(newline_pos) = buf.find('\n') {
            buf.drain(..=newline_pos);
        }

        Ok(buf)
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

    /// Rotate the log file if it exceeds [`MAX_LOG_SIZE`] or the oldest
    /// entry is older than [`MAX_LOG_AGE_SECS`] (7 days).
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

        let should_rotate = if metadata.len() >= MAX_LOG_SIZE {
            true
        } else {
            // Check age of oldest entry (first line of the file)
            self.oldest_entry_exceeds_max_age()
        };

        if !should_rotate {
            return Ok(());
        }

        self.perform_rotation()
    }

    /// Check if the oldest log entry (first line) is older than [`MAX_LOG_AGE_SECS`].
    ///
    /// Reads only the first line of the JSONL file and parses its `ts` field.
    /// Returns `false` if the file can't be read or the timestamp can't be parsed.
    fn oldest_entry_exceeds_max_age(&self) -> bool {
        use std::io::BufRead;
        let file = match std::fs::File::open(&self.log_file) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let reader = std::io::BufReader::new(file);
        let first_line = match reader.lines().next() {
            Some(Ok(line)) => line,
            _ => return false,
        };
        let entry: serde_json::Value = match serde_json::from_str(&first_line) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let ts_str = match entry.get("ts").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return false,
        };
        // Parse ISO 8601 timestamp and compare with current time.
        // chrono is already a dependency of lpm-tunnel.
        let entry_time = match chrono::DateTime::parse_from_rfc3339(ts_str) {
            Ok(t) => t,
            Err(_) => return false,
        };
        let age_secs = chrono::Utc::now()
            .signed_duration_since(entry_time)
            .num_seconds();
        age_secs > MAX_LOG_AGE_SECS
    }

    /// Execute the actual file rotation (shift .1→.2→.3, delete oldest, move current→.1).
    fn perform_rotation(&self) -> std::io::Result<()> {
        // Shift existing rotated files: .3 → delete (+ clean bodies), .2 → .3, .1 → .2
        for i in (1..=MAX_ROTATED_FILES).rev() {
            let from = self.rotated_path(i);
            if i == MAX_ROTATED_FILES {
                // Clean up body files referenced by the oldest rotated log before deleting it
                cleanup_bodies_for_log(&from, &self.bodies_dir);
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
            // Use current time so age-based rotation doesn't trigger unexpectedly
            timestamp: chrono::Utc::now().to_rfc3339(),
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
            auto_acked: false,
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

    #[cfg(unix)]
    #[test]
    fn log_file_created_with_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let logger = WebhookLogger::new(dir.path());
        logger.append(&make_webhook("perm-1")).unwrap();

        let metadata = std::fs::metadata(&logger.log_file).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "log file should have 0o600 permissions, got {mode:o}"
        );
    }

    #[test]
    fn unsafe_id_skipped_before_jsonl_write() {
        let dir = tempfile::tempdir().unwrap();
        let logger = WebhookLogger::new(dir.path());

        let mut wh = make_webhook("../../../etc/passwd");
        // The make_webhook helper sets id, so override it
        wh.id = "../../../etc/passwd".to_string();
        // append should silently skip (return Ok)
        logger.append(&wh).unwrap();

        // JSONL log should not exist (no writes happened)
        assert!(
            !logger.log_file.exists(),
            "JSONL log should not be written for unsafe ID"
        );
    }

    #[test]
    fn rotation_cleans_up_orphaned_body_files() {
        let dir = tempfile::tempdir().unwrap();
        let logger = WebhookLogger::new(dir.path());

        // Create dirs
        std::fs::create_dir_all(&logger.log_dir).unwrap();
        std::fs::create_dir_all(&logger.bodies_dir).unwrap();

        // Write 3 webhooks normally
        logger.append(&make_webhook("old-1")).unwrap();
        logger.append(&make_webhook("old-2")).unwrap();
        logger.append(&make_webhook("old-3")).unwrap();

        // Verify body files exist
        assert!(logger.bodies_dir.join("old-1.json").exists());
        assert!(logger.bodies_dir.join("old-2.json").exists());
        assert!(logger.bodies_dir.join("old-3.json").exists());

        // Simulate: fill up rotated slots so current log is at MAX_ROTATED_FILES
        // Move current log to .3 (oldest slot that gets deleted on next rotation)
        std::fs::rename(&logger.log_file, logger.rotated_path(MAX_ROTATED_FILES)).unwrap();

        // Create a large current log to trigger rotation
        let large_content = "x".repeat(MAX_LOG_SIZE as usize + 1);
        std::fs::write(&logger.log_file, &large_content).unwrap();

        logger.rotate_if_needed().unwrap();

        // Body files from the deleted .3 log should be cleaned up
        assert!(
            !logger.bodies_dir.join("old-1.json").exists(),
            "old-1 body should be cleaned"
        );
        assert!(
            !logger.bodies_dir.join("old-2.json").exists(),
            "old-2 body should be cleaned"
        );
        assert!(
            !logger.bodies_dir.join("old-3.json").exists(),
            "old-3 body should be cleaned"
        );
    }

    #[cfg(unix)]
    #[test]
    fn body_file_created_with_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let logger = WebhookLogger::new(dir.path());
        logger.append(&make_webhook("perm-body")).unwrap();

        let body_path = logger.bodies_dir.join("perm-body.json");
        let metadata = std::fs::metadata(&body_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "body file should have 0o600 permissions, got {mode:o}"
        );
    }

    #[test]
    fn read_empty_log() {
        let dir = tempfile::tempdir().unwrap();
        let logger = WebhookLogger::new(dir.path());
        let entries = logger.read_recent(10, None);
        assert!(entries.is_empty());
    }

    // ── Age-based rotation tests ──────────────────────────────────

    #[test]
    fn age_rotation_triggers_when_oldest_entry_exceeds_7_days() {
        let dir = tempfile::tempdir().unwrap();
        let logger = WebhookLogger::new(dir.path());

        std::fs::create_dir_all(&logger.log_dir).unwrap();

        // Write a JSONL entry with a timestamp 8 days ago
        let old_ts = (chrono::Utc::now() - chrono::Duration::days(8)).to_rfc3339();
        let entry = serde_json::json!({
            "id": "old-1", "ts": old_ts, "method": "POST",
            "path": "/hook", "status": 200, "ms": 10,
            "provider": null, "summary": "test", "req_size": 0, "res_size": 0,
        });
        let mut line = serde_json::to_string(&entry).unwrap();
        line.push('\n');
        std::fs::write(&logger.log_file, &line).unwrap();

        // Should rotate due to age even though file is tiny
        logger.rotate_if_needed().unwrap();

        assert!(
            !logger.log_file.exists(),
            "active log should be rotated away"
        );
        assert!(logger.rotated_path(1).exists(), "rotated .1 should exist");
    }

    #[test]
    fn age_rotation_does_not_trigger_for_recent_entries() {
        let dir = tempfile::tempdir().unwrap();
        let logger = WebhookLogger::new(dir.path());

        std::fs::create_dir_all(&logger.log_dir).unwrap();

        // Write a JSONL entry with a recent timestamp
        let recent_ts = chrono::Utc::now().to_rfc3339();
        let entry = serde_json::json!({
            "id": "new-1", "ts": recent_ts, "method": "POST",
            "path": "/hook", "status": 200, "ms": 10,
            "provider": null, "summary": "test", "req_size": 0, "res_size": 0,
        });
        let mut line = serde_json::to_string(&entry).unwrap();
        line.push('\n');
        std::fs::write(&logger.log_file, &line).unwrap();

        // Should NOT rotate — entry is fresh
        logger.rotate_if_needed().unwrap();

        assert!(logger.log_file.exists(), "active log should remain");
        assert!(
            !logger.rotated_path(1).exists(),
            "no rotation should have happened"
        );
    }

    // ── Read rotated files tests ──────────────────────────────────

    #[test]
    fn read_recent_spans_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        let logger = WebhookLogger::new(dir.path());

        // Write 3 entries to active log
        logger.append(&make_webhook("active-1")).unwrap();
        logger.append(&make_webhook("active-2")).unwrap();
        logger.append(&make_webhook("active-3")).unwrap();

        // Manually create a rotated file with 2 older entries
        std::fs::create_dir_all(&logger.log_dir).unwrap();
        let rotated_entries = [
            serde_json::json!({"id":"rot-1","ts":"2026-01-01T00:00:00Z","method":"POST","path":"/old","status":200,"ms":5,"provider":null,"summary":"old 1","req_size":0,"res_size":0}),
            serde_json::json!({"id":"rot-2","ts":"2026-01-01T00:01:00Z","method":"POST","path":"/old","status":200,"ms":5,"provider":null,"summary":"old 2","req_size":0,"res_size":0}),
        ];
        let rotated_content: String = rotated_entries
            .iter()
            .map(|e| format!("{}\n", serde_json::to_string(e).unwrap()))
            .collect();
        std::fs::write(logger.rotated_path(1), rotated_content).unwrap();

        // Request 5 entries — should span active (3) + rotated (2)
        let entries = logger.read_recent(5, None);
        assert_eq!(entries.len(), 5);

        // Newest first: active-3, active-2, active-1, rot-2, rot-1
        assert_eq!(entries[0].id, "active-3");
        assert_eq!(entries[1].id, "active-2");
        assert_eq!(entries[2].id, "active-1");
        assert_eq!(entries[3].id, "rot-2");
        assert_eq!(entries[4].id, "rot-1");
    }

    #[test]
    fn read_recent_stops_when_count_satisfied() {
        let dir = tempfile::tempdir().unwrap();
        let logger = WebhookLogger::new(dir.path());

        // Write 5 entries to active log
        for i in 0..5 {
            logger.append(&make_webhook(&format!("wh-{i}"))).unwrap();
        }

        // Create a rotated file (should NOT be read)
        std::fs::create_dir_all(&logger.log_dir).unwrap();
        let rotated_entry = serde_json::json!({"id":"should-not-appear","ts":"2026-01-01T00:00:00Z","method":"POST","path":"/old","status":200,"ms":5,"provider":null,"summary":"old","req_size":0,"res_size":0});
        std::fs::write(
            logger.rotated_path(1),
            format!("{}\n", serde_json::to_string(&rotated_entry).unwrap()),
        )
        .unwrap();

        // Request only 3 entries — active log has enough
        let entries = logger.read_recent(3, None);
        assert_eq!(entries.len(), 3);
        // None should be from the rotated file
        assert!(entries.iter().all(|e| e.id != "should-not-appear"));
    }

    #[test]
    fn read_recent_filters_across_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        let logger = WebhookLogger::new(dir.path());

        // Active log: one Stripe webhook
        let mut stripe_wh = make_webhook("stripe-active");
        stripe_wh.provider = Some(WebhookProvider::Stripe);
        logger.append(&stripe_wh).unwrap();

        // Rotated file: one GitHub + one Stripe entry
        std::fs::create_dir_all(&logger.log_dir).unwrap();
        let rotated = [
            serde_json::json!({"id":"github-rot","ts":"2026-01-01T00:00:00Z","method":"POST","path":"/gh","status":200,"ms":5,"provider":"GitHub","summary":"GitHub: push","req_size":0,"res_size":0}),
            serde_json::json!({"id":"stripe-rot","ts":"2026-01-01T00:01:00Z","method":"POST","path":"/stripe","status":200,"ms":5,"provider":"Stripe","summary":"Stripe: payment","req_size":0,"res_size":0}),
        ];
        let content: String = rotated
            .iter()
            .map(|e| format!("{}\n", serde_json::to_string(e).unwrap()))
            .collect();
        std::fs::write(logger.rotated_path(1), content).unwrap();

        // Filter for Stripe only
        let filter = WebhookFilter {
            provider: Some("Stripe".to_string()),
            status: None,
        };
        let entries = logger.read_recent(10, Some(&filter));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "stripe-active");
        assert_eq!(entries[1].id, "stripe-rot");
    }
}
