//! SQLite persistence layer with FTS5 full-text search.
//!
//! Stores all captured HTTP traffic in `.lpm/inspector.db`. Uses:
//! - WAL mode for concurrent reads/writes without blocking
//! - FTS5 virtual table for full-text search across request/response bodies
//! - Write batching via a background flush task to avoid SQLite becoming
//!   a bottleneck on the tunnel's hot path
//!
//! # Schema
//!
//! - `sessions` — tunnel session metadata (start/end, domain, port)
//! - `requests` — captured HTTP requests/responses (headers, bodies, timing)
//! - `requests_fts` — FTS5 index over path, summary, and body content

use lpm_tunnel::webhook::{CapturedWebhook, WebhookProvider};
use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{Mutex, mpsc};

/// Batch flush interval — writes are buffered and flushed together.
const FLUSH_INTERVAL_MS: u64 = 100;

/// Maximum number of buffered writes before forcing a flush.
const FLUSH_BATCH_SIZE: usize = 50;
const WRITE_QUEUE_CAPACITY: usize = 256;
const WRITE_QUEUE_BYTE_BUDGET: usize = 64 * 1024 * 1024;

/// Handle to the inspector database.
///
/// All writes go through a background task that batches inserts.
/// Reads happen directly on a separate connection (WAL mode allows this).
#[derive(Clone)]
pub struct InspectorDb {
    /// Read-only connection (shared across API handlers via Arc<Mutex>).
    read_conn: Arc<Mutex<Connection>>,
    /// Session lifecycle writes bypass the lossy capture queue.
    control_conn: Arc<std::sync::Mutex<Connection>>,
    /// Channel for sending writes to the background flush task.
    write_tx: mpsc::Sender<DbWrite>,
    queued_capture_bytes: Arc<AtomicUsize>,
    /// Database file path (for display/diagnostics).
    pub db_path: PathBuf,
}

/// A write operation to be batched.
enum DbWrite {
    InsertRequest {
        webhook: Arc<CapturedWebhook>,
        session_id: Option<String>,
        retained_bytes: usize,
    },
    Flush(tokio::sync::oneshot::Sender<Result<(), String>>),
}

impl InspectorDb {
    /// Open (or create) the inspector database at `{project_dir}/.lpm/inspector.db`.
    ///
    /// Initializes the schema if the database is new. Starts the background
    /// write-batching task.
    pub fn open(project_dir: &Path) -> Result<Self, rusqlite::Error> {
        let lpm_dir = project_dir.join(".lpm");
        let db_path = lpm_dir.join("inspector.db");
        prepare_lpm_dir(&lpm_dir).map_err(sqlite_io_error)?;
        let _opening = lock_capture_files(&db_path)?;
        if let Err(error) = ensure_captures_ignored(&lpm_dir) {
            tracing::warn!("could not keep tunnel captures out of git: {error}");
        }
        if prepare_capture_files(&db_path).map_err(sqlite_io_error)? {
            replace_with_owner_only_copy(&db_path)?;
        }

        // Write connection (owned by the background flush task)
        let write_conn = open_capture_connection(&db_path, "NORMAL")?;
        refuse_foreign_schema(&write_conn, &db_path)?;
        init_schema(&write_conn)?;

        // Read connection (shared across API handlers). The busy timeout
        // lets low-frequency mutations (tag updates, session renames) wait
        // while the write connection flushes a batch.
        let read_conn = open_capture_connection(&db_path, "NORMAL")?;
        let control_conn = open_control_connection(&db_path)?;

        let (write_tx, write_rx) = mpsc::channel(WRITE_QUEUE_CAPACITY);
        let queued_capture_bytes = Arc::new(AtomicUsize::new(0));

        // Spawn background flush task
        let write_conn = Arc::new(Mutex::new(write_conn));
        tokio::spawn(flush_task(
            write_conn,
            write_rx,
            Arc::clone(&queued_capture_bytes),
        ));

        Ok(Self {
            read_conn: Arc::new(Mutex::new(read_conn)),
            control_conn: Arc::new(std::sync::Mutex::new(control_conn)),
            write_tx,
            queued_capture_bytes,
            db_path,
        })
    }

    /// Open a temporary file-based database (for testing).
    ///
    /// Each call creates a unique database file so tests don't interfere
    /// with each other when running in parallel.
    pub fn open_temp() -> Result<Self, rusqlite::Error> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let tmp = std::env::temp_dir().join(format!(
            "lpm-inspect-test-{}-{nanos}-{id}.db",
            std::process::id()
        ));

        let write_conn = Connection::open(&tmp)?;
        configure_connection(&write_conn, "NORMAL")?;
        init_schema(&write_conn)?;

        let read_conn = Connection::open(&tmp)?;
        configure_connection(&read_conn, "NORMAL")?;
        let control_conn = open_control_connection(&tmp)?;

        let (write_tx, write_rx) = mpsc::channel(WRITE_QUEUE_CAPACITY);
        let queued_capture_bytes = Arc::new(AtomicUsize::new(0));
        let write_conn = Arc::new(Mutex::new(write_conn));
        tokio::spawn(flush_task(
            write_conn,
            write_rx,
            Arc::clone(&queued_capture_bytes),
        ));

        Ok(Self {
            read_conn: Arc::new(Mutex::new(read_conn)),
            control_conn: Arc::new(std::sync::Mutex::new(control_conn)),
            write_tx,
            queued_capture_bytes,
            db_path: tmp,
        })
    }

    /// Insert a captured request (non-blocking — queued for batch write).
    pub fn insert_request(&self, webhook: CapturedWebhook, session_id: Option<String>) {
        self.insert_shared_request(Arc::new(webhook), session_id);
    }

    pub(crate) fn insert_shared_request(
        &self,
        webhook: Arc<CapturedWebhook>,
        session_id: Option<String>,
    ) {
        if self.write_tx.capacity() == 0 {
            tracing::warn!("inspector database capture queue full; dropping capture");
            return;
        }
        let retained_bytes = webhook.retained_size_bytes();
        if self
            .queued_capture_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |queued| {
                queued
                    .checked_add(retained_bytes)
                    .filter(|next| *next <= WRITE_QUEUE_BYTE_BUDGET)
            })
            .is_err()
        {
            tracing::warn!("inspector database capture byte budget full; dropping capture");
            return;
        }
        if self
            .write_tx
            .try_send(DbWrite::InsertRequest {
                webhook,
                session_id,
                retained_bytes,
            })
            .is_err()
        {
            self.queued_capture_bytes
                .fetch_sub(retained_bytes, Ordering::Relaxed);
        }
    }

    pub(crate) async fn insert_durable_request(
        &self,
        webhook: Arc<CapturedWebhook>,
        session_id: Option<String>,
    ) -> Result<(), String> {
        let connection = Arc::clone(&self.control_conn);
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let transaction = connection
                .transaction()
                .map_err(|error| error.to_string())?;
            insert_request_row(&transaction, &webhook, session_id.as_deref())
                .map_err(|error| error.to_string())?;
            transaction.commit().map_err(|error| error.to_string())
        })
        .await
        .map_err(|error| format!("capture persistence task failed: {error}"))?
    }

    #[cfg(test)]
    fn queued_capture_bytes(&self) -> usize {
        self.queued_capture_bytes.load(Ordering::Relaxed)
    }

    /// Record a new tunnel session start.
    pub fn start_session(
        &self,
        id: String,
        domain: Option<String>,
        local_port: u16,
    ) -> Result<(), rusqlite::Error> {
        self.start_session_named(id, domain, local_port, None)
    }

    /// Record a new tunnel session start with an optional display name.
    pub fn start_session_named(
        &self,
        id: String,
        domain: Option<String>,
        local_port: u16,
        name: Option<String>,
    ) -> Result<(), rusqlite::Error> {
        let conn = self
            .control_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        conn.execute(
            "INSERT OR IGNORE INTO sessions (id, name, domain, local_port)
             VALUES (?1, ?2, ?3, ?4)",
            params![id, name, domain, local_port],
        )?;
        Ok(())
    }

    pub(crate) fn start_session_named_reversible(
        &self,
        id: String,
        domain: Option<String>,
        local_port: u16,
        name: Option<String>,
    ) -> Result<bool, rusqlite::Error> {
        let mut conn = self
            .control_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let transaction = conn.transaction()?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO sessions (id, name, domain, local_port)
             VALUES (?1, ?2, ?3, ?4)",
            params![&id, name, domain, local_port],
        )?;
        if inserted != 0 {
            transaction.execute(
                "INSERT INTO pending_sessions (session_id) VALUES (?1)",
                params![id],
            )?;
        }
        transaction.commit()?;
        Ok(inserted != 0)
    }

    pub(crate) fn rollback_session_start(&self, id: &str) -> Result<bool, rusqlite::Error> {
        let mut conn = self
            .control_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let transaction = conn.transaction()?;
        transaction.execute(
            "DELETE FROM pending_sessions WHERE session_id = ?1",
            params![id],
        )?;
        let deleted = transaction.execute(
            "DELETE FROM sessions
             WHERE id = ?1
               AND NOT EXISTS (SELECT 1 FROM requests WHERE session_id = ?1)",
            params![id],
        )?;
        if deleted == 0 {
            return Ok(false);
        }
        transaction.commit()?;
        Ok(true)
    }

    pub(crate) fn commit_session_start(&self, id: &str) -> Result<bool, rusqlite::Error> {
        let mut conn = self
            .control_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let transaction = conn.transaction()?;
        let committed = transaction.execute(
            "DELETE FROM pending_sessions WHERE session_id = ?1",
            params![id],
        )?;
        transaction.commit()?;
        Ok(committed != 0)
    }

    /// Record a tunnel session end.
    pub fn end_session(&self, id: String) -> Result<(), rusqlite::Error> {
        let mut conn = self
            .control_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let transaction = conn.transaction()?;
        transaction.execute(
            "UPDATE sessions SET ended_at = datetime('now') WHERE id = ?1",
            params![&id],
        )?;
        transaction.execute(
            "DELETE FROM pending_sessions WHERE session_id = ?1",
            params![id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Wait until all writes queued before this call have committed.
    pub async fn flush_pending_writes(&self) -> Result<(), String> {
        let (flushed_tx, flushed_rx) = tokio::sync::oneshot::channel();
        self.write_tx
            .send(DbWrite::Flush(flushed_tx))
            .await
            .map_err(|_| "inspector database writer stopped unexpectedly".to_string())?;
        tokio::time::timeout(std::time::Duration::from_secs(5), flushed_rx)
            .await
            .map_err(|_| "inspector database flush timed out".to_string())?
            .map_err(|_| {
                "inspector database writer stopped before committing queued captures".to_string()
            })?
    }

    /// Query recent requests, newest first.
    pub async fn list_requests(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredRequest>, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        let mut stmt = conn.prepare_cached(
            "SELECT id, session_id, timestamp, method, path, status, duration_ms,
                    provider, summary, req_size, res_size, signature_diagnostic IS NOT NULL as has_sig,
                    auto_acked
             FROM requests
             ORDER BY timestamp DESC, id DESC
             LIMIT ?1 OFFSET ?2",
        )?;

        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            Ok(StoredRequest {
                id: row.get(0)?,
                session_id: row.get(1)?,
                timestamp: row.get(2)?,
                method: row.get(3)?,
                path: row.get(4)?,
                status: row.get(5)?,
                duration_ms: row.get(6)?,
                provider: row.get(7)?,
                summary: row.get(8)?,
                req_size: row.get(9)?,
                res_size: row.get(10)?,
                has_signature_issue: row.get(11)?,
                auto_acked: row.get(12)?,
            })
        })?;

        rows.collect()
    }

    /// Get full detail for a single request by ID.
    pub async fn get_request(
        &self,
        id: &str,
    ) -> Result<Option<StoredRequestDetail>, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        let mut stmt = conn.prepare_cached(
            "SELECT id, session_id, timestamp, method, path, status, duration_ms,
                    provider, summary, signature_diagnostic,
                    request_headers, request_body, response_headers, response_body,
                    tags, auto_acked, req_size, res_size, response_body_incomplete
             FROM requests WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id], stored_detail_from_row);

        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get a full captured webhook by ID for detail views and replay.
    pub async fn get_webhook(&self, id: &str) -> Result<Option<CapturedWebhook>, rusqlite::Error> {
        self.get_request(id)
            .await?
            .map(stored_detail_to_webhook)
            .transpose()
    }

    /// Query full captured webhooks, newest first.
    pub async fn list_webhooks(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CapturedWebhook>, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        let mut stmt = conn.prepare_cached(
            "SELECT id, session_id, timestamp, method, path, status, duration_ms,
                    provider, summary, signature_diagnostic,
                    request_headers, request_body, response_headers, response_body,
                    tags, auto_acked, req_size, res_size, response_body_incomplete
             FROM requests
             ORDER BY timestamp DESC, id DESC
             LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], stored_detail_from_row)?;

        rows.map(|row| row.and_then(stored_detail_to_webhook))
            .collect()
    }

    /// Full-text search across request paths, summaries, and bodies.
    pub async fn search(
        &self,
        query: &str,
        provider: Option<&str>,
        status: Option<StatusQuery>,
        limit: usize,
    ) -> Result<Vec<StoredRequest>, rusqlite::Error> {
        let conn = self.read_conn.lock().await;

        // Build dynamic query based on filters
        let mut sql = String::from(
            "SELECT r.id, r.session_id, r.timestamp, r.method, r.path, r.status,
                    r.duration_ms, r.provider, r.summary, r.req_size, r.res_size,
                    r.signature_diagnostic IS NOT NULL, r.auto_acked
             FROM requests r",
        );

        let mut conditions: Vec<String> = Vec::new();

        if !query.is_empty() {
            sql.push_str(" JOIN requests_fts fts ON r.rowid = fts.rowid");
            conditions.push("requests_fts MATCH ?1".to_string());
        }

        if provider.is_some() {
            conditions.push("LOWER(r.provider) = LOWER(?2)".to_string());
        }

        match &status {
            Some(StatusQuery::Exact(code)) => {
                conditions.push(format!("r.status = {code}"));
            }
            Some(StatusQuery::Class(class)) => {
                let lo = class * 100;
                let hi = lo + 99;
                conditions.push(format!("r.status BETWEEN {lo} AND {hi}"));
            }
            Some(StatusQuery::Error) => {
                conditions.push("r.status >= 400".to_string());
            }
            None => {}
        }

        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }

        sql.push_str(" ORDER BY r.timestamp DESC, r.id DESC LIMIT ?3");

        let mut stmt = conn.prepare(&sql)?;

        // Bind parameters — FTS query and provider are optional
        let fts_query = if query.is_empty() {
            String::new()
        } else {
            // Escape FTS5 special characters and use prefix matching
            sanitize_fts_query(query)
        };

        let provider_str = provider.unwrap_or("");

        let rows = stmt.query_map(params![fts_query, provider_str, limit as i64], |row| {
            Ok(StoredRequest {
                id: row.get(0)?,
                session_id: row.get(1)?,
                timestamp: row.get(2)?,
                method: row.get(3)?,
                path: row.get(4)?,
                status: row.get(5)?,
                duration_ms: row.get(6)?,
                provider: row.get(7)?,
                summary: row.get(8)?,
                req_size: row.get(9)?,
                res_size: row.get(10)?,
                has_signature_issue: row.get(11)?,
                auto_acked: row.get(12)?,
            })
        })?;

        rows.collect()
    }

    /// Get total count of stored requests.
    pub async fn count(&self) -> Result<usize, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        conn.query_row("SELECT COUNT(*) FROM requests", [], |row| row.get(0))
    }

    /// List sessions, newest first.
    pub async fn list_sessions(&self, limit: usize) -> Result<Vec<StoredSession>, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        let mut stmt = conn.prepare_cached(
            "SELECT s.id, s.name, s.domain, s.local_port, s.started_at, s.ended_at,
                    (SELECT COUNT(*) FROM requests r WHERE r.session_id = s.id) as request_count
             FROM sessions s
             WHERE NOT EXISTS (
                 SELECT 1 FROM pending_sessions pending WHERE pending.session_id = s.id
             )
             ORDER BY s.started_at DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(StoredSession {
                id: row.get(0)?,
                name: row.get(1)?,
                domain: row.get(2)?,
                local_port: row.get(3)?,
                started_at: row.get(4)?,
                ended_at: row.get(5)?,
                request_count: row.get(6)?,
            })
        })?;

        rows.collect()
    }

    pub(crate) async fn get_stored_session_including_pending(
        &self,
        id: &str,
    ) -> Result<Option<StoredSession>, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        let session = conn.query_row(
            "SELECT s.id, s.name, s.domain, s.local_port, s.started_at, s.ended_at,
                    (SELECT COUNT(*) FROM requests r WHERE r.session_id = s.id)
             FROM sessions s
             WHERE s.id = ?1",
            params![id],
            |row| {
                Ok(StoredSession {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    domain: row.get(2)?,
                    local_port: row.get(3)?,
                    started_at: row.get(4)?,
                    ended_at: row.get(5)?,
                    request_count: row.get(6)?,
                })
            },
        );
        match session {
            Ok(session) => Ok(Some(session)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Rename a session.
    pub async fn rename_session(&self, id: &str, name: &str) -> Result<bool, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        let updated = conn.execute(
            "UPDATE sessions SET name = ?1 WHERE id = ?2",
            params![name, id],
        )?;
        Ok(updated > 0)
    }

    /// Get a single session with summary statistics.
    pub async fn get_session(&self, id: &str) -> Result<Option<SessionDetail>, rusqlite::Error> {
        self.get_session_with_pending(id, false).await
    }

    pub(crate) async fn get_session_including_pending(
        &self,
        id: &str,
    ) -> Result<Option<SessionDetail>, rusqlite::Error> {
        self.get_session_with_pending(id, true).await
    }

    async fn get_session_with_pending(
        &self,
        id: &str,
        include_pending: bool,
    ) -> Result<Option<SessionDetail>, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        let pending_filter = if include_pending {
            ""
        } else {
            "AND NOT EXISTS (SELECT 1 FROM pending_sessions pending WHERE pending.session_id = s.id)"
        };
        let query = format!(
            "SELECT s.id, s.name, s.domain, s.local_port, s.started_at, s.ended_at,
                    (SELECT COUNT(*) FROM requests r WHERE r.session_id = s.id),
                    (SELECT COUNT(*) FROM requests r WHERE r.session_id = s.id AND r.status >= 400),
                    (SELECT COUNT(DISTINCT r.provider) FROM requests r WHERE r.session_id = s.id AND r.provider IS NOT NULL)
             FROM sessions s WHERE s.id = ?1 {pending_filter}"
        );
        let session = conn.query_row(&query, params![id], |row| {
            Ok(SessionDetail {
                id: row.get(0)?,
                name: row.get(1)?,
                domain: row.get(2)?,
                local_port: row.get(3)?,
                started_at: row.get(4)?,
                ended_at: row.get(5)?,
                request_count: row.get(6)?,
                failure_count: row.get(7)?,
                provider_count: row.get(8)?,
            })
        });

        match session {
            Ok(s) => {
                // Compute duration from timestamps
                Ok(Some(s))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// List requests for a specific session, newest first.
    pub async fn list_session_requests(
        &self,
        session_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredRequest>, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        let mut stmt = conn.prepare_cached(
            "SELECT id, session_id, timestamp, method, path, status, duration_ms,
                    provider, summary, req_size, res_size, signature_diagnostic IS NOT NULL as has_sig,
                    auto_acked
             FROM requests
             WHERE session_id = ?1
             ORDER BY timestamp DESC, id DESC
             LIMIT ?2 OFFSET ?3",
        )?;

        let rows = stmt.query_map(params![session_id, limit as i64, offset as i64], |row| {
            Ok(StoredRequest {
                id: row.get(0)?,
                session_id: row.get(1)?,
                timestamp: row.get(2)?,
                method: row.get(3)?,
                path: row.get(4)?,
                status: row.get(5)?,
                duration_ms: row.get(6)?,
                provider: row.get(7)?,
                summary: row.get(8)?,
                req_size: row.get(9)?,
                res_size: row.get(10)?,
                has_signature_issue: row.get(11)?,
                auto_acked: row.get(12)?,
            })
        })?;

        rows.collect()
    }

    /// Update the tags for a request.
    pub async fn update_tags(&self, id: &str, tags: &[String]) -> Result<bool, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        let tags_json = crate::export::serialize_tags(tags);
        let updated = conn.execute(
            "UPDATE requests SET tags = ?1 WHERE id = ?2",
            params![tags_json, id],
        )?;
        Ok(updated > 0)
    }

    /// Delete requests older than `days` days and clean up FTS index.
    pub async fn cleanup(&self, days: i64) -> Result<usize, rusqlite::Error> {
        let conn = self.read_conn.lock().await;

        // Collect rowids to delete from FTS before removing from requests
        let cutoff = format!("-{days} days");
        let rowids: Vec<i64> = {
            let mut stmt =
                conn.prepare("SELECT rowid FROM requests WHERE created_at < datetime('now', ?1)")?;
            let rows = stmt.query_map(params![cutoff], |row| row.get(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        if rowids.is_empty() {
            return Ok(0);
        }

        // Delete FTS entries first (standalone table, standard DELETE works)
        for rowid in &rowids {
            conn.execute("DELETE FROM requests_fts WHERE rowid = ?1", params![rowid])?;
        }

        // Then delete from the requests table
        let deleted = conn.execute(
            "DELETE FROM requests WHERE created_at < datetime('now', ?1)",
            params![cutoff],
        )?;

        Ok(deleted)
    }

    /// Remove captured requests and completed sessions from the inspector database.
    ///
    /// Open sessions are retained so another process can continue attaching
    /// captures without violating the request-to-session foreign key.
    pub async fn clear_history(&self) -> Result<(), rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        // Immediate: a deferred transaction that reads before it writes gets
        // SQLITE_BUSY at once, without waiting, if another connection
        // commits in between.
        let tx =
            rusqlite::Transaction::new_unchecked(&conn, rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM requests_fts", [])?;
        tx.execute("DELETE FROM requests", [])?;
        tx.execute("DELETE FROM sessions WHERE ended_at IS NOT NULL", [])?;
        tx.commit()
    }

    /// Return SQLite's connection-local external-write revision.
    ///
    /// `data_version` changes when another connection commits, including
    /// request, session, and tag mutations. That makes it a better observer
    /// signal than a request-only row-count fingerprint.
    pub async fn revision(&self) -> Result<i64, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        conn.query_row("PRAGMA data_version", [], |row| row.get(0))
    }
}

/// The `.lpm/.gitignore` line that keeps the capture database and its
/// SQLite sidecars out of git, since captures hold request headers and
/// bodies.
const CAPTURES_IGNORE_LINE: &str = "inspector.db*";

/// How long a connection waits for another's lock, and how long opening
/// keeps retrying what SQLite refuses at once while another connection is
/// busy.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The suffixes of the files SQLite keeps beside the capture database.
const SQLITE_SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// The file beside the capture database whose name ends in `suffix`.
fn capture_file(db_path: &Path, suffix: &str) -> PathBuf {
    let mut name = db_path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// The capture database and the sidecar files SQLite keeps beside it.
fn capture_files(db_path: &Path) -> [PathBuf; 4] {
    [
        db_path.to_path_buf(),
        capture_file(db_path, SQLITE_SIDECARS[0]),
        capture_file(db_path, SQLITE_SIDECARS[1]),
        capture_file(db_path, SQLITE_SIDECARS[2]),
    ]
}

fn sqlite_io_error(error: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

fn with_path(path: &Path, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{}: {error}", path.display()))
}

fn linked_or_not(path: &Path, expected: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{} is a link or not a {expected}; tunnel captures, which hold request \
             headers and bodies, are kept only in the project's own files",
            path.display()
        ),
    )
}

#[cfg(unix)]
fn another_users(path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{} belongs to another user; tunnel captures, which hold request headers \
             and bodies, are kept only in your own files. Run the tunnel as its owner, \
             or make it yours",
            path.display()
        ),
    )
}

fn hard_linked(path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{} has other hard links, so captures written to it would change those \
             files too; move it aside and retry",
            path.display()
        ),
    )
}

/// Whether an entry is a link: a symbolic link, or on Windows a junction.
/// Other reparse points, such as a synced folder's cloud placeholders, are
/// the project's own files.
fn is_link(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

/// Makes sure `.lpm` is a directory of the project's own, creating it if
/// needed: a link, which a cloned repository could point anywhere, such as
/// into a directory it serves, is refused. On Unix it must also be the
/// user's own, and is made writable by no one else, so no other user can
/// swap the capture files' names between the checks below and SQLite's
/// opens.
fn prepare_lpm_dir(lpm_dir: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(lpm_dir) {
        Ok(metadata) if is_link(&metadata) || !metadata.is_dir() => {
            return Err(linked_or_not(lpm_dir, "directory"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(lpm_dir).map_err(|error| with_path(lpm_dir, error))?;
        }
        Err(error) => return Err(with_path(lpm_dir, error)),
    }
    restrict_lpm_dir(lpm_dir)
}

#[cfg(unix)]
fn restrict_lpm_dir(lpm_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory =
        lpm_common::open_nofollow(lpm_dir).map_err(|error| with_path(lpm_dir, error))?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() {
        return Err(linked_or_not(lpm_dir, "directory"));
    }
    if metadata.uid() != lpm_common::current_uid() {
        return Err(another_users(lpm_dir));
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        directory
            .set_permissions(std::fs::Permissions::from_mode(mode & !0o022))
            .map_err(|error| with_path(lpm_dir, error))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_lpm_dir(_lpm_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Holds other LPM processes off the capture files while this one checks,
/// replaces and opens them. A process that opened the database while it was
/// being replaced would go on writing to the old file.
fn lock_capture_files(
    db_path: &Path,
) -> Result<lpm_common::SingleFileExclusiveLockHandle, rusqlite::Error> {
    let lock_path = capture_file(db_path, "-lock");
    lpm_common::acquire_single_file_exclusive_lock_nofollow(&lock_path).map_err(|error| {
        sqlite_io_error(std::io::Error::other(format!(
            "{}: {error}",
            lock_path.display()
        )))
    })
}

/// Makes the capture files safe to write before SQLite opens them, and says
/// whether the database must be replaced, as others could open it or a
/// sidecar. No capture file may be a link, another user's, or have other
/// hard links. Existing ones are made owner-only, as a checkout or an older
/// release may have left them readable (see [`restrict_capture_file`]).
/// Sidecars without a database, which SQLite could read into a new one, are
/// removed, and a new database is created owner-only, so it's never
/// readable by others.
fn prepare_capture_files(db_path: &Path) -> std::io::Result<bool> {
    let mut open_to_others = false;
    let mut database_exists = false;
    for path in capture_files(db_path) {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if is_link(&metadata) || !metadata.is_file() => {
                return Err(linked_or_not(&path, "file"));
            }
            Ok(metadata) => {
                open_to_others |= restrict_capture_file(&path, &metadata)?;
                database_exists |= path == db_path;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(with_path(&path, error)),
        }
    }
    if database_exists {
        return Ok(open_to_others);
    }
    for suffix in SQLITE_SIDECARS {
        remove_if_present(&capture_file(db_path, suffix))?;
    }
    create_owner_only(db_path)?;
    Ok(false)
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(with_path(path, error)),
        _ => Ok(()),
    }
}

/// Checks an existing capture file and says whether others could open it.
/// One they couldn't is made owner-only. One they could keeps its mode,
/// made only the owner's to read and write as well, until the database is
/// replaced, so a replacement that can't run yet runs on a later open.
/// Modes are changed by name, which no other user can swap in a directory
/// only its owner can write, rather than through a handle, whose closing
/// would drop the locks SQLite holds on the file in this process, and which
/// a file without read permission can't have. A file that's gone needs
/// nothing: SQLite removes `-wal` and `-shm` when another process closes
/// its last connection.
#[cfg(unix)]
fn restrict_capture_file(path: &Path, metadata: &std::fs::Metadata) -> std::io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.uid() != lpm_common::current_uid() {
        return Err(another_users(path));
    }
    if metadata.nlink() > 1 {
        return Err(hard_linked(path));
    }
    let mode = metadata.mode() & 0o7777;
    let open_to_others = mode & 0o077 != 0;
    let wanted = if open_to_others { mode | 0o600 } else { 0o600 };
    if mode != wanted {
        match std::fs::set_permissions(path, std::fs::Permissions::from_mode(wanted)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(with_path(path, error)),
        }
    }
    Ok(open_to_others)
}

/// Refuses an existing capture file with other hard links, read through a
/// handle that doesn't follow a link. Access to it is the project's ACLs.
#[cfg(not(unix))]
fn restrict_capture_file(path: &Path, _metadata: &std::fs::Metadata) -> std::io::Result<bool> {
    let file = match lpm_common::open_nofollow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(with_path(path, error)),
    };
    if lpm_common::link_count(&file).map_err(|error| with_path(path, error))? > 1 {
        return Err(hard_linked(path));
    }
    Ok(false)
}

#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(with_path(path, error)),
    }
}

#[cfg(not(unix))]
fn create_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Replaces a capture database others could open with an owner-only copy.
/// Making the file owner-only stops new opens, but not a handle another user
/// opened while it was readable, which would go on reading every capture
/// written after; the copy is a new file such a handle doesn't reach. A
/// database another process has open isn't replaced, since that process
/// would go on writing to the old file.
fn replace_with_owner_only_copy(db_path: &Path) -> Result<(), rusqlite::Error> {
    let in_use = || {
        sqlite_io_error(std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            format!(
                "{} is open to other users, and another process has it open, so it \
                 can't be replaced with an owner-only copy yet; stop other `lpm tunnel` \
                 and `lpm dev` runs in this project and retry",
                db_path.display()
            ),
        ))
    };
    let database = open_nofollow_connection(db_path)?;
    // Leaving WAL needs the only connection, so it also proves no other
    // process has the database open, and folds the WAL into the file.
    match database.query_row("PRAGMA journal_mode=DELETE", [], |row| {
        row.get::<_, String>(0)
    }) {
        Ok(mode) if mode.eq_ignore_ascii_case("delete") => {}
        Ok(_) => return Err(in_use()),
        Err(error) if is_busy(&error) => return Err(in_use()),
        Err(error) => return Err(error),
    }

    let copy_path = capture_file(db_path, "-copy");
    for path in [&copy_path, &capture_file(&copy_path, "-journal")] {
        remove_if_present(path).map_err(sqlite_io_error)?;
    }
    create_owner_only(&copy_path).map_err(sqlite_io_error)?;
    {
        let mut copy = open_nofollow_connection(&copy_path)?;
        let backup = rusqlite::backup::Backup::new(&database, &mut copy)?;
        let deadline = std::time::Instant::now() + BUSY_TIMEOUT;
        loop {
            match backup.step(-1)? {
                rusqlite::backup::StepResult::Done => break,
                _ if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => return Err(in_use()),
            }
        }
    }
    drop(database);
    for suffix in SQLITE_SIDECARS {
        remove_if_present(&capture_file(db_path, suffix)).map_err(sqlite_io_error)?;
    }
    std::fs::rename(&copy_path, db_path).map_err(|error| sqlite_io_error(with_path(db_path, error)))
}

/// Opens a capture database without following a link at its path, with the
/// settings every capture connection has (see [`harden_connection`]).
fn open_nofollow_connection(path: &Path) -> Result<Connection, rusqlite::Error> {
    let connection = connect_nofollow(path)?;
    harden_connection(&connection)?;
    Ok(connection)
}

/// On Unix, SQLite's no-follow open refuses a link anywhere in the path, as
/// macOS's `/var` and `/tmp` are, so it gets the directory's real path,
/// which leaves only the database itself to refuse as a link. On Windows the
/// flag does nothing, and the path is opened as it is.
fn connect_nofollow(path: &Path) -> Result<Connection, rusqlite::Error> {
    #[cfg(unix)]
    let path = {
        let directory = match path.parent() {
            Some(directory) if !directory.as_os_str().is_empty() => directory,
            _ => Path::new("."),
        };
        std::fs::canonicalize(directory)
            .map_err(|error| sqlite_io_error(with_path(directory, error)))?
            .join(path.file_name().unwrap_or(path.as_os_str()))
    };
    Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::default() | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
}

/// What every capture connection has: a database from a repository or
/// another tool can't run schema code with side effects or write SQLite's
/// internal tables, and a busy database is waited for.
fn harden_connection(connection: &Connection) -> Result<(), rusqlite::Error> {
    use rusqlite::config::DbConfig;

    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.busy_timeout(BUSY_TIMEOUT)
}

/// Opens a capture connection in WAL, with `synchronous` as its sync level.
fn open_capture_connection(path: &Path, synchronous: &str) -> Result<Connection, rusqlite::Error> {
    let connection = connect_nofollow(path)?;
    configure_connection(&connection, synchronous)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection, synchronous: &str) -> Result<(), rusqlite::Error> {
    harden_connection(connection)?;
    use_wal(connection)?;
    connection.execute_batch(&format!(
        "PRAGMA synchronous={synchronous}; PRAGMA foreign_keys=ON;"
    ))
}

/// Switches the database to WAL. Connections switching a new database at
/// once can get SQLITE_BUSY without the busy timeout being waited, so the
/// switch is retried, a jittered few milliseconds apart, until it passes.
fn use_wal(connection: &Connection) -> Result<(), rusqlite::Error> {
    use rand::Rng as _;

    let deadline = std::time::Instant::now() + BUSY_TIMEOUT;
    loop {
        match connection.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(())) {
            Err(error) if is_busy(&error) && std::time::Instant::now() < deadline => {
                let pause = rand::thread_rng().gen_range(5..=25);
                std::thread::sleep(std::time::Duration::from_millis(pause));
            }
            result => return result,
        }
    }
}

fn is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

/// Refuses a database whose schema holds triggers or views, which LPM never
/// creates: one from a repository or another tool could run them on every
/// capture written.
fn refuse_foreign_schema(connection: &Connection, db_path: &Path) -> Result<(), rusqlite::Error> {
    let foreign: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type IN ('trigger', 'view'))",
        [],
        |row| row.get(0),
    )?;
    if foreign {
        return Err(sqlite_io_error(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} holds triggers or views, which LPM never creates; move it aside \
                 and retry",
                db_path.display()
            ),
        )));
    }
    Ok(())
}

/// A `.gitignore` line as git reads it: without one trailing carriage
/// return or trailing spaces that aren't escaped. Leading whitespace stays
/// part of the pattern, as it does for git.
fn git_pattern(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut end = line.len();
    while end > 0 && line[end - 1] == b' ' && !(end >= 2 && line[end - 2] == b'\\') {
        end -= 1;
    }
    &line[..end]
}

/// Whether these `.gitignore` lines leave the capture files ignored: a rule
/// covering them, unanchored or anchored to `.lpm/` (`inspector.db*`, or `*`
/// as a tool directory's ignore file has), after the last negation that
/// could match one. The lines are bytes, as git reads them.
fn ignores_captures(lines: &[u8]) -> bool {
    const COVERING: [&[u8]; 3] = [CAPTURES_IGNORE_LINE.as_bytes(), b"*", b"**"];
    let mut ignored = false;
    for line in lines.split(|byte| *byte == b'\n') {
        let pattern = git_pattern(line);
        let unanchored = pattern.strip_prefix(b"/").unwrap_or(pattern);
        if COVERING.contains(&unanchored) {
            ignored = true;
        } else if let Some(negated) = pattern.strip_prefix(b"!")
            && could_name_a_capture_file(negated)
        {
            ignored = false;
        }
    }
    ignored
}

/// Whether a negated pattern could match a capture file. Only one of plain
/// characters that doesn't hold `inspector.db` in any case can't: escapes,
/// wildcards and ranges can all spell a capture file's name, and a
/// repository on a case-insensitive disk matches it in any case.
fn could_name_a_capture_file(pattern: &[u8]) -> bool {
    const NAME: &[u8] = b"inspector.db";
    let plain = pattern
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'_' | b'-'));
    !plain
        || pattern
            .windows(NAME.len())
            .any(|window| window.eq_ignore_ascii_case(NAME))
}

/// Adds [`CAPTURES_IGNORE_LINE`] to `.lpm/.gitignore` unless the file
/// already ignores the capture files. An ignore file inside `.lpm/` holds
/// wherever the project sits in a repository, and leaves the project's own
/// `.gitignore` alone. One that git wouldn't read as a file of the
/// project's, being a link or not a regular file, or that its owner keeps
/// from being written, being read-only or on Unix another user's, is left
/// as it is; the CLI's capture warning then says git doesn't ignore the
/// captures.
fn ensure_captures_ignored(lpm_dir: &Path) -> std::io::Result<()> {
    let path = lpm_dir.join(".gitignore");
    let (existing, metadata) = match lpm_common::read_file_capped_unlinked(
        &path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok((bytes, metadata)) => (bytes, Some(metadata)),
        Err(lpm_common::BoundedReadError::NotFound { .. }) => (Vec::new(), None),
        Err(error) => return Err(std::io::Error::other(error)),
    };
    if ignores_captures(&existing) {
        return Ok(());
    }
    if let Some(metadata) = &metadata {
        refuse_kept_from_writing(&path, metadata)?;
    }
    let newline: &[u8] = if existing.windows(2).any(|pair| pair == b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    };
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with(b"\n") {
        updated.extend_from_slice(newline);
    }
    updated.extend_from_slice(b"# LPM tunnel captures hold request headers and bodies.");
    updated.extend_from_slice(newline);
    updated.extend_from_slice(CAPTURES_IGNORE_LINE.as_bytes());
    updated.extend_from_slice(newline);
    lpm_common::write_file_atomic(&path, updated)
}

fn refuse_kept_from_writing(path: &Path, metadata: &std::fs::Metadata) -> std::io::Result<()> {
    #[cfg(unix)]
    let read_only = {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != lpm_common::current_uid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{} belongs to another user", path.display()),
            ));
        }
        metadata.permissions().mode() & 0o200 == 0
    };
    #[cfg(not(unix))]
    let read_only = metadata.permissions().readonly();
    if read_only {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{} is read-only", path.display()),
        ));
    }
    Ok(())
}

// ── Schema initialization ─────────────────────────────────────────────

fn open_control_connection(path: &Path) -> Result<Connection, rusqlite::Error> {
    open_capture_connection(path, "FULL")
}

fn init_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sessions (
             id TEXT PRIMARY KEY,
             name TEXT,
             domain TEXT,
             local_port INTEGER,
             started_at TEXT NOT NULL DEFAULT (datetime('now')),
             ended_at TEXT
         );

         CREATE TABLE IF NOT EXISTS pending_sessions (
             session_id TEXT PRIMARY KEY,
             FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
         );

         CREATE TABLE IF NOT EXISTS requests (
             id TEXT PRIMARY KEY,
             session_id TEXT,
             timestamp TEXT NOT NULL,
             method TEXT NOT NULL,
             path TEXT NOT NULL,
             status INTEGER,
             duration_ms INTEGER,
             provider TEXT,
             summary TEXT,
             signature_diagnostic TEXT,
             request_headers TEXT,
             request_body BLOB,
             response_headers TEXT,
             response_body BLOB,
             req_size INTEGER,
             res_size INTEGER,
             tags TEXT,
             auto_acked INTEGER DEFAULT 0,
             created_at TEXT DEFAULT (datetime('now')),
             FOREIGN KEY (session_id) REFERENCES sessions(id)
         );

         CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_id);
         CREATE INDEX IF NOT EXISTS idx_requests_provider ON requests(provider);
         CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
         CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp DESC, id DESC);

         CREATE VIRTUAL TABLE IF NOT EXISTS requests_fts USING fts5(
             path, summary, request_body, response_body
         );",
    )?;
    ensure_capture_schema(conn)
}

fn ensure_capture_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let has_capture_flag = tx
        .prepare("PRAGMA table_info(requests)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|name| name == "response_body_incomplete");
    if !has_capture_flag {
        tx.execute(
            "ALTER TABLE requests ADD COLUMN response_body_incomplete INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    tx.commit()
}

// ── Background flush task ─────────────────────────────────────────────

async fn flush_task(
    conn: Arc<Mutex<Connection>>,
    mut rx: mpsc::Receiver<DbWrite>,
    queued_capture_bytes: Arc<AtomicUsize>,
) {
    let mut batch: Vec<DbWrite> = Vec::with_capacity(FLUSH_BATCH_SIZE);
    let mut pending_error: Option<String> = None;

    loop {
        // Wait for the first write or channel close
        match rx.recv().await {
            Some(write) => batch.push(write),
            None => break, // Channel closed — shutdown
        }

        // Drain any additional buffered writes (non-blocking)
        while batch.len() < FLUSH_BATCH_SIZE {
            match rx.try_recv() {
                Ok(write) => batch.push(write),
                Err(_) => break,
            }
        }

        // If we didn't hit batch size, wait briefly for more writes
        if batch.len() < FLUSH_BATCH_SIZE {
            tokio::time::sleep(std::time::Duration::from_millis(FLUSH_INTERVAL_MS)).await;
            while batch.len() < FLUSH_BATCH_SIZE {
                match rx.try_recv() {
                    Ok(write) => batch.push(write),
                    Err(_) => break,
                }
            }
        }

        flush_pending_batch(&conn, &mut batch, &mut pending_error, &queued_capture_bytes).await;
    }

    // Drain remaining writes on shutdown
    while let Ok(write) = rx.try_recv() {
        batch.push(write);
    }
    flush_pending_batch(&conn, &mut batch, &mut pending_error, &queued_capture_bytes).await;
}

async fn flush_pending_batch(
    conn: &Arc<Mutex<Connection>>,
    batch: &mut Vec<DbWrite>,
    pending_error: &mut Option<String>,
    queued_capture_bytes: &AtomicUsize,
) {
    if batch.is_empty() {
        return;
    }

    let current_result = {
        let conn = conn.lock().await;
        match flush_batch(&conn, batch) {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::warn!("inspector db flush error: {error}");
                Err(error.to_string())
            }
        }
    };
    if let Err(error) = current_result
        && pending_error.is_none()
    {
        *pending_error = Some(error);
    }

    let has_flush_marker = batch.iter().any(|write| matches!(write, DbWrite::Flush(_)));
    let reported_result = pending_error.clone().map_or(Ok(()), Err);
    finish_batch(batch, reported_result, queued_capture_bytes);
    if has_flush_marker {
        *pending_error = None;
    }
}

fn finish_batch(
    batch: &mut Vec<DbWrite>,
    flush_result: Result<(), String>,
    queued_capture_bytes: &AtomicUsize,
) {
    for write in batch.drain(..) {
        match write {
            DbWrite::InsertRequest { retained_bytes, .. } => {
                queued_capture_bytes.fetch_sub(retained_bytes, Ordering::Relaxed);
            }
            DbWrite::Flush(flushed_tx) => {
                let _ = flushed_tx.send(flush_result.clone());
            }
        }
    }
}

fn flush_batch(conn: &Connection, batch: &[DbWrite]) -> Result<(), rusqlite::Error> {
    let tx = conn.unchecked_transaction()?;

    for write in batch {
        match write {
            DbWrite::InsertRequest {
                webhook,
                session_id,
                ..
            } => {
                insert_request_row(&tx, webhook, session_id.as_deref())?;
            }
            DbWrite::Flush(_) => {}
        }
    }

    tx.commit()
}

fn insert_request_row(
    conn: &Connection,
    webhook: &CapturedWebhook,
    session_id: Option<&str>,
) -> Result<(), rusqlite::Error> {
    let headers_json = serde_json::to_string(&webhook.request_headers).unwrap_or_default();
    let resp_headers_json = serde_json::to_string(&webhook.response_headers).unwrap_or_default();

    // Extract text for FTS indexing (only index UTF-8 content)
    let req_body_text = std::str::from_utf8(&webhook.request_body)
        .unwrap_or("")
        .to_string();
    let res_body_text = std::str::from_utf8(&webhook.response_body)
        .unwrap_or("")
        .to_string();

    // Before INSERT OR REPLACE: if this ID already exists, delete its FTS entry.
    // INSERT OR REPLACE deletes the old row (and its rowid) then inserts a new one
    // with a new rowid, which would orphan the old FTS entry.
    let old_rowid: Option<i64> = conn
        .query_row(
            "SELECT rowid FROM requests WHERE id = ?1",
            params![webhook.id],
            |row| row.get(0),
        )
        .ok();
    if let Some(old) = old_rowid {
        conn.execute("DELETE FROM requests_fts WHERE rowid = ?1", params![old])?;
    }

    conn.execute(
        "INSERT OR REPLACE INTO requests
         (id, session_id, timestamp, method, path, status, duration_ms,
          provider, summary, signature_diagnostic,
          request_headers, request_body, response_headers, response_body,
          req_size, res_size, auto_acked, response_body_incomplete)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        params![
            webhook.id,
            session_id,
            webhook.timestamp,
            webhook.method,
            webhook.path,
            webhook.response_status,
            webhook.duration_ms,
            webhook.provider.map(|p| p.to_string()),
            webhook.summary,
            webhook.signature_diagnostic,
            headers_json,
            webhook.request_body,
            resp_headers_json,
            webhook.response_body,
            webhook.request_body.len(),
            webhook.response_body.len(),
            webhook.auto_acked,
            webhook.response_body_incomplete,
        ],
    )?;

    // Get the new rowid and insert into FTS
    let new_rowid: i64 = conn.query_row(
        "SELECT rowid FROM requests WHERE id = ?1",
        params![webhook.id],
        |row| row.get(0),
    )?;
    conn.execute(
        "INSERT INTO requests_fts (rowid, path, summary, request_body, response_body)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            new_rowid,
            webhook.path,
            webhook.summary,
            req_body_text,
            res_body_text
        ],
    )?;

    Ok(())
}

/// Sanitize a user query for FTS5 to prevent syntax errors.
///
/// FTS5 has special operators (AND, OR, NOT, NEAR, quotes, etc.).
/// We wrap each token in double quotes to treat them as literal strings.
fn sanitize_fts_query(query: &str) -> String {
    query
        .split_whitespace()
        .map(|token| {
            // Escape double quotes within tokens
            let escaped = token.replace('"', "\"\"");
            format!("\"{escaped}\"")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Query types ───────────────────────────────────────────────────────

/// Status filter for search queries.
pub enum StatusQuery {
    /// Exact status code (e.g., 404).
    Exact(u16),
    /// Status class: 2 = 2xx, 4 = 4xx, 5 = 5xx.
    Class(u16),
    /// All errors (>= 400).
    Error,
}

/// Compact request row (no bodies) for list views.
#[derive(Debug)]
pub struct StoredRequest {
    pub id: String,
    pub session_id: Option<String>,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub provider: Option<String>,
    pub summary: String,
    pub req_size: usize,
    pub res_size: usize,
    pub has_signature_issue: bool,
    pub auto_acked: bool,
}

/// Full request detail including headers and bodies.
#[derive(Debug)]
pub struct StoredRequestDetail {
    pub id: String,
    pub session_id: Option<String>,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub provider: Option<String>,
    pub summary: String,
    pub signature_diagnostic: Option<String>,
    pub request_headers: String,
    pub request_body: Vec<u8>,
    pub response_headers: String,
    pub response_body: Vec<u8>,
    pub tags: Option<String>,
    pub auto_acked: bool,
    pub req_size: usize,
    pub res_size: usize,
    pub response_body_incomplete: bool,
}

fn stored_detail_from_row(row: &rusqlite::Row<'_>) -> Result<StoredRequestDetail, rusqlite::Error> {
    Ok(StoredRequestDetail {
        id: row.get(0)?,
        session_id: row.get(1)?,
        timestamp: row.get(2)?,
        method: row.get(3)?,
        path: row.get(4)?,
        status: row.get(5)?,
        duration_ms: row.get(6)?,
        provider: row.get(7)?,
        summary: row.get(8)?,
        signature_diagnostic: row.get(9)?,
        request_headers: row.get(10)?,
        request_body: row.get(11)?,
        response_headers: row.get(12)?,
        response_body: row.get(13)?,
        tags: row.get(14)?,
        auto_acked: row.get(15)?,
        response_body_incomplete: row.get(18)?,
        req_size: row.get(16)?,
        res_size: row.get(17)?,
    })
}

fn stored_detail_to_webhook(
    stored: StoredRequestDetail,
) -> Result<CapturedWebhook, rusqlite::Error> {
    if stored.request_body.len() != stored.req_size || stored.response_body.len() != stored.res_size
    {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            11,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "capture body was truncated by an older LPM CLI and cannot be replayed faithfully",
            )),
        ));
    }

    let request_headers: HashMap<String, String> = serde_json::from_str(&stored.request_headers)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    let response_headers: HashMap<String, String> = serde_json::from_str(&stored.response_headers)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                12,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    let provider = stored
        .provider
        .as_deref()
        .map(parse_stored_provider)
        .transpose()?;

    Ok(CapturedWebhook {
        id: stored.id,
        timestamp: stored.timestamp,
        method: stored.method,
        path: stored.path,
        request_headers,
        request_body: stored.request_body,
        response_status: stored.status,
        response_headers,
        response_body: stored.response_body,
        duration_ms: stored.duration_ms,
        provider,
        summary: stored.summary,
        signature_diagnostic: stored.signature_diagnostic,
        auto_acked: stored.auto_acked,
        response_body_incomplete: stored.response_body_incomplete,
    })
}

fn parse_stored_provider(provider: &str) -> Result<WebhookProvider, rusqlite::Error> {
    match provider.to_ascii_lowercase().as_str() {
        "stripe" => Ok(WebhookProvider::Stripe),
        "github" => Ok(WebhookProvider::GitHub),
        "clerk" => Ok(WebhookProvider::Clerk),
        "resend" => Ok(WebhookProvider::Resend),
        "sendgrid" => Ok(WebhookProvider::SendGrid),
        "twilio" => Ok(WebhookProvider::Twilio),
        "svix" => Ok(WebhookProvider::Svix),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown stored webhook provider `{provider}`"),
            )),
        )),
    }
}

/// Session metadata.
#[derive(Debug)]
pub struct StoredSession {
    pub id: String,
    pub name: Option<String>,
    pub domain: Option<String>,
    pub local_port: u16,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub request_count: usize,
}

/// Session detail with summary statistics.
#[derive(Debug)]
pub struct SessionDetail {
    pub id: String,
    pub name: Option<String>,
    pub domain: Option<String>,
    pub local_port: u16,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub request_count: usize,
    pub failure_count: usize,
    pub provider_count: usize,
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_tunnel::webhook::WebhookProvider;
    use std::collections::HashMap;

    const CAPTURES_IGNORED: &str =
        "# LPM tunnel captures hold request headers and bodies.\ninspector.db*\n";

    fn lpm_gitignore(project: &Path) -> String {
        std::fs::read_to_string(project.join(".lpm/.gitignore")).unwrap()
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A file of root's, for checks of files that belong to another user;
    /// None when the tests run as root.
    #[cfg(unix)]
    fn another_users_file() -> Option<(PathBuf, std::fs::Metadata)> {
        if lpm_common::current_uid() == 0 {
            return None;
        }
        let path = PathBuf::from("/etc/hosts");
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        Some((path, metadata))
    }

    #[tokio::test]
    async fn opening_keeps_captures_out_of_git_once() {
        let project = tempfile::tempdir().unwrap();

        drop(InspectorDb::open(project.path()).unwrap());
        drop(InspectorDb::open(project.path()).unwrap());

        assert_eq!(lpm_gitignore(project.path()), CAPTURES_IGNORED);
    }

    #[tokio::test]
    async fn opening_adds_the_capture_rule_to_an_lpm_gitignore_of_the_project() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        std::fs::write(project.path().join(".lpm/.gitignore"), "skills/").unwrap();

        drop(InspectorDb::open(project.path()).unwrap());

        assert_eq!(
            lpm_gitignore(project.path()),
            format!("skills/\n{CAPTURES_IGNORED}")
        );
    }

    fn opened_with_gitignore(content: &[u8]) -> (tempfile::TempDir, Vec<u8>) {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        std::fs::write(project.path().join(".lpm/.gitignore"), content).unwrap();
        drop(InspectorDb::open(project.path()).unwrap());
        let written = std::fs::read(project.path().join(".lpm/.gitignore")).unwrap();
        (project, written)
    }

    #[tokio::test]
    async fn opening_leaves_an_lpm_gitignore_git_reads_as_ignoring_captures() {
        for content in [
            "inspector.db*\n",
            "inspector.db*  \n",
            "inspector.db*\r\n",
            "/inspector.db*\n",
            "!inspector.db\ninspector.db*\n",
            "*\n!.gitignore\n",
            "*\n!skills/\n!/added-sources.json\n!Skills_2-x\n",
            "/*\n",
            "**\n",
        ] {
            let (_project, written) = opened_with_gitignore(content.as_bytes());
            assert_eq!(written, content.as_bytes(), "{content:?}");
        }
    }

    #[tokio::test]
    async fn opening_adds_the_rule_where_git_wouldnt_read_one() {
        for content in [
            "  inspector.db*\n",
            "\tinspector.db*\n",
            "inspector.db*\t\n",
            "inspector.db*\\ \n",
            "inspector.db*\n!inspector.db\n",
            "inspector.db*\n!*\n",
            "inspector.db*\n!*.db\n",
            "inspector.db*\n!inspector*\n",
            "inspector.db*\n!**\n",
            "inspector.db*\n!inspector.d?\n",
            "inspector.db*\n!inspector.d[b]\n",
            "inspector.db*\n!inspector.d\\b\n",
            "inspector.db*\n!inspector\\.db\n",
            "inspector.db*\n!/inspector.d\\b\n",
            "inspector.db*\n!inspecto\\r.db-wal\n",
            "inspector.db*\n!Inspector.db\n",
            "inspector.db*\n!INSPECTOR.DB-WAL\n",
            "**\n!INSPECTOR.DB\n",
            "*\n!.lpm/inspector.db\n",
            "inspector.db\n",
        ] {
            let (_project, written) = opened_with_gitignore(content.as_bytes());
            assert_eq!(
                written,
                format!("{content}{CAPTURES_IGNORED}").as_bytes(),
                "{content:?}"
            );
        }
    }

    #[tokio::test]
    async fn opening_adds_the_rule_to_an_lpm_gitignore_that_isnt_utf8() {
        let content = b"skills/\n\xff\xfe-notes\n";

        let (_project, written) = opened_with_gitignore(content);

        let mut expected = content.to_vec();
        expected.extend_from_slice(CAPTURES_IGNORED.as_bytes());
        assert_eq!(written, expected);
    }

    #[tokio::test]
    async fn opening_reads_a_rule_beside_lines_that_arent_utf8() {
        let content = b"\xff\xfe\ninspector.db*\n";

        let (_project, written) = opened_with_gitignore(content);

        assert_eq!(written, content);
    }

    #[tokio::test]
    async fn opening_adds_the_rule_after_one_with_two_carriage_returns_which_git_reads_as_another()
    {
        let (_project, written) = opened_with_gitignore(b"inspector.db*\r\r\n");

        assert_eq!(
            written,
            b"inspector.db*\r\r\n# LPM tunnel captures hold request headers and bodies.\r\ninspector.db*\r\n"
        );
    }

    #[tokio::test]
    async fn opening_reads_a_negation_ending_in_a_carriage_return_as_git_does() {
        let (_project, written) = opened_with_gitignore(b"inspector.db*\r\n!Inspector.DB\r\n");

        assert_eq!(
            written,
            b"inspector.db*\r\n!Inspector.DB\r\n# LPM tunnel captures hold request headers and bodies.\r\ninspector.db*\r\n"
        );
    }

    #[tokio::test]
    async fn opening_adds_the_rule_with_the_file_s_line_endings() {
        let (_project, written) = opened_with_gitignore(b"skills/\r\n");

        assert_eq!(
            written,
            b"skills/\r\n# LPM tunnel captures hold request headers and bodies.\r\ninspector.db*\r\n"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn opening_leaves_a_read_only_lpm_gitignore_alone_even_empty() {
        for content in ["skills/\n", ""] {
            let project = tempfile::tempdir().unwrap();
            std::fs::create_dir(project.path().join(".lpm")).unwrap();
            let path = project.path().join(".lpm/.gitignore");
            std::fs::write(&path, content).unwrap();
            set_mode(&path, 0o444);

            drop(InspectorDb::open(project.path()).unwrap());

            assert_eq!(lpm_gitignore(project.path()), content, "{content:?}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn opening_leaves_an_lpm_gitignore_its_owner_cant_write_alone() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let path = project.path().join(".lpm/.gitignore");
        std::fs::write(&path, "skills/\n").unwrap();
        set_mode(&path, 0o464);

        drop(InspectorDb::open(project.path()).unwrap());

        assert_eq!(lpm_gitignore(project.path()), "skills/\n");
    }

    #[cfg(unix)]
    #[test]
    fn leaves_another_user_s_lpm_gitignore_alone() {
        let Some((path, metadata)) = another_users_file() else {
            return;
        };

        let error = refuse_kept_from_writing(&path, &metadata).unwrap_err();

        assert!(
            error.to_string().contains("belongs to another user"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn opening_leaves_an_lpm_gitignore_that_isnt_a_regular_file_alone() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".lpm/.gitignore")).unwrap();

        drop(InspectorDb::open(project.path()).unwrap());

        assert!(project.path().join(".lpm/.gitignore").is_dir());
    }

    #[tokio::test]
    async fn opening_writes_the_rule_before_it_creates_the_database() {
        let project = tempfile::tempdir().unwrap();
        // A database path that can't be a file makes the open fail right
        // after the rule is written, and before any database exists.
        std::fs::create_dir_all(project.path().join(".lpm/inspector.db")).unwrap();

        assert!(InspectorDb::open(project.path()).is_err());

        assert_eq!(lpm_gitignore(project.path()), CAPTURES_IGNORED);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn opening_makes_an_lpm_directory_others_could_write_theirs_alone() {
        let project = tempfile::tempdir().unwrap();
        let lpm_dir = project.path().join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        set_mode(&lpm_dir, 0o777);

        drop(InspectorDb::open(project.path()).unwrap());

        assert_eq!(mode(&lpm_dir), 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_another_user_s_lpm_directory() {
        if lpm_common::current_uid() == 0 {
            return;
        }

        let error = restrict_lpm_dir(Path::new("/usr")).unwrap_err();

        assert!(
            error.to_string().contains("belongs to another user"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_another_user_s_capture_file() {
        let Some((path, metadata)) = another_users_file() else {
            return;
        };

        let error = restrict_capture_file(&path, &metadata).unwrap_err();

        assert!(
            error.to_string().contains("belongs to another user"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restricting_a_capture_file_that_vanished_needs_nothing() {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().join("inspector.db-wal");
        std::fs::write(&path, b"").unwrap();
        set_mode(&path, 0o400);
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert!(!restrict_capture_file(&path, &metadata).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn preparing_refuses_a_capture_file_with_other_hard_links() {
        let project = tempfile::tempdir().unwrap();
        let lpm_dir = project.path().join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        let served = project.path().join("public.txt");
        std::fs::write(&served, b"").unwrap();
        set_mode(&served, 0o644);
        std::fs::hard_link(&served, lpm_dir.join("inspector.db")).unwrap();

        let error = prepare_capture_files(&lpm_dir.join("inspector.db")).unwrap_err();

        assert!(error.to_string().contains("other hard links"), "{error}");
        assert_eq!(mode(&served), 0o644);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn opening_refuses_a_linked_lpm_directory_or_capture_file() {
        let outside = tempfile::tempdir().unwrap();
        let linked_dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), linked_dir.path().join(".lpm")).unwrap();
        assert!(InspectorDb::open(linked_dir.path()).is_err());
        assert!(!outside.path().join("inspector.db").exists());

        for name in ["inspector.db", "inspector.db-wal"] {
            let project = tempfile::tempdir().unwrap();
            std::fs::create_dir(project.path().join(".lpm")).unwrap();
            let target = outside.path().join(format!("{name}-target"));
            std::fs::write(&target, "outside\n").unwrap();
            set_mode(&target, 0o644);
            std::os::unix::fs::symlink(&target, project.path().join(".lpm").join(name)).unwrap();

            assert!(InspectorDb::open(project.path()).is_err(), "{name}");
            assert_eq!(
                std::fs::read_to_string(&target).unwrap(),
                "outside\n",
                "{name}"
            );
            assert_eq!(mode(&target), 0o644, "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn preparing_makes_leftover_capture_files_others_couldnt_open_owner_only() {
        let project = tempfile::tempdir().unwrap();
        let lpm_dir = project.path().join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        for (name, leftover_mode) in [
            ("inspector.db", 0o000),
            ("inspector.db-wal", 0o400),
            ("inspector.db-shm", 0o700),
            ("inspector.db-journal", 0o600),
        ] {
            let path = lpm_dir.join(name);
            std::fs::write(&path, b"").unwrap();
            set_mode(&path, leftover_mode);
        }

        assert!(!prepare_capture_files(&lpm_dir.join("inspector.db")).unwrap());

        for name in [
            "inspector.db",
            "inspector.db-wal",
            "inspector.db-shm",
            "inspector.db-journal",
        ] {
            assert_eq!(mode(&lpm_dir.join(name)), 0o600, "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn preparing_keeps_a_leftover_others_could_open_for_the_database_s_replacement() {
        let project = tempfile::tempdir().unwrap();
        let lpm_dir = project.path().join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        for (name, leftover_mode) in [("inspector.db", 0o600), ("inspector.db-wal", 0o204)] {
            let path = lpm_dir.join(name);
            std::fs::write(&path, b"").unwrap();
            set_mode(&path, leftover_mode);
        }

        assert!(prepare_capture_files(&lpm_dir.join("inspector.db")).unwrap());

        assert_eq!(mode(&lpm_dir.join("inspector.db-wal")), 0o604);
    }

    #[cfg(unix)]
    #[test]
    fn preparing_removes_sidecars_left_without_a_database() {
        let project = tempfile::tempdir().unwrap();
        let lpm_dir = project.path().join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        for name in [
            "inspector.db-wal",
            "inspector.db-shm",
            "inspector.db-journal",
        ] {
            let path = lpm_dir.join(name);
            std::fs::write(&path, b"leftover").unwrap();
            set_mode(&path, 0o644);
        }

        assert!(!prepare_capture_files(&lpm_dir.join("inspector.db")).unwrap());

        for name in [
            "inspector.db-wal",
            "inspector.db-shm",
            "inspector.db-journal",
        ] {
            assert!(!lpm_dir.join(name).exists(), "{name}");
        }
        assert_eq!(mode(&lpm_dir.join("inspector.db")), 0o600);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn opening_keeps_capture_files_owner_only() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let wal = project.path().join(".lpm/inspector.db-wal");
        std::fs::write(&wal, b"").unwrap();
        set_mode(&wal, 0o644);

        drop(InspectorDb::open(project.path()).unwrap());

        for name in ["inspector.db", "inspector.db-wal"] {
            assert_eq!(
                mode(&project.path().join(".lpm").join(name)),
                0o600,
                "{name}"
            );
        }
    }

    /// A project whose capture database holds one capture, with no
    /// connection left open.
    #[cfg(unix)]
    fn project_with_a_capture() -> tempfile::TempDir {
        let project = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = InspectorDb::open(project.path()).unwrap();
            db.insert_durable_request(Arc::new(make_webhook("kept", 200)), None)
                .await
                .unwrap();
        });
        // Dropping the runtime drops the flush task and its connection.
        drop(runtime);
        project
    }

    #[cfg(unix)]
    #[test]
    fn opening_replaces_a_database_others_could_open_with_an_owner_only_copy() {
        use std::os::unix::fs::MetadataExt;

        let project = project_with_a_capture();
        let db_path = project.path().join(".lpm/inspector.db");
        set_mode(&db_path, 0o644);
        // A handle another user could have opened while the file was
        // readable.
        let earlier_handle = std::fs::File::open(&db_path).unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let kept = runtime.block_on(async {
            let db = InspectorDb::open(project.path()).unwrap();
            db.get_webhook("kept").await.unwrap()
        });

        assert!(kept.is_some());
        assert_eq!(mode(&db_path), 0o600);
        let replaced = earlier_handle.metadata().unwrap();
        assert_eq!(replaced.nlink(), 0);
        assert_ne!(replaced.ino(), std::fs::metadata(&db_path).unwrap().ino());
        assert!(!project.path().join(".lpm/inspector.db-copy").exists());
    }

    #[cfg(unix)]
    #[test]
    fn opening_waits_to_replace_a_database_another_process_has_open() {
        let project = project_with_a_capture();
        let db_path = project.path().join(".lpm/inspector.db");
        set_mode(&db_path, 0o644);
        let other = Connection::open(&db_path).unwrap();
        other
            .query_row("SELECT count(*) FROM requests", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let started = std::time::Instant::now();

        let error = runtime
            .block_on(async { InspectorDb::open(project.path()).map(drop) })
            .unwrap_err();

        assert!(
            error.to_string().contains("another process has it open"),
            "{error}"
        );
        // Leaving WAL tells at once; the copy's own wait is the busy timeout.
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        assert_eq!(mode(&db_path), 0o644);
        drop(other);
        runtime.block_on(async { drop(InspectorDb::open(project.path()).unwrap()) });
        assert_eq!(mode(&db_path), 0o600);
    }

    #[tokio::test]
    async fn opening_refuses_a_database_with_triggers_or_views() {
        for statement in [
            "CREATE TRIGGER copy_requests AFTER INSERT ON requests BEGIN SELECT 1; END;",
            "CREATE VIEW recent AS SELECT * FROM requests;",
        ] {
            let project = tempfile::tempdir().unwrap();
            std::fs::create_dir(project.path().join(".lpm")).unwrap();
            let db_path = project.path().join(".lpm/inspector.db");
            Connection::open(&db_path)
                .unwrap()
                .execute_batch(&format!("CREATE TABLE requests (id TEXT); {statement}"))
                .unwrap();
            #[cfg(unix)]
            set_mode(&db_path, 0o600);

            let error = InspectorDb::open(project.path()).map(drop).unwrap_err();

            assert!(error.to_string().contains("triggers or views"), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn capture_connections_refuse_a_linked_database() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("elsewhere.db");
        Connection::open(&target)
            .unwrap()
            .execute_batch("CREATE TABLE t (x);")
            .unwrap();
        let link = directory.path().join("inspector.db");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(open_nofollow_connection(&link).is_err());
    }

    #[test]
    fn capture_connections_trust_no_schema_code() {
        let directory = tempfile::tempdir().unwrap();

        let connection =
            open_capture_connection(&directory.path().join("inspector.db"), "NORMAL").unwrap();

        let trusted: i64 = connection
            .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
            .unwrap();
        assert_eq!(trusted, 0);
        assert!(
            connection
                .db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
                .unwrap()
        );
    }

    #[test]
    fn switching_to_wal_waits_out_a_connection_that_refuses_it_at_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inspector.db");
        let holder = Connection::open(&path).unwrap();
        holder
            .execute_batch("CREATE TABLE t (x); BEGIN; SELECT * FROM t;")
            .unwrap();
        let switcher = Connection::open(&path).unwrap();
        switcher.busy_timeout(std::time::Duration::ZERO).unwrap();
        let released = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            holder.execute_batch("COMMIT").unwrap();
            holder
        });

        use_wal(&switcher).unwrap();

        let mode: String = switcher
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        drop(released.join().unwrap());
    }

    #[test]
    fn switching_to_wal_gives_up_at_once_on_anything_but_a_busy_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inspector.db");
        std::fs::write(&path, vec![b'x'; 4096]).unwrap();
        let connection = Connection::open(&path).unwrap();
        let started = std::time::Instant::now();

        assert!(use_wal(&connection).is_err());

        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn opening_a_new_database_from_several_processes_at_once_succeeds() {
        for _ in 0..10 {
            let project = tempfile::tempdir().unwrap();
            let openers: Vec<_> = (0..8)
                .map(|_| {
                    let path = project.path().to_path_buf();
                    tokio::task::spawn_blocking(move || InspectorDb::open(&path).map(drop))
                })
                .collect();
            for opener in openers {
                opener.await.unwrap().unwrap();
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn opening_waits_for_another_lpm_process_opening_the_captures() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let lock = lpm_common::acquire_single_file_exclusive_lock_nofollow(
            project.path().join(".lpm/inspector.db-lock"),
        )
        .unwrap();
        let path = project.path().to_path_buf();
        let opener = tokio::task::spawn_blocking(move || {
            InspectorDb::open(&path).map(drop)?;
            Ok::<_, rusqlite::Error>(std::time::Instant::now())
        });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let released = std::time::Instant::now();
        drop(lock);
        let opened = opener.await.unwrap().unwrap();

        assert!(opened >= released, "opened before the lock was released");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clearing_history_from_two_processes_at_once_succeeds() {
        let project = tempfile::tempdir().unwrap();
        let first = InspectorDb::open(project.path()).unwrap();
        let second = InspectorDb::open(project.path()).unwrap();
        for round in 0..200 {
            first
                .insert_durable_request(Arc::new(make_webhook(&format!("r{round}"), 200)), None)
                .await
                .unwrap();
            let (first_clear, second_clear) = (first.clone(), second.clone());
            let (one, two) = tokio::join!(
                tokio::spawn(async move { first_clear.clear_history().await }),
                tokio::spawn(async move { second_clear.clear_history().await }),
            );
            one.unwrap().unwrap();
            two.unwrap().unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn opening_leaves_a_linked_lpm_gitignore_and_its_target_alone() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("profile");
        std::fs::write(&target, "export PATH\n").unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let link = project.path().join(".lpm/.gitignore");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        drop(InspectorDb::open(project.path()).unwrap());

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "export PATH\n");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn capture_schema_upgrade_serializes_concurrent_openers() {
        std::thread_local! {
            static WAITING: std::cell::RefCell<Option<std::sync::mpsc::SyncSender<()>>> = const { std::cell::RefCell::new(None) };
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inspector.db");
        let mut first = Connection::open(&path).unwrap();
        first.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE requests (id TEXT PRIMARY KEY); INSERT INTO requests VALUES ('retained');").unwrap();
        let writer = first
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let (waiting_tx, waiting_rx) = std::sync::mpsc::sync_channel(1);
        let second = std::thread::spawn(move || {
            WAITING.with(|waiting| *waiting.borrow_mut() = Some(waiting_tx));
            let conn = Connection::open(path).unwrap();
            conn.busy_handler(Some(|attempt| {
                WAITING.with(|waiting| {
                    if let Some(sender) = waiting.borrow_mut().take() {
                        sender.send(()).unwrap();
                    }
                });
                std::thread::sleep(std::time::Duration::from_millis(10));
                attempt < 200
            }))
            .unwrap();
            ensure_capture_schema(&conn)
        });
        waiting_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        writer.execute("ALTER TABLE requests ADD COLUMN response_body_incomplete INTEGER NOT NULL DEFAULT 0", []).unwrap();
        writer.commit().unwrap();
        second.join().unwrap().unwrap();
        ensure_capture_schema(&first).unwrap();
        let retained: (String, bool) = first
            .query_row(
                "SELECT id, response_body_incomplete FROM requests",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(retained, ("retained".into(), false));
    }

    pub(super) fn make_webhook(id: &str, status: u16) -> CapturedWebhook {
        CapturedWebhook {
            id: id.to_string(),
            timestamp: "2026-04-06T12:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/api/webhook".to_string(),
            request_headers: HashMap::from([(
                "content-type".to_string(),
                "application/json".to_string(),
            )]),
            request_body: br#"{"type":"charge.succeeded","amount":2000}"#.to_vec(),
            response_status: status,
            response_headers: HashMap::new(),
            response_body: br#"{"ok":true}"#.to_vec(),
            duration_ms: 42,
            provider: Some(WebhookProvider::Stripe),
            summary: "Stripe: charge.succeeded".to_string(),
            signature_diagnostic: None,
            auto_acked: false,
            response_body_incomplete: false,
        }
    }

    #[tokio::test]
    async fn insert_and_list() {
        let db = InspectorDb::open_temp().unwrap();
        db.insert_request(make_webhook("w1", 200), None);
        db.insert_request(make_webhook("w2", 500), None);
        db.flush_pending_writes().await.unwrap();

        let requests = db.list_requests(10, 0).await.unwrap();
        assert_eq!(requests.len(), 2);
        // Newest first
        assert_eq!(requests[0].id, "w2");
        assert_eq!(requests[1].id, "w1");
    }

    #[tokio::test]
    async fn get_request_detail() {
        let db = InspectorDb::open_temp().unwrap();
        db.insert_request(make_webhook("w1", 200), None);
        db.flush_pending_writes().await.unwrap();

        let detail = db.get_request("w1").await.unwrap().unwrap();
        assert_eq!(detail.id, "w1");
        assert_eq!(detail.status, 200);
        assert!(!detail.request_body.is_empty());

        let not_found = db.get_request("nonexistent").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn full_text_search() {
        let db = InspectorDb::open_temp().unwrap();
        db.insert_request(make_webhook("w1", 200), None);

        let mut w2 = make_webhook("w2", 500);
        w2.request_body =
            br#"{"type":"payment_intent.failed","error":"insufficient_funds"}"#.to_vec();
        w2.summary = "Stripe: payment_intent.failed".to_string();
        db.insert_request(w2, None);
        db.flush_pending_writes().await.unwrap();

        // Search for "insufficient_funds"
        let results = db
            .search("insufficient_funds", None, None, 10)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "w2");

        // Search for "charge" should find w1
        let results = db.search("charge", None, None, 10).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "w1");
    }

    #[tokio::test]
    async fn search_with_provider_filter() {
        let db = InspectorDb::open_temp().unwrap();
        db.insert_request(make_webhook("w1", 200), None);

        let mut w2 = make_webhook("w2", 200);
        w2.provider = None;
        w2.summary = "POST /api/hook".to_string();
        db.insert_request(w2, None);
        db.flush_pending_writes().await.unwrap();

        let results = db.search("", Some("stripe"), None, 10).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "w1");
    }

    #[tokio::test]
    async fn search_with_status_filter() {
        let db = InspectorDb::open_temp().unwrap();
        db.insert_request(make_webhook("w1", 200), None);
        db.insert_request(make_webhook("w2", 500), None);
        db.flush_pending_writes().await.unwrap();

        let results = db
            .search("", None, Some(StatusQuery::Class(5)), 10)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "w2");

        let results = db
            .search("", None, Some(StatusQuery::Error), 10)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn session_lifecycle() {
        let db = InspectorDb::open_temp().unwrap();

        db.start_session("s1".to_string(), Some("acme.lpm.fyi".to_string()), 3000)
            .unwrap();
        db.insert_request(make_webhook("w1", 200), Some("s1".to_string()));
        db.insert_request(make_webhook("w2", 200), Some("s1".to_string()));
        db.end_session("s1".to_string()).unwrap();
        db.flush_pending_writes().await.unwrap();

        let sessions = db.list_sessions(10).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "s1");
        assert_eq!(sessions[0].domain, Some("acme.lpm.fyi".to_string()));
        assert_eq!(sessions[0].request_count, 2);
        assert!(sessions[0].ended_at.is_some());
    }

    #[tokio::test]
    async fn failed_reversible_session_rollback_keeps_the_session_hidden() {
        let db = InspectorDb::open_temp().unwrap();
        assert!(
            db.start_session_named_reversible(
                "pending-session".to_string(),
                Some("pending.lpm.fyi".to_string()),
                3000,
                None,
            )
            .unwrap()
        );
        db.insert_request(
            make_webhook("captured-before-rollback", 200),
            Some("pending-session".to_string()),
        );
        db.flush_pending_writes().await.unwrap();

        assert!(!db.rollback_session_start("pending-session").unwrap());

        assert!(db.get_session("pending-session").await.unwrap().is_none());
        assert!(
            db.get_session_including_pending("pending-session")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn session_lifecycle_persists_while_the_capture_writer_is_saturated() {
        let project = tempfile::tempdir().unwrap();
        let db_path = project.path().join("inspector.db");
        let write_conn = Connection::open(&db_path).unwrap();
        configure_connection(&write_conn, "NORMAL").unwrap();
        init_schema(&write_conn).unwrap();
        let read_conn = Connection::open(&db_path).unwrap();
        configure_connection(&read_conn, "NORMAL").unwrap();
        let control_conn = open_control_connection(&db_path).unwrap();
        let (write_tx, write_rx) = mpsc::channel(1);
        let queued_capture_bytes = Arc::new(AtomicUsize::new(0));
        let db = InspectorDb {
            read_conn: Arc::new(Mutex::new(read_conn)),
            control_conn: Arc::new(std::sync::Mutex::new(control_conn)),
            write_tx,
            queued_capture_bytes: Arc::clone(&queued_capture_bytes),
            db_path,
        };

        db.start_session("saturated-session".to_string(), None, 3000)
            .unwrap();
        db.insert_request(
            make_webhook("queued-while-paused", 200),
            Some("saturated-session".to_string()),
        );
        assert_eq!(db.write_tx.capacity(), 0);
        db.end_session("saturated-session".to_string()).unwrap();

        let writer = tokio::spawn(flush_task(
            Arc::new(Mutex::new(write_conn)),
            write_rx,
            queued_capture_bytes,
        ));
        db.flush_pending_writes().await.unwrap();

        let session = db.get_session("saturated-session").await.unwrap().unwrap();
        assert_eq!(session.request_count, 1);
        assert!(session.ended_at.is_some());
        assert!(
            db.get_webhook("queued-while-paused")
                .await
                .unwrap()
                .is_some()
        );

        writer.abort();
        let _ = writer.await;
    }

    #[tokio::test]
    async fn clear_history_preserves_an_open_session_for_future_captures() {
        let project = tempfile::tempdir().unwrap();
        let writer = InspectorDb::open(project.path()).unwrap();
        let clearer = InspectorDb::open(project.path()).unwrap();

        writer
            .start_session(
                "active-session".to_string(),
                Some("active.lpm.fyi".to_string()),
                3000,
            )
            .unwrap();
        writer.insert_request(
            make_webhook("before-clear", 200),
            Some("active-session".to_string()),
        );
        writer.flush_pending_writes().await.unwrap();

        clearer.clear_history().await.unwrap();

        writer.insert_request(
            make_webhook("after-clear", 201),
            Some("active-session".to_string()),
        );
        writer.flush_pending_writes().await.unwrap();

        assert!(writer.get_webhook("before-clear").await.unwrap().is_none());
        assert!(writer.get_webhook("after-clear").await.unwrap().is_some());
        let sessions = writer.list_sessions(10).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "active-session");
        assert_eq!(sessions[0].request_count, 1);
    }

    #[tokio::test]
    async fn explicit_flush_reports_a_failure_from_an_earlier_batch() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let conn = Arc::new(Mutex::new(conn));
        let mut pending_error = None;
        let queued_capture_bytes = AtomicUsize::new(0);
        let webhook = Arc::new(make_webhook("orphaned-request", 200));
        let retained_bytes = webhook.retained_size_bytes();
        queued_capture_bytes.store(retained_bytes, Ordering::Relaxed);
        let mut failed_batch = vec![DbWrite::InsertRequest {
            webhook,
            session_id: Some("missing-session".to_string()),
            retained_bytes,
        }];

        flush_pending_batch(
            &conn,
            &mut failed_batch,
            &mut pending_error,
            &queued_capture_bytes,
        )
        .await;

        assert!(
            pending_error
                .as_deref()
                .is_some_and(|error| error.contains("FOREIGN KEY")),
            "the first failed batch must remain pending until an explicit flush"
        );

        let (flushed_tx, flushed_rx) = tokio::sync::oneshot::channel();
        let mut marker_batch = vec![DbWrite::Flush(flushed_tx)];
        flush_pending_batch(
            &conn,
            &mut marker_batch,
            &mut pending_error,
            &queued_capture_bytes,
        )
        .await;

        let error = flushed_rx.await.unwrap().unwrap_err();
        assert!(error.contains("FOREIGN KEY"));
        assert!(pending_error.is_none());
    }

    #[tokio::test]
    async fn capture_queue_byte_budget_rejects_oversized_requests_without_accounting_leaks() {
        let db = InspectorDb::open_temp().unwrap();
        let mut webhook = make_webhook("oversized-queue-entry", 200);
        webhook.request_body = Vec::with_capacity(WRITE_QUEUE_BYTE_BUDGET + 1);

        db.insert_request(webhook, None);
        db.flush_pending_writes().await.unwrap();

        assert_eq!(db.queued_capture_bytes(), 0);
        assert_eq!(db.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn capture_queue_releases_byte_budget_after_committing_shared_requests() {
        let db = InspectorDb::open_temp().unwrap();
        let mut webhook = make_webhook("shared-queue-entry", 200);
        webhook.request_body = vec![0; 1024 * 1024];
        let webhook = Arc::new(webhook);

        db.insert_shared_request(Arc::clone(&webhook), None);
        db.flush_pending_writes().await.unwrap();

        assert_eq!(db.queued_capture_bytes(), 0);
        assert_eq!(db.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn count_requests() {
        let db = InspectorDb::open_temp().unwrap();
        db.insert_request(make_webhook("w1", 200), None);
        db.insert_request(make_webhook("w2", 200), None);
        db.insert_request(make_webhook("w3", 200), None);
        db.flush_pending_writes().await.unwrap();

        assert_eq!(db.count().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn pagination() {
        let db = InspectorDb::open_temp().unwrap();
        for i in 0..5 {
            let mut w = make_webhook(&format!("w{i}"), 200);
            w.timestamp = format!("2026-04-06T12:00:{i:02}Z");
            db.insert_request(w, None);
        }
        db.flush_pending_writes().await.unwrap();

        let page1 = db.list_requests(2, 0).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].id, "w4"); // newest

        let page2 = db.list_requests(2, 2).await.unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].id, "w2");
    }

    #[test]
    fn sanitize_fts_handles_special_chars() {
        assert_eq!(sanitize_fts_query("hello world"), "\"hello\" \"world\"");
        assert_eq!(sanitize_fts_query("cus_123"), "\"cus_123\"");
        assert_eq!(sanitize_fts_query(""), "");
    }

    #[tokio::test]
    async fn request_body_round_trips_without_legacy_truncation() {
        let db = InspectorDb::open_temp().unwrap();
        let mut webhook = make_webhook("large", 200);
        webhook.request_body = vec![0x5a; 10 * 1024 * 1024 + 1];
        db.insert_request(webhook.clone(), None);
        db.flush_pending_writes().await.unwrap();

        let stored = db.get_webhook("large").await.unwrap().unwrap();
        assert_eq!(stored.request_body, webhook.request_body);
    }

    /// Verify that our search query never returns phantom results even if
    /// FTS has stale entries — the JOIN with the requests table filters them.
    #[tokio::test]
    async fn search_never_returns_phantom_results() {
        let db = InspectorDb::open_temp().unwrap();

        let mut w = make_webhook("phantom-test", 200);
        w.request_body = br#"{"event":"unique_phantom_canary_xyz"}"#.to_vec();
        w.summary = "unique_phantom_canary_xyz".to_string();
        db.insert_request(w, None);
        db.flush_pending_writes().await.unwrap();

        // Verify the search finds it
        let results = db
            .search("unique_phantom_canary_xyz", None, None, 10)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);

        // Simulate a raw delete (e.g., external tool, manual cleanup)
        // This leaves an orphaned FTS entry — but our search uses a JOIN
        {
            let conn = db.read_conn.lock().await;
            conn.execute("DELETE FROM requests WHERE id = 'phantom-test'", [])
                .unwrap();
        }

        // Search must return 0 results (JOIN filters the phantom FTS entry)
        let results = db
            .search("unique_phantom_canary_xyz", None, None, 10)
            .await
            .unwrap();
        assert_eq!(
            results.len(),
            0,
            "search must not return phantom results after row deletion"
        );
    }

    /// Regression test: FTS5 index must stay consistent when a request ID
    /// is inserted twice (INSERT OR REPLACE). The old FTS entry must be
    /// replaced, not duplicated.
    #[tokio::test]
    async fn fts_no_duplicates_on_replace() {
        let db = InspectorDb::open_temp().unwrap();

        let mut w1 = make_webhook("replace-test", 200);
        w1.request_body = br#"{"event":"original_value_abc"}"#.to_vec();
        w1.summary = "original_value_abc".to_string();
        db.insert_request(w1, None);
        db.flush_pending_writes().await.unwrap();

        // Replace with different body
        let mut w2 = make_webhook("replace-test", 200);
        w2.request_body = br#"{"event":"replaced_value_def"}"#.to_vec();
        w2.summary = "replaced_value_def".to_string();
        db.insert_request(w2, None);
        db.flush_pending_writes().await.unwrap();

        // Old value must NOT be in FTS index (direct query, no JOIN masking)
        {
            let conn = db.read_conn.lock().await;
            let old_fts: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM requests_fts WHERE requests_fts MATCH '\"original_value_abc\"'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                old_fts, 0,
                "old FTS entry must be gone after INSERT OR REPLACE"
            );
        }

        // New value must exist exactly once in FTS
        {
            let conn = db.read_conn.lock().await;
            let new_fts: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM requests_fts WHERE requests_fts MATCH '\"replaced_value_def\"'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(new_fts, 1, "new FTS entry must exist exactly once");
        }
    }

    #[tokio::test]
    async fn rename_session() {
        let db = InspectorDb::open_temp().unwrap();
        db.start_session("s1".to_string(), Some("acme.lpm.fyi".to_string()), 3000)
            .unwrap();
        db.flush_pending_writes().await.unwrap();

        let updated = db
            .rename_session("s1", "debugging payment flow")
            .await
            .unwrap();
        assert!(updated);

        let sessions = db.list_sessions(10).await.unwrap();
        assert_eq!(sessions[0].name, Some("debugging payment flow".to_string()));
    }

    #[tokio::test]
    async fn rename_session_not_found() {
        let db = InspectorDb::open_temp().unwrap();
        let updated = db.rename_session("nonexistent", "name").await.unwrap();
        assert!(!updated);
    }

    #[tokio::test]
    async fn get_session_detail() {
        let db = InspectorDb::open_temp().unwrap();
        db.start_session("s1".to_string(), Some("acme.lpm.fyi".to_string()), 3000)
            .unwrap();
        db.insert_request(make_webhook("w1", 200), Some("s1".to_string()));
        db.insert_request(make_webhook("w2", 500), Some("s1".to_string()));
        db.insert_request(make_webhook("w3", 200), Some("s1".to_string()));
        db.end_session("s1".to_string()).unwrap();
        db.flush_pending_writes().await.unwrap();

        let detail = db.get_session("s1").await.unwrap().unwrap();
        assert_eq!(detail.id, "s1");
        assert_eq!(detail.request_count, 3);
        assert_eq!(detail.failure_count, 1);
        assert!(detail.ended_at.is_some());
    }

    #[tokio::test]
    async fn get_session_not_found() {
        let db = InspectorDb::open_temp().unwrap();
        let result = db.get_session("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_session_requests() {
        let db = InspectorDb::open_temp().unwrap();
        db.start_session("s1".to_string(), None, 3000).unwrap();
        db.insert_request(make_webhook("w1", 200), Some("s1".to_string()));
        db.insert_request(make_webhook("w2", 200), Some("s1".to_string()));
        // This one belongs to a different session
        db.insert_request(make_webhook("w3", 200), None);
        db.flush_pending_writes().await.unwrap();

        let requests = db.list_session_requests("s1", 10, 0).await.unwrap();
        assert_eq!(requests.len(), 2);
    }

    #[tokio::test]
    async fn update_tags() {
        let db = InspectorDb::open_temp().unwrap();
        db.insert_request(make_webhook("w1", 200), None);
        db.flush_pending_writes().await.unwrap();

        let tags = vec!["bug".to_string(), "repro".to_string()];
        let updated = db.update_tags("w1", &tags).await.unwrap();
        assert!(updated);

        let detail = db.get_request("w1").await.unwrap().unwrap();
        let parsed = crate::export::parse_tags(detail.tags.as_deref());
        assert_eq!(parsed, vec!["bug", "repro"]);
    }

    #[tokio::test]
    async fn persisted_webhook_reopens_with_replay_fidelity() {
        let project = tempfile::tempdir().unwrap();
        let mut webhook = make_webhook("fidelity", 207);
        webhook
            .request_headers
            .insert("x-replay-canary".to_string(), "header-value".to_string());
        webhook.request_body = vec![0, 1, 2, 0xff];
        webhook.response_headers.insert(
            "content-type".to_string(),
            "application/octet-stream".to_string(),
        );
        webhook.response_body = vec![0xfe, 3, 2, 1];
        webhook.auto_acked = true;
        webhook.response_body_incomplete = true;

        {
            let writer = InspectorDb::open(project.path()).unwrap();
            writer.insert_request(webhook.clone(), None);
            writer.flush_pending_writes().await.unwrap();
        }

        let reader = InspectorDb::open(project.path()).unwrap();
        let reopened = reader.get_webhook("fidelity").await.unwrap().unwrap();

        assert_eq!(reopened.request_headers, webhook.request_headers);
        assert_eq!(reopened.request_body, webhook.request_body);
        assert_eq!(reopened.response_headers, webhook.response_headers);
        assert_eq!(reopened.response_body, webhook.response_body);
        assert!(reopened.auto_acked);
        assert!(reopened.response_body_incomplete);
    }

    #[tokio::test]
    async fn project_databases_remain_isolated_for_paths_with_spaces_and_brackets() {
        let root = tempfile::tempdir().unwrap();
        let first_project = root.path().join("C [workspace] first");
        let second_project = root.path().join("D [workspace] second");
        std::fs::create_dir_all(&first_project).unwrap();
        std::fs::create_dir_all(&second_project).unwrap();

        let first = InspectorDb::open(&first_project).unwrap();
        let second = InspectorDb::open(&second_project).unwrap();
        first.insert_request(make_webhook("first-only", 200), None);
        second.insert_request(make_webhook("second-only", 200), None);
        first.flush_pending_writes().await.unwrap();
        second.flush_pending_writes().await.unwrap();

        assert!(first.get_webhook("second-only").await.unwrap().is_none());
        assert!(second.get_webhook("first-only").await.unwrap().is_none());
        assert_eq!(
            first.list_requests(10, 0).await.unwrap()[0].id,
            "first-only"
        );
        assert_eq!(
            second.list_requests(10, 0).await.unwrap()[0].id,
            "second-only"
        );
    }

    #[tokio::test]
    async fn concurrent_reader_observes_every_committed_capture() {
        let project = tempfile::tempdir().unwrap();
        let writer = InspectorDb::open(project.path()).unwrap();
        let reader = InspectorDb::open(project.path()).unwrap();
        let writer_task = tokio::spawn(async move {
            for index in 0..100 {
                let mut webhook = make_webhook(&format!("concurrent-{index:03}"), 200);
                webhook.timestamp = format!("2026-07-26T12:00:{:02}Z", index % 60);
                writer.insert_request(webhook, None);
                if index % 10 == 0 {
                    tokio::task::yield_now().await;
                }
            }
            writer.flush_pending_writes().await.unwrap();
        });

        while !writer_task.is_finished() {
            reader.list_requests(25, 0).await.unwrap();
            tokio::task::yield_now().await;
        }
        writer_task.await.unwrap();

        assert_eq!(reader.count().await.unwrap(), 100);
    }

    #[test]
    fn corrupt_project_database_fails_instead_of_creating_an_empty_store() {
        let project = tempfile::tempdir().unwrap();
        let lpm_dir = project.path().join(".lpm");
        std::fs::create_dir_all(&lpm_dir).unwrap();
        std::fs::write(lpm_dir.join("inspector.db"), b"not a sqlite database").unwrap();

        let error = match InspectorDb::open(project.path()) {
            Ok(_) => panic!("corrupt database must not open"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("database"));
    }
}

#[cfg(test)]
#[path = "db/durable_tests.rs"]
mod durable_tests;
