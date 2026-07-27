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
use tokio::sync::{Mutex, mpsc};

/// Batch flush interval — writes are buffered and flushed together.
const FLUSH_INTERVAL_MS: u64 = 100;

/// Maximum number of buffered writes before forcing a flush.
const FLUSH_BATCH_SIZE: usize = 50;

/// Handle to the inspector database.
///
/// All writes go through a background task that batches inserts.
/// Reads happen directly on a separate connection (WAL mode allows this).
#[derive(Clone)]
pub struct InspectorDb {
    /// Read-only connection (shared across API handlers via Arc<Mutex>).
    read_conn: Arc<Mutex<Connection>>,
    /// Channel for sending writes to the background flush task.
    write_tx: mpsc::UnboundedSender<DbWrite>,
    /// Database file path (for display/diagnostics).
    pub db_path: PathBuf,
}

/// A write operation to be batched.
enum DbWrite {
    InsertRequest(Box<CapturedWebhook>, Option<String>),
    StartSession {
        id: String,
        name: Option<String>,
        domain: Option<String>,
        local_port: u16,
    },
    EndSession {
        id: String,
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
        std::fs::create_dir_all(&lpm_dir)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;

        let db_path = lpm_dir.join("inspector.db");

        // Write connection (owned by the background flush task)
        let write_conn = Connection::open(&db_path)?;
        restrict_database_permissions(&db_path)?;
        init_schema(&write_conn)?;

        // Read connection (shared across API handlers).
        // busy_timeout ensures low-frequency mutations (tag updates, session renames)
        // wait gracefully if the write connection holds a lock during batch flushes.
        let read_conn = Connection::open(&db_path)?;
        read_conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=5000;",
        )?;

        let (write_tx, write_rx) = mpsc::unbounded_channel();

        // Spawn background flush task
        let write_conn = Arc::new(Mutex::new(write_conn));
        tokio::spawn(flush_task(write_conn, write_rx));

        Ok(Self {
            read_conn: Arc::new(Mutex::new(read_conn)),
            write_tx,
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
        init_schema(&write_conn)?;

        let read_conn = Connection::open(&tmp)?;
        read_conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=5000;",
        )?;

        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let write_conn = Arc::new(Mutex::new(write_conn));
        tokio::spawn(flush_task(write_conn, write_rx));

        Ok(Self {
            read_conn: Arc::new(Mutex::new(read_conn)),
            write_tx,
            db_path: tmp,
        })
    }

    /// Insert a captured request (non-blocking — queued for batch write).
    pub fn insert_request(&self, webhook: CapturedWebhook, session_id: Option<String>) {
        let _ = self
            .write_tx
            .send(DbWrite::InsertRequest(Box::new(webhook), session_id));
    }

    /// Record a new tunnel session start.
    pub fn start_session(&self, id: String, domain: Option<String>, local_port: u16) {
        self.start_session_named(id, domain, local_port, None);
    }

    /// Record a new tunnel session start with an optional display name.
    pub fn start_session_named(
        &self,
        id: String,
        domain: Option<String>,
        local_port: u16,
        name: Option<String>,
    ) {
        let _ = self.write_tx.send(DbWrite::StartSession {
            id,
            name,
            domain,
            local_port,
        });
    }

    /// Record a tunnel session end.
    pub fn end_session(&self, id: String) {
        let _ = self.write_tx.send(DbWrite::EndSession { id });
    }

    /// Wait until all writes queued before this call have committed.
    pub async fn flush_pending_writes(&self) -> Result<(), String> {
        let (flushed_tx, flushed_rx) = tokio::sync::oneshot::channel();
        self.write_tx
            .send(DbWrite::Flush(flushed_tx))
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
                    tags, auto_acked, req_size, res_size
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
                    tags, auto_acked, req_size, res_size
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
        let conn = self.read_conn.lock().await;

        let session = conn.query_row(
            "SELECT s.id, s.name, s.domain, s.local_port, s.started_at, s.ended_at,
                    (SELECT COUNT(*) FROM requests r WHERE r.session_id = s.id),
                    (SELECT COUNT(*) FROM requests r WHERE r.session_id = s.id AND r.status >= 400),
                    (SELECT COUNT(DISTINCT r.provider) FROM requests r WHERE r.session_id = s.id AND r.provider IS NOT NULL)
             FROM sessions s WHERE s.id = ?1",
            params![id],
            |row| {
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
            },
        );

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
        let tx = conn.unchecked_transaction()?;
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

// ── Schema initialization ─────────────────────────────────────────────

#[cfg(unix)]
fn restrict_database_permissions(path: &Path) -> Result<(), rusqlite::Error> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}

#[cfg(not(unix))]
fn restrict_database_permissions(_path: &Path) -> Result<(), rusqlite::Error> {
    Ok(())
}

fn init_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA foreign_keys=ON;
         PRAGMA busy_timeout=5000;

         CREATE TABLE IF NOT EXISTS sessions (
             id TEXT PRIMARY KEY,
             name TEXT,
             domain TEXT,
             local_port INTEGER,
             started_at TEXT NOT NULL DEFAULT (datetime('now')),
             ended_at TEXT
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
    Ok(())
}

// ── Background flush task ─────────────────────────────────────────────

async fn flush_task(conn: Arc<Mutex<Connection>>, mut rx: mpsc::UnboundedReceiver<DbWrite>) {
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

        flush_pending_batch(&conn, &mut batch, &mut pending_error).await;
    }

    // Drain remaining writes on shutdown
    while let Ok(write) = rx.try_recv() {
        batch.push(write);
    }
    flush_pending_batch(&conn, &mut batch, &mut pending_error).await;
}

async fn flush_pending_batch(
    conn: &Arc<Mutex<Connection>>,
    batch: &mut Vec<DbWrite>,
    pending_error: &mut Option<String>,
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
    finish_batch(batch, reported_result);
    if has_flush_marker {
        *pending_error = None;
    }
}

fn finish_batch(batch: &mut Vec<DbWrite>, flush_result: Result<(), String>) {
    for write in batch.drain(..) {
        if let DbWrite::Flush(flushed_tx) = write {
            let _ = flushed_tx.send(flush_result.clone());
        }
    }
}

fn flush_batch(conn: &Connection, batch: &[DbWrite]) -> Result<(), rusqlite::Error> {
    let tx = conn.unchecked_transaction()?;

    for write in batch {
        match write {
            DbWrite::InsertRequest(webhook, session_id) => {
                insert_request_row(&tx, webhook, session_id.as_deref())?;
            }
            DbWrite::StartSession {
                id,
                name,
                domain,
                local_port,
            } => {
                tx.execute(
                    "INSERT OR IGNORE INTO sessions (id, name, domain, local_port)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![id, name, domain, local_port],
                )?;
            }
            DbWrite::EndSession { id } => {
                tx.execute(
                    "UPDATE sessions SET ended_at = datetime('now') WHERE id = ?1",
                    params![id],
                )?;
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
          req_size, res_size, auto_acked)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
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

    fn make_webhook(id: &str, status: u16) -> CapturedWebhook {
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

        db.start_session("s1".to_string(), Some("acme.lpm.fyi".to_string()), 3000);
        db.insert_request(make_webhook("w1", 200), Some("s1".to_string()));
        db.insert_request(make_webhook("w2", 200), Some("s1".to_string()));
        db.end_session("s1".to_string());
        db.flush_pending_writes().await.unwrap();

        let sessions = db.list_sessions(10).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "s1");
        assert_eq!(sessions[0].domain, Some("acme.lpm.fyi".to_string()));
        assert_eq!(sessions[0].request_count, 2);
        assert!(sessions[0].ended_at.is_some());
    }

    #[tokio::test]
    async fn clear_history_preserves_an_open_session_for_future_captures() {
        let project = tempfile::tempdir().unwrap();
        let writer = InspectorDb::open(project.path()).unwrap();
        let clearer = InspectorDb::open(project.path()).unwrap();

        writer.start_session(
            "active-session".to_string(),
            Some("active.lpm.fyi".to_string()),
            3000,
        );
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
        let mut failed_batch = vec![DbWrite::InsertRequest(
            Box::new(make_webhook("orphaned-request", 200)),
            Some("missing-session".to_string()),
        )];

        flush_pending_batch(&conn, &mut failed_batch, &mut pending_error).await;

        assert!(
            pending_error
                .as_deref()
                .is_some_and(|error| error.contains("FOREIGN KEY")),
            "the first failed batch must remain pending until an explicit flush"
        );

        let (flushed_tx, flushed_rx) = tokio::sync::oneshot::channel();
        let mut marker_batch = vec![DbWrite::Flush(flushed_tx)];
        flush_pending_batch(&conn, &mut marker_batch, &mut pending_error).await;

        let error = flushed_rx.await.unwrap().unwrap_err();
        assert!(error.contains("FOREIGN KEY"));
        assert!(pending_error.is_none());
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
        db.start_session("s1".to_string(), Some("acme.lpm.fyi".to_string()), 3000);
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
        db.start_session("s1".to_string(), Some("acme.lpm.fyi".to_string()), 3000);
        db.insert_request(make_webhook("w1", 200), Some("s1".to_string()));
        db.insert_request(make_webhook("w2", 500), Some("s1".to_string()));
        db.insert_request(make_webhook("w3", 200), Some("s1".to_string()));
        db.end_session("s1".to_string());
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
        db.start_session("s1".to_string(), None, 3000);
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
