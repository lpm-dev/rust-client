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
    open_to_others: bool,
    ownership_ignored: bool,
    /// Who records the sessions this handle starts, and how to tell whether
    /// another session's recorder still runs.
    session_owners: Option<Arc<SessionOwnership>>,
    /// The directory [`Self::open_temp`]'s database is in, removed with the
    /// last handle.
    #[cfg(test)]
    _temp_dir: Option<Arc<tempfile::TempDir>>,
    /// The flush task's connection, for tests to look at.
    #[cfg(test)]
    write_conn: Arc<Mutex<Connection>>,
}

/// A count as SQL takes it, the largest one where it's past `i64`'s range,
/// as a negative `LIMIT` would mean no limit.
fn sql_count(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
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
    /// Opens (or creates) `{project_dir}/.lpm/inspector.db` to record
    /// captures, starting the background write-batching task. The capture
    /// files are made owner-only first: a database others could open is
    /// replaced with an owner-only copy (see [`OpenError`] for when it can't
    /// be yet).
    pub fn open(project_dir: &Path) -> Result<Self, OpenError> {
        let (owner, _identity) = CaptureOwner::of(project_dir)?;
        Self::open_project(project_dir, Access::Capture, owner)
            .map_err(|error| owner.explain(error))
    }

    /// Opens (or creates) `{project_dir}/.lpm/inspector.db` to read and
    /// manage the captures recorded there, without recording any. Existing
    /// files keep their access, so this works while another process records
    /// to the database; [`Self::open_to_others`] says whether others could
    /// open it.
    pub fn open_for_review(project_dir: &Path) -> Result<Self, OpenError> {
        let (owner, _identity) = CaptureOwner::of(project_dir)?;
        Self::open_project(project_dir, Access::Review, owner).map_err(|error| owner.explain(error))
    }

    fn open_project(
        project_dir: &Path,
        access: Access,
        owner: CaptureOwner,
    ) -> Result<Self, OpenError> {
        let lpm_dir = project_dir.join(".lpm");
        let db_path = lpm_dir.join("inspector.db");
        let ownership_ignored = prepare_lpm_dir(&lpm_dir, owner, access)?;
        #[cfg(test)]
        if let Some(meanwhile) = tests::AFTER_LPM_DIR.with_borrow_mut(Option::take) {
            meanwhile();
        }
        let _opening = lock_capture_files(&db_path)?;
        remove_replacement_copy(&db_path)?;
        if let Err(error) = keep_lpm_dir_ignored(&lpm_dir, owner) {
            tracing::warn!("could not keep tunnel captures out of git: {error}");
        }
        // On a volume that ignores ownership, every user owns the files, so
        // they're open to others whatever their mode, and a copy is too.
        let mut open_to_others =
            prepare_capture_files(&db_path, owner, access)? || ownership_ignored;
        if open_to_others && access == Access::Capture && !ownership_ignored {
            open_to_others = !replace_with_owner_only_copy(&db_path)?;
        }
        open_to_others |= !create_wal_sidecars(&db_path)?;

        // Write connection (owned by the background flush task)
        let write_conn = open_capture_connection(&db_path, "NORMAL").map_err(damaged(&db_path))?;
        refuse_unknown_schema(&write_conn, &db_path, damaged(&db_path))?;
        init_schema(&write_conn).map_err(damaged(&db_path))?;

        // Read connection (shared across API handlers). The busy timeout
        // lets low-frequency mutations (tag updates, session renames) wait
        // while the write connection flushes a batch.
        let read_conn = open_capture_connection(&db_path, "NORMAL").map_err(damaged(&db_path))?;
        let control_conn = open_control_connection(&db_path).map_err(damaged(&db_path))?;
        if owner.by_root {
            for connection in [&write_conn, &read_conn, &control_conn] {
                keep_wal_files(connection).map_err(damaged(&db_path))?;
            }
        }

        Ok(Self::with_connections(
            write_conn,
            read_conn,
            control_conn,
            db_path,
            open_to_others,
            ownership_ignored,
        ))
    }

    fn with_connections(
        write_conn: Connection,
        read_conn: Connection,
        control_conn: Connection,
        db_path: PathBuf,
        open_to_others: bool,
        ownership_ignored: bool,
    ) -> Self {
        let (write_tx, write_rx) = mpsc::channel(WRITE_QUEUE_CAPACITY);
        let queued_capture_bytes = Arc::new(AtomicUsize::new(0));
        let write_conn = Arc::new(Mutex::new(write_conn));
        #[cfg(test)]
        let kept_write_conn = Arc::clone(&write_conn);
        tokio::spawn(flush_task(
            write_conn,
            write_rx,
            Arc::clone(&queued_capture_bytes),
        ));

        Self {
            read_conn: Arc::new(Mutex::new(read_conn)),
            control_conn: Arc::new(std::sync::Mutex::new(control_conn)),
            write_tx,
            queued_capture_bytes,
            db_path,
            open_to_others,
            ownership_ignored,
            session_owners: None,
            #[cfg(test)]
            _temp_dir: None,
            #[cfg(test)]
            write_conn: kept_write_conn,
        }
    }

    /// Records this process as the owner of the sessions this handle starts,
    /// and ends open sessions whose owner is gone: those of a tunnel that
    /// crashed, was killed, or lost its terminal never record their end.
    /// They're ended again whenever sessions are listed, cleared or deleted.
    pub fn with_session_ownership(mut self, ownership: SessionOwnership) -> Self {
        self.session_owners = Some(Arc::new(ownership));
        let conn = self
            .control_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.end_abandoned_sessions_on(&conn);
        drop(conn);
        self
    }

    /// Ends abandoned sessions before an operation that shows or removes
    /// sessions by whether they're open. A failure leaves them open, which
    /// that operation still handles.
    fn end_abandoned_sessions_on(&self, conn: &Connection) {
        if let Some(ownership) = &self.session_owners
            && let Err(error) = end_abandoned_sessions(conn, ownership)
        {
            tracing::warn!("failed to end abandoned inspector sessions: {error}");
        }
    }

    /// The owner columns of a session this handle starts.
    fn owner_columns(&self) -> (Option<u32>, Option<&str>) {
        self.session_owners
            .as_deref()
            .map_or((None, None), |owner| {
                (Some(owner.pid), Some(owner.identity.as_str()))
            })
    }

    /// Opens a database in a directory of its own, removed with the last
    /// handle, so tests running in parallel don't share one.
    #[cfg(test)]
    pub(crate) fn open_temp() -> Result<Self, rusqlite::Error> {
        let temp_dir = tempfile::Builder::new()
            .prefix("lpm-inspect-test-")
            .tempdir()
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let tmp = temp_dir.path().join("inspector.db");

        let write_conn = Connection::open(&tmp)?;
        configure_connection(&write_conn, "NORMAL")?;
        init_schema(&write_conn)?;
        let read_conn = Connection::open(&tmp)?;
        configure_connection(&read_conn, "NORMAL")?;
        let control_conn = open_control_connection(&tmp)?;

        Ok(Self {
            _temp_dir: Some(Arc::new(temp_dir)),
            ..Self::with_connections(write_conn, read_conn, control_conn, tmp, false, false)
        })
    }

    /// Whether other users could open the capture files when this handle
    /// opened them: a database [`Self::open_for_review`] found so, or one
    /// whose file modes don't keep others out, which [`Self::open`] can't
    /// make owner-only: on a filesystem without Unix modes, or a volume that
    /// ignores ownership ([`Self::ownership_ignored`]).
    pub fn open_to_others(&self) -> bool {
        self.open_to_others
    }

    /// Whether the capture files' volume ignores ownership, as one mounted
    /// `noowners` on macOS does: every user owns its files, so they're open
    /// to others whatever their mode, and no open can change that.
    pub fn ownership_ignored(&self) -> bool {
        self.ownership_ignored
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
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
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
        let (owner_pid, owner_identity) = self.owner_columns();
        let conn = self
            .control_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        conn.execute(
            "INSERT OR IGNORE INTO sessions
                 (id, name, domain, local_port, owner_pid, owner_identity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, name, domain, local_port, owner_pid, owner_identity],
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
        let (owner_pid, owner_identity) = self.owner_columns();
        let mut conn = self
            .control_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let transaction =
            conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO sessions
                 (id, name, domain, local_port, owner_pid, owner_identity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![&id, name, domain, local_port, owner_pid, owner_identity],
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
        let transaction =
            conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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
        let transaction =
            conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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
        let transaction =
            conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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

        let rows = stmt.query_map(params![sql_count(limit), sql_count(offset)], |row| {
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

    /// The local port the session that captured request `id` forwarded to.
    pub async fn request_local_port(&self, id: &str) -> Result<Option<u16>, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        let port = conn.query_row(
            "SELECT s.local_port FROM requests r JOIN sessions s ON s.id = r.session_id
             WHERE r.id = ?1",
            params![id],
            |row| row.get::<_, Option<u16>>(0),
        );
        match port {
            Ok(port) => Ok(port.filter(|port| *port != 0)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error),
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
        let rows = stmt.query_map(
            params![sql_count(limit), sql_count(offset)],
            stored_detail_from_row,
        )?;

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

        let rows = stmt.query_map(params![fts_query, provider_str, sql_count(limit)], |row| {
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
        self.end_abandoned_sessions_on(&conn);
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

        let rows = stmt.query_map(params![sql_count(limit)], |row| {
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

        let rows = stmt.query_map(
            params![session_id, sql_count(limit), sql_count(offset)],
            |row| {
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
            },
        )?;

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
    /// captures without violating the request-to-session foreign key. The
    /// captures leave no trace in the file: the full-text index, which keeps
    /// a deleted entry's terms until its segments merge, is rebuilt from its
    /// emptied content; `secure_delete` zeroes the freed pages; and the WAL,
    /// which still holds the captures' earlier pages, is checkpointed and
    /// truncated, unless another connection is reading at that moment.
    pub async fn clear_history(&self) -> Result<(), rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        self.end_abandoned_sessions_on(&conn);
        // Immediate: a deferred transaction that reads before it writes gets
        // SQLITE_BUSY at once, without waiting, if another connection
        // commits in between.
        let tx =
            rusqlite::Transaction::new_unchecked(&conn, rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM requests_fts", [])?;
        tx.execute(
            "INSERT INTO requests_fts(requests_fts) VALUES ('rebuild')",
            [],
        )?;
        tx.execute("DELETE FROM requests", [])?;
        tx.execute("DELETE FROM sessions WHERE ended_at IS NOT NULL", [])?;
        tx.commit()?;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
    }

    /// Delete an ended session and every request it captured.
    ///
    /// Open sessions are refused, since a running tunnel may still attach
    /// captures to them. The captures leave no trace, as with
    /// [`clear_history`](Self::clear_history): merging the full-text index
    /// drops their terms, `secure_delete` zeroes the freed pages, and the WAL
    /// is truncated unless another connection is reading.
    pub async fn delete_session(&self, id: &str) -> Result<SessionDeletion, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        self.end_abandoned_sessions_on(&conn);
        let tx =
            rusqlite::Transaction::new_unchecked(&conn, rusqlite::TransactionBehavior::Immediate)?;
        let ended = tx.query_row(
            "SELECT ended_at IS NOT NULL FROM sessions WHERE id = ?1",
            params![id],
            |row| row.get::<_, bool>(0),
        );
        match ended {
            Ok(true) => {}
            Ok(false) => return Ok(SessionDeletion::Open),
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(SessionDeletion::NotFound),
            Err(error) => return Err(error),
        }
        let request_ids = delete_session_requests(
            &tx,
            "SELECT id, rowid FROM requests WHERE session_id = ?1",
            params![id],
        )?;
        tx.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        tx.commit()?;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(SessionDeletion::Deleted(request_ids))
    }

    /// Delete every ended session and the requests they captured, leaving no
    /// trace of them as [`delete_session`](Self::delete_session) does.
    pub async fn delete_ended_sessions(&self) -> Result<DeletedSessions, rusqlite::Error> {
        let conn = self.read_conn.lock().await;
        self.end_abandoned_sessions_on(&conn);
        let tx =
            rusqlite::Transaction::new_unchecked(&conn, rusqlite::TransactionBehavior::Immediate)?;
        let request_ids = delete_session_requests(
            &tx,
            "SELECT r.id, r.rowid FROM requests r
             JOIN sessions s ON s.id = r.session_id
             WHERE s.ended_at IS NOT NULL",
            [],
        )?;
        let sessions = tx.execute("DELETE FROM sessions WHERE ended_at IS NOT NULL", [])?;
        tx.commit()?;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(DeletedSessions {
            sessions,
            request_ids,
        })
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

/// Whether the process that started an open session still runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerState {
    /// The recorded process runs.
    Running,
    /// No process runs with the recorded PID and identity: it exited, or the
    /// system gave its PID to another process.
    Gone,
    /// A process with the PID runs, but its identity can't be read, as for
    /// another user's process on some systems.
    Unknown,
}

/// The process recording sessions through a database handle, and a check of
/// whether the recorder of another session still runs. The identity tells a
/// process apart from a later one given the same PID.
#[derive(Debug, Clone)]
pub struct SessionOwnership {
    pid: u32,
    identity: String,
    state_of: fn(pid: u32, identity: &str) -> OwnerState,
}

impl SessionOwnership {
    pub fn new(pid: u32, identity: String, state_of: fn(u32, &str) -> OwnerState) -> Self {
        Self {
            pid,
            identity,
            state_of,
        }
    }

    /// Whether an open session's recorder is gone, so the session never ends.
    fn abandoned(&self, owner_pid: Option<u32>, owner_identity: Option<&str>) -> bool {
        match (owner_pid, owner_identity) {
            (Some(pid), Some(identity)) => (self.state_of)(pid, identity) == OwnerState::Gone,
            // Started before LPM CLI recorded owners. An earlier release still
            // running could be recording it, but nothing else can end it.
            (None, _) => true,
            (Some(_), None) => false,
        }
    }
}

/// Ends the open sessions whose recorder is gone, at their last capture or,
/// without one, their start. A pending one, never shown, is discarded as its
/// recorder would have rolled it back.
fn end_abandoned_sessions(
    conn: &Connection,
    ownership: &SessionOwnership,
) -> Result<usize, rusqlite::Error> {
    let mut abandoned = Vec::new();
    {
        let mut stmt = conn.prepare_cached(
            "SELECT id, owner_pid, owner_identity FROM sessions WHERE ended_at IS NULL",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let owner_identity: Option<String> = row.get(2)?;
            if ownership.abandoned(row.get(1)?, owner_identity.as_deref()) {
                abandoned.push(row.get::<_, String>(0)?);
            }
        }
    }
    if abandoned.is_empty() {
        return Ok(0);
    }
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let mut ended = 0;
    {
        let mut unpend = tx.prepare("DELETE FROM pending_sessions WHERE session_id = ?1")?;
        let mut discard = tx.prepare(
            "DELETE FROM sessions
             WHERE id = ?1 AND ended_at IS NULL
               AND NOT EXISTS (SELECT 1 FROM requests WHERE session_id = ?1)",
        )?;
        let mut end = tx.prepare(
            "UPDATE sessions
             SET ended_at = COALESCE(
                 (SELECT MAX(created_at) FROM requests WHERE session_id = ?1),
                 started_at
             )
             WHERE id = ?1 AND ended_at IS NULL",
        )?;
        for id in &abandoned {
            if unpend.execute(params![id])? != 0 && discard.execute(params![id])? != 0 {
                ended += 1;
            } else {
                ended += end.execute(params![id])?;
            }
        }
    }
    tx.commit()?;
    Ok(ended)
}

/// Outcome of [`InspectorDb::delete_session`].
#[derive(Debug, PartialEq, Eq)]
pub enum SessionDeletion {
    /// The session is gone, with the requests it captured.
    Deleted(Vec<String>),
    /// The session is still open; a running tunnel may capture into it.
    Open,
    /// No session has this ID.
    NotFound,
}

/// What [`InspectorDb::delete_ended_sessions`] removed.
#[derive(Debug, PartialEq, Eq)]
pub struct DeletedSessions {
    pub sessions: usize,
    pub request_ids: Vec<String>,
}

/// Delete the requests `select` yields as `(id, rowid)` rows, and their
/// full-text entries, returning their IDs.
fn delete_session_requests(
    tx: &rusqlite::Transaction<'_>,
    select: &str,
    select_params: impl rusqlite::Params,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut request_ids = Vec::new();
    let mut rowids = Vec::new();
    {
        let mut stmt = tx.prepare(select)?;
        let mut rows = stmt.query(select_params)?;
        while let Some(row) = rows.next()? {
            request_ids.push(row.get::<_, String>(0)?);
            rowids.push(row.get::<_, i64>(1)?);
        }
    }
    if rowids.is_empty() {
        return Ok(request_ids);
    }
    {
        let mut delete_text = tx.prepare("DELETE FROM requests_fts WHERE rowid = ?1")?;
        let mut delete_request = tx.prepare("DELETE FROM requests WHERE rowid = ?1")?;
        for rowid in &rowids {
            delete_text.execute(params![rowid])?;
            delete_request.execute(params![rowid])?;
        }
    }
    // A deleted entry's terms stay in its index segment until segments merge.
    tx.execute(
        "INSERT INTO requests_fts(requests_fts) VALUES ('optimize')",
        [],
    )?;
    Ok(request_ids)
}

/// Why the capture database couldn't be opened.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// `.lpm` or a capture file failed a check or a file operation; the
    /// message names it, and says what to do. One others could open that
    /// another process has open, which [`InspectorDb::open`] can't replace
    /// yet, is [`std::io::ErrorKind::ResourceBusy`].
    #[error("{0}")]
    Files(#[from] std::io::Error),
    /// SQLite can't read the file as a database, or finds it damaged.
    #[error(
        "{} is damaged or isn't a capture database ({detail}); move it aside {}, and retry",
        path.display(),
        with_its_sidecars(path)
    )]
    Damaged { path: PathBuf, detail: String },
    /// Any other SQLite failure.
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
}

impl OpenError {
    /// The I/O failure this is, for callers that report it as one.
    pub fn kind(&self) -> std::io::ErrorKind {
        match self {
            Self::Files(error) => error.kind(),
            Self::Damaged { .. } => std::io::ErrorKind::InvalidData,
            Self::Database(_) => std::io::ErrorKind::Other,
        }
    }
}

/// Reads SQLite's refusal of a file it can't use as a database as such.
fn damaged(db_path: &Path) -> impl Fn(rusqlite::Error) -> OpenError + '_ {
    move |error| match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt) => {
            OpenError::Damaged {
                path: db_path.to_path_buf(),
                detail: error.to_string(),
            }
        }
        _ => OpenError::Database(error),
    }
}

/// What an open of the capture database may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Records captures: makes `.lpm` and the capture files safe to write
    /// them to, replacing a database others could open.
    Capture,
    /// Reads and manages recorded captures. Changes no existing file's
    /// access, and so runs while another process records to the database.
    Review,
}

/// Whose capture files are: the user's own. Root in a project another user
/// owns, as in a container over a mounted checkout, opens them as that user
/// ([`OwnerIdentity`]): that user can move `.lpm` and the names in it at any
/// time, and so could otherwise have what root reads, writes and removes
/// there land anywhere.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
struct CaptureOwner {
    uid: u32,
    /// Whether root opens the capture files as their owner.
    by_root: bool,
}

/// What root holds while it opens the capture files as their owner: on
/// Linux, the owner's filesystem identity, taken by the opening thread
/// alone; elsewhere, root doesn't open another user's.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
type OwnerIdentity = Option<lpm_common::thread_identity::ActingAs>;
#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
struct OwnerIdentity;

/// What an open holds that takes no other user's identity.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const OWN_IDENTITY: OwnerIdentity = None;
#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
const OWN_IDENTITY: OwnerIdentity = OwnerIdentity;

#[cfg(unix)]
impl CaptureOwner {
    /// The capture files' owner, and the identity root holds while it opens
    /// them as that owner. The project's path must be one no user but its
    /// owner and root can change ([`refuse_changeable_path`]).
    fn of(project_dir: &Path) -> std::io::Result<(Self, OwnerIdentity)> {
        use std::os::unix::fs::MetadataExt;

        let uid = lpm_common::current_uid();
        let project =
            std::fs::metadata(project_dir).map_err(|error| with_path(project_dir, error))?;
        let owner = if uid == 0 { project.uid() } else { uid };
        refuse_changeable_path(project_dir, owner)?;
        if uid != 0 || owner == 0 {
            return Ok((
                Self {
                    uid: owner,
                    by_root: false,
                },
                OWN_IDENTITY,
            ));
        }
        let identity = act_as_project_owner(project_dir, &project)?;
        Ok((
            Self {
                uid: owner,
                by_root: true,
            },
            identity,
        ))
    }

    fn owns(self, metadata: &std::fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;

        metadata.uid() == self.uid
    }

    /// Says, of a file root was refused as the project's owner, whose
    /// access that was.
    fn explain(self, error: OpenError) -> OpenError {
        match error {
            OpenError::Files(error)
                if self.by_root && error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                OpenError::Files(std::io::Error::new(
                    error.kind(),
                    format!(
                        "{error} (root opens the capture files of user {}'s project as \
                         that user)",
                        self.uid
                    ),
                ))
            }
            other => other,
        }
    }
}

/// Refuses a project whose path a user other than `owner` and root could
/// change: such a user could move `.lpm`, or a directory above it, while
/// the capture files are opened by name, and have them written elsewhere,
/// or their captures read.
#[cfg(unix)]
fn refuse_changeable_path(project_dir: &Path, owner: u32) -> std::io::Result<()> {
    let Some(found) = lpm_common::path_trust::first_changeable_directory(project_dir, owner)
        .map_err(|error| with_path(project_dir, error))?
    else {
        return Ok(());
    };
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{} can be changed by other users: {}. They could move .lpm while tunnel \
             captures, which hold request headers and bodies, are opened, so captures are \
             kept only where no one but the project's owner and root can; keep the project \
             under directories only you can change",
            found.directory.display(),
            found.reason
        ),
    ))
}

/// The names in `.lpm` root may have left its own, which it gives to the
/// project's owner before opening them as that owner.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const ROOTS_CAPTURE_FILES: [&str; 8] = [
    ".gitignore",
    "inspector.db",
    "inspector.db-wal",
    "inspector.db-shm",
    "inspector.db-journal",
    "inspector.db-lock",
    "inspector.db-copy",
    "inspector.db-copy-journal",
];

/// Takes the project owner's identity on this thread, with their groups,
/// once root has given them what it left its own in `.lpm`, as an
/// `lpm install` run as root makes `.lpm` root's; what root can't give
/// safely is refused, naming it. An owner the user database doesn't know,
/// as a host's in a container, gets the project's group, or none where
/// that's root's.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn act_as_project_owner(
    project_dir: &Path,
    project: &std::fs::Metadata,
) -> std::io::Result<OwnerIdentity> {
    use lpm_common::path_trust;
    use std::os::unix::fs::MetadataExt;

    const NO_GROUP: u32 = 65_534;
    let uid = project.uid();
    let refused = |error: std::io::Error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "{} belongs to user {uid}, and root records tunnel captures there only as \
                 that user, so that it can't be made to write elsewhere, which this process \
                 can't do ({error}); run the tunnel as the project's owner",
                project_dir.display()
            ),
        )
    };
    let (gid, groups) = match path_trust::account(uid).map_err(refused)? {
        Some(account) => (
            account.gid,
            path_trust::groups_of(&account).map_err(refused)?,
        ),
        None => {
            let gid = if project.gid() == 0 {
                NO_GROUP
            } else {
                project.gid()
            };
            (gid, vec![gid])
        }
    };
    let lpm_dir = project_dir.join(".lpm");
    let names = ROOTS_CAPTURE_FILES.map(std::ffi::OsStr::new);
    let kept = path_trust::give_root_entries(&lpm_dir, &names, uid, gid)
        .map_err(|error| with_path(&lpm_dir, error))?;
    // A `.gitignore` root keeps is only left without the rule that ignores `.lpm`.
    if let Some(name) = kept.iter().find(|name| *name != ".gitignore") {
        let path = lpm_dir.join(name);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} belongs to root, which records tunnel captures in user {uid}'s project                  only as that user, and can't give it to them safely, as others could have                  put it there or it leads elsewhere; give it to that user (chown {uid}) or                  remove it",
                path.display()
            ),
        ));
    }
    lpm_common::thread_identity::act_as(uid, gid, &groups)
        .map(Some)
        .map_err(refused)
}

#[cfg(all(unix, not(all(target_os = "linux", target_pointer_width = "64"))))]
fn act_as_project_owner(
    project_dir: &Path,
    project: &std::fs::Metadata,
) -> std::io::Result<OwnerIdentity> {
    use std::os::unix::fs::MetadataExt;

    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{} belongs to user {}, and root records tunnel captures, which hold request \
             headers and bodies, only in its own projects on this system, as another \
             user could move .lpm to have root write elsewhere; run the tunnel as that \
             user, without sudo",
            project_dir.display(),
            project.uid()
        ),
    ))
}

/// Access to the capture files on Windows is the project's ACLs.
#[cfg(not(unix))]
#[derive(Debug, Clone, Copy)]
struct CaptureOwner {
    by_root: bool,
}

#[cfg(not(unix))]
impl CaptureOwner {
    fn of(_project_dir: &Path) -> std::io::Result<(Self, OwnerIdentity)> {
        Ok((Self { by_root: false }, OWN_IDENTITY))
    }

    fn explain(self, error: OpenError) -> OpenError {
        error
    }
}

/// How long a connection waits for another's lock, and how long opening
/// keeps retrying what SQLite refuses at once while another connection is
/// busy.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn busy_timeout() -> std::time::Duration {
    #[cfg(test)]
    if let Some(timeout) = tests::BUSY_WAIT.get() {
        return timeout;
    }
    BUSY_TIMEOUT
}

/// How long opening waits for another LPM process to finish opening the
/// capture files, which takes longest when one replaces a large database.
const OPEN_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn open_lock_timeout() -> std::time::Duration {
    #[cfg(test)]
    if let Some(timeout) = tests::OPEN_LOCK_WAIT.get() {
        return timeout;
    }
    OPEN_LOCK_TIMEOUT
}

/// The longest string, blob or row SQLite builds: a capture's two bodies of
/// at most 50 MiB each and its headers fit, and a database from elsewhere
/// can't have SQLite build anything much larger for a capture written to it.
const LONGEST_VALUE_BYTES: i32 = 128 * 1024 * 1024;

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

/// A sidecar moves with its database, which an open would otherwise find
/// without it and remove; one found without a database moves alone.
fn hard_linked(path: &Path, db_path: &Path) -> std::io::Error {
    let advice = if path == db_path {
        format!("move it aside {}", with_its_sidecars(db_path))
    } else if db_path.exists() {
        format!(
            "move {} aside {}",
            db_path.display(),
            with_its_sidecars(db_path)
        )
    } else {
        "move it aside".to_owned()
    };
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{} has other hard links, so captures written to it would change those \
             files too; {advice}, and retry",
            path.display()
        ),
    )
}

/// Names the files SQLite keeps beside a capture database, for advice to
/// move it: they go with it, as an open removes those it finds without a
/// database, and a WAL not yet folded into the database holds part of it.
/// SQLite pairs them with a database by suffix, so each keeps its own; in
/// `.lpm`, which ignores everything, git goes on ignoring them.
fn with_its_sidecars(db_path: &Path) -> String {
    let name = db_path
        .file_name()
        .unwrap_or(db_path.as_os_str())
        .to_string_lossy();
    format!(
        "together with any {name}-wal, {name}-shm and {name}-journal beside it, renamed \
         alike with each suffix kept and left in .lpm so git goes on ignoring them"
    )
}

/// Makes sure `.lpm` is a directory of the project's own, creating it if
/// needed. A link, which a cloned repository could point anywhere, such as
/// into a directory it serves, is refused; the metadata of a link, read
/// without following it, is never a directory's. Reparse points other than
/// links, such as a synced folder's placeholders on Windows, read as the
/// directories they stand for. See [`restrict_lpm_dir`] for Unix, and for
/// whether `.lpm`'s volume ignores ownership, which this returns.
fn prepare_lpm_dir(lpm_dir: &Path, owner: CaptureOwner, access: Access) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(lpm_dir) {
        Ok(metadata) if !metadata.is_dir() => return Err(linked_or_not(lpm_dir, "directory")),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(lpm_dir).map_err(|error| with_path(lpm_dir, error))?;
        }
        Err(error) => return Err(with_path(lpm_dir, error)),
    }
    restrict_lpm_dir(lpm_dir, owner, access)
}

/// `.lpm` must be the capture owner's. A capture writer makes it writable
/// by no one else, and on macOS clears its extended ACL, whose entries can
/// grant what its mode doesn't and pass to the files created in it, so no
/// other user can swap the capture files' names between the checks below
/// and SQLite's opens, or read the files created there. Says whether its
/// volume ignores ownership, as only macOS reports.
#[cfg(unix)]
fn restrict_lpm_dir(lpm_dir: &Path, owner: CaptureOwner, access: Access) -> std::io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory =
        lpm_common::open_nofollow(lpm_dir).map_err(|error| with_path(lpm_dir, error))?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() {
        return Err(linked_or_not(lpm_dir, "directory"));
    }
    if !owner.owns(&metadata) {
        return Err(another_users(lpm_dir));
    }
    #[cfg(target_os = "macos")]
    let ownership_ignored = lpm_common::macos_acl::ignores_ownership(&directory)
        .map_err(|error| with_path(lpm_dir, error))?;
    #[cfg(not(target_os = "macos"))]
    let ownership_ignored = false;
    #[cfg(test)]
    let ownership_ignored = ownership_ignored || tests::OWNERSHIP_IGNORED.get();
    if access == Access::Review {
        return Ok(ownership_ignored);
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        directory
            .set_permissions(std::fs::Permissions::from_mode(mode & !0o022))
            .map_err(|error| with_path(lpm_dir, error))?;
    }
    #[cfg(target_os = "macos")]
    if lpm_common::macos_acl::has_extended_acl(&directory)? {
        lpm_common::macos_acl::clear_extended_acl(&directory)
            .map_err(|error| with_path(lpm_dir, error))?;
    }
    Ok(ownership_ignored)
}

#[cfg(not(unix))]
fn restrict_lpm_dir(
    _lpm_dir: &Path,
    _owner: CaptureOwner,
    _access: Access,
) -> std::io::Result<bool> {
    Ok(false)
}

/// Holds other LPM processes off the capture files while this one checks,
/// replaces and opens them. A process that opened the database while it was
/// being replaced would go on writing to the old file. Releases before the
/// lock don't take it.
fn lock_capture_files(
    db_path: &Path,
) -> std::io::Result<lpm_common::SingleFileExclusiveLockHandle> {
    let lock_path = capture_file(db_path, "-lock");
    let file = lpm_common::open_lock_file_nofollow(&lock_path)
        .map_err(|error| with_path(&lock_path, error))?;
    let timeout = open_lock_timeout();
    match lpm_common::acquire_single_file_exclusive_lock_from_file_within(file, timeout) {
        Ok(Some(lock)) => Ok(lock),
        Ok(None) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "another LPM process held {} for {} s while opening the captures; retry \
                 once it has started",
                lock_path.display(),
                timeout.as_secs()
            ),
        )),
        Err(error) => Err(std::io::Error::other(format!(
            "{}: {error}",
            lock_path.display()
        ))),
    }
}

/// Removes the copy, and its journal, of a replacement that didn't finish,
/// as they hold captures. Only an open holding the lock makes one, so any
/// found under it is left over.
fn remove_replacement_copy(db_path: &Path) -> std::io::Result<()> {
    let copy_path = capture_file(db_path, "-copy");
    remove_if_present(&capture_file(&copy_path, "-journal"))?;
    remove_if_present(&copy_path)
}

/// Checks the capture files before SQLite opens them, and says whether
/// others could open them (see [`check_capture_file`]). No capture file may
/// be a link, another user's (see [`CaptureOwner`]), or have other hard
/// links. Sidecars without
/// a database are a removed database's leftovers, which may hold its
/// captures, and are removed; SQLite would only discard them on its next
/// write. A missing database is created owner-only.
fn prepare_capture_files(
    db_path: &Path,
    owner: CaptureOwner,
    access: Access,
) -> std::io::Result<bool> {
    let mut open_to_others = false;
    let mut database_exists = false;
    for path in capture_files(db_path) {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() => return Err(linked_or_not(&path, "file")),
            Ok(metadata) => {
                open_to_others |= check_capture_file(&path, db_path, &metadata, owner, access)?;
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
    Ok(!create_owner_only(db_path)?)
}

/// Makes the WAL files SQLite would create, when they're missing,
/// owner-only first, and says whether they read that way. A file SQLite
/// creates takes the inheritable ACL entries of its directory on macOS,
/// which a review leaves on `.lpm`. Under the open lock no LPM process has
/// the database open in WAL without them, so none is made under one in
/// use, and SQLite takes empty ones as new.
fn create_wal_sidecars(db_path: &Path) -> std::io::Result<bool> {
    let mut owner_only = true;
    for suffix in ["-wal", "-shm"] {
        let path = capture_file(db_path, suffix);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                owner_only &= create_owner_only(&path)?;
            }
            Err(error) => return Err(with_path(&path, error)),
        }
    }
    Ok(owner_only)
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(with_path(path, error)),
        _ => Ok(()),
    }
}

/// Checks an existing capture file and says whether others could open it
/// to read: its mode lets its group or anyone read it, or on macOS it has
/// an extended ACL, whose entries can grant what the mode doesn't. A
/// capture writer makes one others couldn't open owner-only. One they could
/// keeps its mode, made only the owner's to read and write as well, until
/// the database is replaced, so a replacement that can't run yet runs on a
/// later open. Modes are read and changed by name, which no other user can
/// swap in a directory only its owner can write, rather than through a
/// handle, whose closing would drop the locks SQLite holds on the file in
/// this process, and which a file without read permission can't have. A
/// file that's gone needs nothing: SQLite removes `-wal` and `-shm` when
/// another process closes its last connection.
#[cfg(unix)]
fn check_capture_file(
    path: &Path,
    db_path: &Path,
    metadata: &std::fs::Metadata,
    owner: CaptureOwner,
    access: Access,
) -> std::io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !owner.owns(metadata) {
        return Err(another_users(path));
    }
    if metadata.nlink() > 1 {
        return Err(hard_linked(path, db_path));
    }
    let mode = metadata.mode() & 0o7777;
    #[cfg(target_os = "macos")]
    let extended_acl =
        lpm_common::macos_acl::has_extended_acl_at(path).map_err(|error| with_path(path, error))?;
    #[cfg(not(target_os = "macos"))]
    let extended_acl = false;
    let open_to_others = mode & 0o044 != 0 || extended_acl;
    if access == Access::Review {
        return Ok(open_to_others);
    }
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
fn check_capture_file(
    path: &Path,
    db_path: &Path,
    _metadata: &std::fs::Metadata,
    _owner: CaptureOwner,
    _access: Access,
) -> std::io::Result<bool> {
    let file = match lpm_common::open_nofollow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(with_path(path, error)),
    };
    if lpm_common::link_count(&file).map_err(|error| with_path(path, error))? > 1 {
        return Err(hard_linked(path, db_path));
    }
    Ok(false)
}

/// Creates a capture file only its owner can open, and says whether it
/// reads that way: a filesystem without Unix
/// modes, such as FAT or a Windows drive mounted in Linux, shows the mode it
/// likes. On macOS, extended ACL entries it inherited are cleared. A file
/// that appears at the name meanwhile, made by an LPM release that doesn't
/// take the lock, is refused until a retry checks it; `O_EXCL` also refuses
/// a link there.
#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(std::io::Error::new(
                error.kind(),
                format!(
                    "{} appeared while LPM was creating it; retry",
                    path.display()
                ),
            ));
        }
        Err(error) => return Err(with_path(path, error)),
    };
    #[cfg(target_os = "macos")]
    if lpm_common::macos_acl::has_extended_acl(&file)? {
        lpm_common::macos_acl::clear_extended_acl(&file).map_err(|error| with_path(path, error))?;
    }
    let mode = file.metadata()?.mode();
    #[cfg(test)]
    let mode = if tests::MODELESS_FILESYSTEM.get() {
        mode | 0o777
    } else {
        mode
    };
    Ok(mode & 0o044 == 0)
}

#[cfg(not(unix))]
fn create_owner_only(_path: &Path) -> std::io::Result<bool> {
    Ok(true)
}

/// Replaces a capture database others could open with an owner-only copy,
/// and says whether it did. Making the file owner-only stops new opens, but
/// not a handle another user opened while it was readable, which would go
/// on reading every capture written after; the copy is a new file such a
/// handle doesn't reach. As one others could open may have come from
/// anywhere, its schema and integrity are checked first. A database another
/// process has open isn't replaced, since that process would go on writing
/// to the old file. Nor is one on a filesystem that shows the copy open to
/// others too, which the copy wouldn't improve: that's found first, by
/// making the copy's file, since the checks need the only connection and
/// would otherwise refuse this open whenever another process reads the
/// database.
fn replace_with_owner_only_copy(db_path: &Path) -> Result<bool, OpenError> {
    let copy_path = capture_file(db_path, "-copy");
    // Taken before anything is opened, as leaving WAL grows the database.
    let needed = room_to_copy(db_path);
    let owner_only = create_owner_only(&copy_path);
    #[cfg(test)]
    let owner_only = tests::COPY_CREATE_ERROR
        .get()
        .map_or(owner_only, |kind| Err(kind.into()));
    if !matches!(owner_only, Ok(true)) {
        let removed = remove_replacement_copy(db_path);
        if let Err(error) = owner_only {
            return Err(if error.kind() == std::io::ErrorKind::StorageFull {
                no_room_to_copy(db_path, needed)
            } else {
                error.into()
            });
        }
        removed?;
        return Ok(false);
    }
    let checked = match copy_checked_database(db_path, &copy_path, needed) {
        Ok(checked) => checked,
        Err(error) => {
            if let Err(removal) = remove_replacement_copy(db_path) {
                tracing::warn!(
                    "could not remove {}: {removal}",
                    capture_file(db_path, "-copy").display()
                );
            }
            return Err(error);
        }
    };
    #[cfg(test)]
    if let Some(attach) = tests::AFTER_COPY.with_borrow_mut(Option::take) {
        attach();
    }
    for suffix in SQLITE_SIDECARS {
        remove_if_present(&capture_file(db_path, suffix))?;
    }
    std::fs::rename(&copy_path, db_path).map_err(|error| with_path(db_path, error))?;
    // Only now may another connection, as an earlier release's or another
    // tool's that opened the database meanwhile, take a lock on it; SQLite
    // then refuses its writes to a database moved aside.
    drop(checked);
    #[cfg(test)]
    if let Some(look) = tests::AFTER_RENAME.with_borrow_mut(Option::take) {
        look();
    }
    Ok(true)
}

/// Checks a database others could open, and copies it into the owner-only
/// file made for the copy, returning the connection that checked it, which
/// holds the database's exclusive lock until it's dropped: a connection
/// that attaches meanwhile, as an earlier release or another tool can
/// without the opening lock, can't commit a capture the copy lacks. A check
/// that fails leaves the WAL files its connection made: they hold no
/// captures, SQLite removes them as the last connection closes, and such a
/// connection may be using them.
fn copy_checked_database(
    db_path: &Path,
    copy_path: &Path,
    needed: Option<u64>,
) -> Result<Connection, OpenError> {
    ensure_room_to_copy(db_path, needed)?;
    #[cfg(test)]
    if let Some(attach) = tests::BEFORE_CHECK.with_borrow_mut(Option::take) {
        attach();
    }
    let database = open_nofollow_connection(db_path).map_err(checking(db_path, needed))?;
    refuse_unknown_schema(&database, db_path, checking(db_path, needed))?;
    // In WAL, which every LPM connection uses, leaving it needs the only
    // connection, so it proves no other LPM process has the database open,
    // and folds the WAL into the file. In exclusive locking mode, the lock
    // that takes is kept until the connection closes.
    database
        .pragma_update(None, "locking_mode", "EXCLUSIVE")
        .map_err(checking(db_path, needed))?;
    match database.query_row("PRAGMA journal_mode=DELETE", [], |row| {
        row.get::<_, String>(0)
    }) {
        Ok(mode) if mode.eq_ignore_ascii_case("delete") => {}
        Ok(_) => return Err(in_use(db_path)),
        Err(error) if is_busy(&error) => return Err(in_use(db_path)),
        Err(error) => return Err(checking(db_path, needed)(error)),
    }
    refuse_damage(&database, db_path)?;
    copy_database(&database, copy_path, db_path, needed)?;
    Ok(database)
}

/// Reads a full disk while the database is checked as the copy's want of
/// room, and any other failure as [`damaged`] does.
fn checking(db_path: &Path, needed: Option<u64>) -> impl Fn(rusqlite::Error) -> OpenError + '_ {
    move |error| {
        if out_of_room(&error) {
            no_room_to_copy(db_path, needed)
        } else {
            damaged(db_path)(error)
        }
    }
}

/// Whether SQLite failed for want of disk space: a full disk, or a
/// shared-memory file it couldn't grow, which is how a disk with less free
/// than the file's next 32 KiB fails an open.
fn out_of_room(error: &rusqlite::Error) -> bool {
    match error {
        rusqlite::Error::SqliteFailure(failure, _) => {
            failure.code == rusqlite::ErrorCode::DiskFull
                || failure.extended_code == rusqlite::ffi::SQLITE_IOERR_SHMSIZE
        }
        _ => false,
    }
}

/// The room SQLite's shared-memory file takes while the check reads a
/// database with `wal` bytes of WAL in pages of `page_size`: the WAL index
/// keeps a 32 KiB region for each 4,096 frames, the first region 4,062,
/// and a region more is counted for rounding.
fn shared_memory_room(wal: u64, page_size: u64) -> u64 {
    const REGION: u64 = 32 * 1024;
    const WAL_HEADER: u64 = 32;
    const FRAME_HEADER: u64 = 24;
    let frames = wal.saturating_sub(WAL_HEADER) / (page_size + FRAME_HEADER);
    let regions = 1 + frames.saturating_sub(4062).div_ceil(4096);
    (regions + 1) * REGION
}

/// The size of the pages the WAL beside `db_path` holds, from its header;
/// where it doesn't read as one, SQLite's smallest, 512 bytes, which counts
/// the most frames in a WAL. The database's own header isn't read: an
/// empty or missing WAL holds no frames, so its page size counts for
/// nothing, and closing a handle of this process's on the database would
/// release the locks SQLite holds on it here.
fn page_size(db_path: &Path) -> u64 {
    let mut wal = [0; 12];
    let read = lpm_common::open_nofollow(&capture_file(db_path, "-wal"))
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut wal));
    if read.is_ok()
        && matches!(
            u32::from_be_bytes([wal[0], wal[1], wal[2], wal[3]]),
            0x377f_0682 | 0x377f_0683
        )
    {
        let size = u64::from(u32::from_be_bytes([wal[8], wal[9], wal[10], wal[11]]));
        if size.is_power_of_two() && (512..=65_536).contains(&size) {
            return size;
        }
    }
    512
}

/// The free space replacing a database takes. Leaving WAL folds the WAL into
/// the database, which grows by the WAL at most while the shared-memory file
/// is open; then the WAL and that file are removed, and the copy takes the
/// grown database's size. So it never takes more than the database and its
/// WAL, with the shared-memory file on top.
fn room_to_copy(db_path: &Path) -> Option<u64> {
    let database = std::fs::metadata(db_path).ok()?.len();
    let wal = std::fs::metadata(capture_file(db_path, "-wal")).map_or(0, |wal| wal.len());
    Some(
        database
            .saturating_add(wal)
            .saturating_add(shared_memory_room(wal, page_size(db_path))),
    )
}

/// Refuses a replacement its disk can't hold before the database is
/// opened, as SQLite's own failure on a full disk can come as a bare I/O
/// error.
fn ensure_room_to_copy(db_path: &Path, needed: Option<u64>) -> Result<(), OpenError> {
    let available = lpm_common::filesystem_writable_bytes(db_path);
    #[cfg(test)]
    let available = tests::AVAILABLE_BYTES.get().or(available);
    match (available, needed) {
        (Some(available), Some(needed)) if available < needed => {
            Err(no_room_to_copy(db_path, Some(needed)))
        }
        _ => Ok(()),
    }
}

fn in_use(db_path: &Path) -> OpenError {
    OpenError::Files(std::io::Error::new(
        std::io::ErrorKind::ResourceBusy,
        format!(
            "{} is open to other users, and another process has it open, so it can't \
             be replaced with an owner-only copy yet; close what has it open, such as \
             `lpm tunnel inspect --ui` or other `lpm tunnel` and `lpm dev` runs in this \
             project, and retry",
            db_path.display()
        ),
    ))
}

/// Copies the database into the copy's file. A lock another connection
/// holds on the database is waited out for the busy timeout, inside the
/// copy's one step; one held past it leaves the copy unfinished, which is
/// refused rather than taken for the database. The copy takes as much
/// space as the database, free pages included, so a disk without it is
/// named as the cause.
fn copy_database(
    database: &Connection,
    copy_path: &Path,
    db_path: &Path,
    needed: Option<u64>,
) -> Result<(), OpenError> {
    let mut copy = open_nofollow_connection(copy_path)?;
    #[cfg(test)]
    if let Some(pages) = tests::COPY_PAGE_LIMIT.get() {
        copy.pragma_update(None, "max_page_count", pages)?;
    }
    let backup = rusqlite::backup::Backup::new(database, &mut copy)?;
    match backup.step(-1) {
        Ok(rusqlite::backup::StepResult::Done) => Ok(()),
        Ok(_) => Err(in_use(db_path)),
        Err(error) if out_of_room(&error) => Err(no_room_to_copy(db_path, needed)),
        Err(error) => Err(damaged(db_path)(error)),
    }
}

/// The refusal of a replacement its disk lacks room for, naming the room
/// taken before the database was opened.
fn no_room_to_copy(db_path: &Path, needed: Option<u64>) -> OpenError {
    let needed = needed.map_or_else(
        || "as much as it takes".to_owned(),
        |bytes| format!("about {}", lpm_common::format_bytes(bytes)),
    );
    OpenError::Files(std::io::Error::new(
        std::io::ErrorKind::StorageFull,
        format!(
            "{} is open to other users, and replacing it with an owner-only copy needs \
             {needed} free on its disk; free that much, or move it aside {}, and retry",
            db_path.display(),
            with_its_sidecars(db_path)
        ),
    ))
}

/// Refuses a database SQLite finds damaged, in its pages and records or in
/// its full-text index, whose damage a crafted file could aim at SQLite's
/// full-text code: `quick_check` runs the index's own check too.
fn refuse_damage(connection: &Connection, db_path: &Path) -> Result<(), OpenError> {
    let pages: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(damaged(db_path))?;
    if pages != "ok" {
        return Err(OpenError::Damaged {
            path: db_path.to_path_buf(),
            detail: lpm_common::sanitize_terminal_inline(&pages).into_owned(),
        });
    }
    Ok(())
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
            .map_err(|error| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(with_path(directory, error)))
            })?
            .join(path.file_name().unwrap_or(path.as_os_str()))
    };
    Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::default() | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
}

/// What every capture connection has. A database from a repository or
/// another tool can't run schema code with side effects, write SQLite's
/// internal tables, or have SQLite build a value larger than
/// [`LONGEST_VALUE_BYTES`]; SQLite checks each page's cells as it reads
/// them; deleted captures are overwritten, not left in free pages; and a
/// busy database is waited for.
fn harden_connection(connection: &Connection) -> Result<(), rusqlite::Error> {
    use rusqlite::config::DbConfig;
    use rusqlite::limits::Limit;

    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, LONGEST_VALUE_BYTES)?;
    connection.busy_timeout(busy_timeout())?;
    connection.execute_batch("PRAGMA cell_size_check=ON; PRAGMA secure_delete=ON;")
}

/// Opens a capture connection in WAL, with `synchronous` as its sync level.
fn open_capture_connection(path: &Path, synchronous: &str) -> Result<Connection, rusqlite::Error> {
    let connection = connect_nofollow(path)?;
    configure_connection(&connection, synchronous)?;
    Ok(connection)
}

/// Configures a capture connection. Switching it to WAL opens the WAL and
/// its shared memory, by name, under the identity the open holds
/// ([`CaptureOwner`]); the connection keeps them open.
fn configure_connection(connection: &Connection, synchronous: &str) -> Result<(), rusqlite::Error> {
    harden_connection(connection)?;
    use_wal(connection)?;
    connection.execute_batch(&format!(
        "PRAGMA synchronous={synchronous}; PRAGMA foreign_keys=ON;"
    ))
}

/// Keeps the WAL and its shared memory when the last connection closes,
/// the WAL emptied rather than removed, for a connection root opened as the
/// capture owner: SQLite removes them by name, which by then can lead
/// anywhere the owner points it.
fn keep_wal_files(connection: &Connection) -> Result<(), rusqlite::Error> {
    let mut persist: std::ffi::c_int = 1;
    // SAFETY: the handle is this open connection's, the database name is
    // NUL-terminated, and SQLite reads and writes the int only during the
    // call.
    let code = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            (&raw mut persist).cast(),
        )
    };
    if code != rusqlite::ffi::SQLITE_OK {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            Some("SQLite can't keep the WAL file".to_owned()),
        ));
    }
    connection.execute_batch("PRAGMA journal_size_limit=0;")
}

/// Switches the database to WAL. Connections switching a new database at
/// once can get SQLITE_BUSY without the busy timeout being waited, so the
/// switch is retried, a jittered few milliseconds apart, until it passes.
fn use_wal(connection: &Connection) -> Result<(), rusqlite::Error> {
    use rand::Rng as _;

    let deadline = std::time::Instant::now() + busy_timeout();
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

/// A schema object as SQLite stores it: its type, name, table and SQL, the
/// SQL in its [`canonical_sql`] form.
type SchemaObject = (String, String, String, Option<String>);

/// SQL as SQLite tokenizes it, for comparing schema text. Whitespace next
/// to a parenthesis or a comma, which are tokens of their own, is dropped,
/// so the text an `ALTER TABLE` splices in reads the same however it's
/// spaced; any other run of whitespace reads as one space, as it may part
/// two tokens that would otherwise read as one (`< =` and `<=`). Quoted
/// text, a string or a quoted name, and comments are kept as written, a
/// line comment with the newline that ends it. Whitespace is SQLite's own:
/// ASCII space, tab, newline, form feed and carriage return. So schema text
/// whose tokens differ for SQLite can't read the same here, but for one
/// case: a parameter's Tcl form, `$x(y)` and its `@`, `:` and `#` kin, takes
/// a parenthesis into its token, so it reads the same as `$x (y)`. SQLite
/// creates no schema with a parameter, but a crafted file's schema can hold
/// one; LPM's schema has none of those characters outside quotes, so such
/// text never reads as LPM's.
fn canonical_sql(sql: &str) -> String {
    let separates = |character: char| matches!(character, '(' | ')' | ',');
    let mut canonical = String::with_capacity(sql.len());
    let mut spaced = false;
    let mut characters = sql.chars().peekable();
    while let Some(character) = characters.next() {
        if matches!(character, ' ' | '\t' | '\n' | '\x0c' | '\r') {
            spaced = true;
            continue;
        }
        if spaced
            && !canonical.is_empty()
            && !canonical.ends_with(separates)
            && !separates(character)
        {
            canonical.push(' ');
        }
        spaced = false;
        canonical.push(character);
        let end = match (character, characters.peek()) {
            ('\'' | '"' | '`', _) => character.to_string(),
            ('[', _) => "]".to_owned(),
            ('-', Some('-')) => "\n".to_owned(),
            ('/', Some('*')) => {
                canonical.push('*');
                characters.next();
                "*/".to_owned()
            }
            _ => continue,
        };
        // The span's own text, so `/*/` doesn't read as a closed comment.
        let mut span = String::new();
        for kept in characters.by_ref() {
            span.push(kept);
            if span.ends_with(end.as_str()) {
                break;
            }
        }
        canonical.push_str(&span);
    }
    canonical
}

/// The database's schema objects.
fn schema_objects(connection: &Connection) -> Result<Vec<SchemaObject>, rusqlite::Error> {
    let mut statement =
        connection.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master")?;
    statement
        .query_map([], |row| {
            let sql: Option<String> = row.get(3)?;
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                sql.as_deref().map(canonical_sql),
            ))
        })?
        .collect()
}

/// LPM's own schema objects: those [`CAPTURE_SCHEMA`] creates, which a
/// database from an earlier release may hold as they are, and those after
/// [`ensure_capture_schema`] upgrades them, both built by this SQLite in
/// memory, with the statistics tables `ANALYZE` adds, which run nothing.
/// Anything else, whatever its name, is unknown: SQLite loads an object
/// named like its own from a schema it didn't write.
fn lpm_schema() -> Result<std::collections::HashSet<SchemaObject>, rusqlite::Error> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(CAPTURE_SCHEMA)?;
    let mut objects: std::collections::HashSet<_> =
        schema_objects(&connection)?.into_iter().collect();
    ensure_capture_schema(&connection)?;
    connection.execute_batch("ANALYZE")?;
    objects.extend(schema_objects(&connection)?);
    Ok(objects)
}

/// Refuses a database holding a schema object LPM never creates. One from
/// a repository or another tool could otherwise run code of its own on
/// every capture written: a trigger, or a check, default, generated column
/// or index expression that's slow by design.
fn refuse_unknown_schema(
    connection: &Connection,
    db_path: &Path,
    failed: impl Fn(rusqlite::Error) -> OpenError,
) -> Result<(), OpenError> {
    let known = lpm_schema()?;
    let unknown: Vec<String> = schema_objects(connection)
        .map_err(failed)?
        .into_iter()
        .filter(|object| !known.contains(object))
        .map(|(kind, name, _, _)| format!("{kind} {}", lpm_common::sanitize_terminal_inline(&name)))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(OpenError::Files(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "{} holds schema LPM never creates ({}); move it aside {}, and retry",
            db_path.display(),
            unknown.join(", "),
            with_its_sidecars(db_path)
        ),
    )))
}

/// Makes `.lpm/.gitignore` ignore everything in `.lpm`, as every command
/// keeps it ([`lpm_common::project_state`]), unless git already reads it so.
/// One that git wouldn't read as a file of the project's, being a link or
/// not a regular file, or that its owner keeps from being written, being
/// read-only or on Unix another user's, is left as it is; the CLI's capture
/// warning then says git doesn't ignore the captures.
fn keep_lpm_dir_ignored(lpm_dir: &Path, owner: CaptureOwner) -> std::io::Result<()> {
    let path = lpm_dir.join(lpm_common::project_state::PROJECT_STATE_IGNORE_FILE);
    match lpm_common::read_file_capped_unlinked(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
        Ok((existing, _)) if lpm_common::project_state::keeps_state_out_of_git(&existing) => {
            return Ok(());
        }
        Ok((_, metadata)) => refuse_kept_from_writing(&path, &metadata, owner)?,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {}
        Err(error) => return Err(std::io::Error::other(error)),
    }
    lpm_common::write_file_atomic_with(
        &path,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o644),
        |file| {
            std::io::Write::write_all(
                file,
                lpm_common::project_state::PROJECT_STATE_IGNORE.as_bytes(),
            )
        },
    )
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn refuse_kept_from_writing(
    path: &Path,
    metadata: &std::fs::Metadata,
    owner: CaptureOwner,
) -> std::io::Result<()> {
    #[cfg(unix)]
    let read_only = {
        use std::os::unix::fs::PermissionsExt;

        if !owner.owns(metadata) {
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
    conn.execute_batch(CAPTURE_SCHEMA)?;
    ensure_capture_schema(conn)
}

/// The capture tables and indexes, as every release has created them;
/// [`ensure_capture_schema`] upgrades them since.
const CAPTURE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sessions (
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
         );";

fn ensure_capture_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    for (table, column, definition) in [
        (
            "requests",
            "response_body_incomplete",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        ("sessions", "owner_pid", "INTEGER"),
        ("sessions", "owner_identity", "TEXT"),
    ] {
        let columns = tx
            .prepare(&format!("PRAGMA table_info({table})"))?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        if !columns.is_empty() && !columns.iter().any(|name| name == column) {
            tx.execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
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

/// Writes a batch of captures in one transaction, which takes the write
/// lock as it begins: a capture's insert reads before it writes, and a
/// transaction that only took a snapshot can't write once another
/// connection commits, such as a clear or a tag edit, where one that waited
/// for the lock writes after it.
fn flush_batch(conn: &Connection, batch: &[DbWrite]) -> Result<(), rusqlite::Error> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;

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

    /// The advice for the capture database LPM can't use.
    const ADVICE: &str = "move it aside together with any inspector.db-wal, \
                          inspector.db-shm and inspector.db-journal beside it, renamed alike \
                          with each suffix kept and left in .lpm so git goes on ignoring \
                          them, and retry";

    thread_local! {
        /// The most pages this thread's database copies may hold, as a
        /// full disk would stop them.
        pub(super) static COPY_PAGE_LIMIT: std::cell::Cell<Option<i64>> =
            const { std::cell::Cell::new(None) };
        /// How long this thread's opens wait for the lock, in place of
        /// [`OPEN_LOCK_TIMEOUT`], for a test of the wait itself.
        pub(super) static OPEN_LOCK_WAIT: std::cell::Cell<Option<std::time::Duration>> =
            const { std::cell::Cell::new(None) };
        /// How long the connections this thread opens wait for another's
        /// lock, in place of [`BUSY_TIMEOUT`].
        pub(super) static BUSY_WAIT: std::cell::Cell<Option<std::time::Duration>> =
            const { std::cell::Cell::new(None) };
        /// The free space this thread's replacements find on their disk.
        pub(super) static AVAILABLE_BYTES: std::cell::Cell<Option<u64>> =
            const { std::cell::Cell::new(None) };
        /// The failure this thread's replacement copies are created with, as
        /// a disk with no blocks left fails them.
        pub(super) static COPY_CREATE_ERROR: std::cell::Cell<Option<std::io::ErrorKind>> =
            const { std::cell::Cell::new(None) };
        /// Runs once as this thread's next replacement starts its check, as
        /// another process can open the database then.
        pub(super) static BEFORE_CHECK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
        /// Runs once after this thread's next replacement has copied the
        /// database, before the copy takes its name, as a connection
        /// without the opening lock can leave files beside it then.
        pub(super) static AFTER_COPY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
        /// Runs once after this thread's next replacement's copy takes the
        /// database's name, before anything opens it.
        pub(super) static AFTER_RENAME: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
        /// Runs once after this thread's next open has checked `.lpm`, as
        /// the project's owner can move it then.
        pub(super) static AFTER_LPM_DIR: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    #[cfg(unix)]
    thread_local! {
        /// Makes this thread's new capture files read as a filesystem
        /// without Unix modes shows them: open to anyone.
        pub(super) static MODELESS_FILESYSTEM: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        /// Makes this thread's `.lpm` read as on a volume that ignores
        /// ownership.
        pub(super) static OWNERSHIP_IGNORED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// The capture owner of a project of this user's.
    #[cfg(unix)]
    fn this_user() -> CaptureOwner {
        CaptureOwner {
            uid: lpm_common::current_uid(),
            by_root: false,
        }
    }

    const CAPTURES_IGNORED: &str = lpm_common::project_state::PROJECT_STATE_IGNORE;

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
    async fn opening_replaces_an_lpm_gitignore_that_leaves_state_tracked() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        std::fs::write(project.path().join(".lpm/.gitignore"), "skills/").unwrap();

        drop(InspectorDb::open(project.path()).unwrap());

        assert_eq!(lpm_gitignore(project.path()), CAPTURES_IGNORED);
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
    async fn opening_leaves_an_lpm_gitignore_git_reads_as_ignoring_everything() {
        for content in [
            "*\n",
            "*  \n",
            "*\r\n",
            "/*\n",
            "**\n",
            "!inspector.db\n*\n",
            "# notes\n*\n",
        ] {
            let (_project, written) = opened_with_gitignore(content.as_bytes());
            assert_eq!(written, content.as_bytes(), "{content:?}");
        }
    }

    #[tokio::test]
    async fn opening_replaces_an_lpm_gitignore_git_reads_as_tracking_some_state() {
        for content in [
            "inspector.db*\n",
            "  *\n",
            "\t*\n",
            "*\t\n",
            "*\\ \n",
            "*\n!.gitignore\n",
            "*\n!skills/\n",
            "**\n!INSPECTOR.DB\n",
            "# *\n",
            "*\r\r\n",
        ] {
            let (_project, written) = opened_with_gitignore(content.as_bytes());
            assert_eq!(written, CAPTURES_IGNORED.as_bytes(), "{content:?}");
        }
    }

    #[tokio::test]
    async fn opening_replaces_an_lpm_gitignore_that_isnt_utf8() {
        let (_project, written) = opened_with_gitignore(b"skills/\n\xff\xfe-notes\n");

        assert_eq!(written, CAPTURES_IGNORED.as_bytes());
    }

    #[tokio::test]
    async fn opening_reads_a_rule_beside_lines_that_arent_utf8() {
        let content = b"\xff\xfe\n*\n";

        let (_project, written) = opened_with_gitignore(content);

        assert_eq!(written, content);
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

        let error = refuse_kept_from_writing(&path, &metadata, this_user()).unwrap_err();

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

        let error = restrict_lpm_dir(Path::new("/usr"), this_user(), Access::Review).unwrap_err();

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

        let error =
            check_capture_file(&path, &path, &metadata, this_user(), Access::Review).unwrap_err();

        assert!(
            error.to_string().contains("belongs to another user"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn checking_a_capture_file_that_vanished_needs_nothing() {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().join("inspector.db-wal");
        std::fs::write(&path, b"").unwrap();
        set_mode(&path, 0o400);
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert!(
            !check_capture_file(&path, &path, &metadata, this_user(), Access::Capture).unwrap()
        );
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
        let db_path = lpm_dir.join("inspector.db");
        std::fs::hard_link(&served, &db_path).unwrap();

        let error = prepare_capture_files(&db_path, this_user(), Access::Capture).unwrap_err();

        assert!(error.to_string().contains("other hard links"), "{error}");
        assert!(error.to_string().ends_with(ADVICE), "{error}");
        assert_eq!(mode(&served), 0o644);

        // A sidecar with other hard links moves with its database, which an
        // open would otherwise find without it and remove.
        std::fs::remove_file(&db_path).unwrap();
        std::fs::write(&db_path, b"").unwrap();
        std::fs::hard_link(&served, lpm_dir.join("inspector.db-wal")).unwrap();

        let error = prepare_capture_files(&db_path, this_user(), Access::Capture).unwrap_err();

        assert!(
            error.to_string().ends_with(&format!(
                "move {} aside together with any inspector.db-wal, inspector.db-shm and \
                 inspector.db-journal beside it, renamed alike with each suffix kept and left \
                 in .lpm so git goes on ignoring them, and retry",
                db_path.display()
            )),
            "{error}"
        );
        assert!(lpm_dir.join("inspector.db-wal").exists());

        // Without a database, the sidecar moves alone.
        std::fs::remove_file(&db_path).unwrap();
        let error = prepare_capture_files(&db_path, this_user(), Access::Capture).unwrap_err();

        assert!(
            error.to_string().ends_with(&format!(
                "{} has other hard links, so captures written to it would change those \
                 files too; move it aside, and retry",
                lpm_dir.join("inspector.db-wal").display()
            )),
            "{error}"
        );
        assert!(lpm_dir.join("inspector.db-wal").exists());
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
            ("inspector.db-shm", 0o733),
            ("inspector.db-journal", 0o611),
        ] {
            let path = lpm_dir.join(name);
            std::fs::write(&path, b"").unwrap();
            set_mode(&path, leftover_mode);
        }

        assert!(
            !prepare_capture_files(&lpm_dir.join("inspector.db"), this_user(), Access::Capture)
                .unwrap()
        );

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

        assert!(
            prepare_capture_files(&lpm_dir.join("inspector.db"), this_user(), Access::Capture)
                .unwrap()
        );

        assert_eq!(mode(&lpm_dir.join("inspector.db-wal")), 0o604);
    }

    #[cfg(unix)]
    #[test]
    fn preparing_reads_a_capture_file_its_group_could_read_as_open_to_others() {
        let project = tempfile::tempdir().unwrap();
        let lpm_dir = project.path().join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        for (name, leftover_mode) in [("inspector.db", 0o600), ("inspector.db-shm", 0o440)] {
            let path = lpm_dir.join(name);
            std::fs::write(&path, b"").unwrap();
            set_mode(&path, leftover_mode);
        }

        assert!(
            prepare_capture_files(&lpm_dir.join("inspector.db"), this_user(), Access::Capture)
                .unwrap()
        );

        assert_eq!(mode(&lpm_dir.join("inspector.db-shm")), 0o640);
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

        assert!(
            !prepare_capture_files(&lpm_dir.join("inspector.db"), this_user(), Access::Capture)
                .unwrap()
        );

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
    fn opening_waits_to_replace_a_database_another_connection_has_open() {
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
            error.to_string().contains("another process has it open")
                && error.to_string().contains("`lpm tunnel inspect --ui`"),
            "{error}"
        );
        assert_eq!(error.kind(), std::io::ErrorKind::ResourceBusy);
        assert!(!error.to_string().contains("Move or repair"), "{error}");
        // Leaving WAL tells at once; the copy's own wait is the busy timeout.
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        assert_eq!(mode(&db_path), 0o644);
        // The open connection's WAL files aren't the refused check's to remove.
        for suffix in ["-wal", "-shm"] {
            assert!(capture_file(&db_path, suffix).exists(), "{suffix} removed");
        }
        drop(other);
        runtime.block_on(async { drop(InspectorDb::open(project.path()).unwrap()) });
        assert_eq!(mode(&db_path), 0o600);
    }

    /// Holds the lock openers take while they check, replace and open the
    /// capture files.
    fn hold_capture_lock(project: &Path) -> lpm_common::SingleFileExclusiveLockHandle {
        let file =
            lpm_common::open_lock_file_nofollow(&project.join(".lpm/inspector.db-lock")).unwrap();
        lpm_common::acquire_single_file_exclusive_lock_from_file_within(
            file,
            std::time::Duration::ZERO,
        )
        .unwrap()
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn reviewing_leaves_a_database_others_could_open_as_it_is_and_says_so() {
        use std::os::unix::fs::MetadataExt;

        let project = project_with_a_capture();
        let lpm_dir = project.path().join(".lpm");
        let db_path = lpm_dir.join("inspector.db");
        set_mode(&db_path, 0o644);
        set_mode(&lpm_dir, 0o775);
        let inode = std::fs::metadata(&db_path).unwrap().ino();
        // A process recording to it, which a writer's open would refuse to
        // replace it under.
        let recording = Connection::open(&db_path).unwrap();
        recording
            .query_row("SELECT count(*) FROM requests", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();

        let reviewing = tokio::runtime::Runtime::new().unwrap();
        let (open_to_others, kept) = reviewing.block_on(async {
            let db = InspectorDb::open_for_review(project.path()).unwrap();
            (db.open_to_others(), db.get_webhook("kept").await.unwrap())
        });
        // Shutting the runtime down closes the review's connections, as the
        // end of its process would.
        drop(reviewing);

        assert!(open_to_others);
        assert!(kept.is_some());
        assert_eq!(mode(&db_path), 0o644);
        assert_eq!(mode(&lpm_dir), 0o775);
        assert_eq!(std::fs::metadata(&db_path).unwrap().ino(), inode);
        drop(recording);
        let open_to_others = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { InspectorDb::open(project.path()).unwrap().open_to_others() });
        assert!(!open_to_others);
        assert_eq!(mode(&db_path), 0o600);
        assert_eq!(mode(&lpm_dir), 0o755);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reviewing_a_new_project_creates_an_owner_only_database() {
        let project = tempfile::tempdir().unwrap();

        let db = InspectorDb::open_for_review(project.path()).unwrap();

        assert!(!db.open_to_others());
        assert_eq!(mode(&project.path().join(".lpm/inspector.db")), 0o600);
        assert_eq!(lpm_gitignore(project.path()), CAPTURES_IGNORED);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reviewing_leaves_capture_files_others_couldnt_open_as_they_are() {
        let project = tempfile::tempdir().unwrap();
        drop(InspectorDb::open(project.path()).unwrap());
        let db_path = project.path().join(".lpm/inspector.db");
        set_mode(&db_path, 0o620);

        let db = InspectorDb::open_for_review(project.path()).unwrap();

        assert!(!db.open_to_others());
        assert_eq!(mode(&db_path), 0o620);
    }

    #[tokio::test]
    async fn every_open_removes_a_replacement_copy_left_over() {
        for open in [InspectorDb::open, InspectorDb::open_for_review] {
            let project = tempfile::tempdir().unwrap();
            let lpm_dir = project.path().join(".lpm");
            std::fs::create_dir(&lpm_dir).unwrap();
            std::fs::write(lpm_dir.join("inspector.db-copy"), b"captures").unwrap();
            std::fs::write(lpm_dir.join("inspector.db-copy-journal"), b"captures").unwrap();

            drop(open(project.path()).unwrap());

            assert!(!lpm_dir.join("inspector.db-copy").exists());
            assert!(!lpm_dir.join("inspector.db-copy-journal").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_filesystem_without_modes_keeps_its_database_and_says_it_s_open_to_others() {
        use std::os::unix::fs::MetadataExt;

        let project = project_with_a_capture();
        let db_path = project.path().join(".lpm/inspector.db");
        set_mode(&db_path, 0o644);
        let inode = std::fs::metadata(&db_path).unwrap().ino();
        let fresh = tempfile::tempdir().unwrap();
        MODELESS_FILESYSTEM.set(true);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (existing, ownership_ignored, kept, new) = runtime.block_on(async {
            let db = InspectorDb::open(project.path()).unwrap();
            let kept = db.get_webhook("kept").await.unwrap();
            let new = InspectorDb::open(fresh.path()).unwrap().open_to_others();
            (db.open_to_others(), db.ownership_ignored(), kept, new)
        });
        MODELESS_FILESYSTEM.set(false);

        assert!(existing);
        assert!(!ownership_ignored);
        assert!(new);
        assert!(kept.is_some());
        assert_eq!(std::fs::metadata(&db_path).unwrap().ino(), inode);
        assert!(!project.path().join(".lpm/inspector.db-copy").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_volume_that_ignores_ownership_keeps_its_database_and_says_it_s_open_to_others() {
        use std::os::unix::fs::MetadataExt;

        let project = project_with_a_capture();
        let db_path = project.path().join(".lpm/inspector.db");
        set_mode(&db_path, 0o644);
        let inode = std::fs::metadata(&db_path).unwrap().ino();
        let fresh = tempfile::tempdir().unwrap();
        let owner_only = project_with_a_capture();
        assert_eq!(mode(&owner_only.path().join(".lpm/inspector.db")), 0o600);
        OWNERSHIP_IGNORED.set(true);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (reviewed, existing, kept, new) = runtime.block_on(async {
            let reviewed = InspectorDb::open_for_review(owner_only.path()).unwrap();
            let review = InspectorDb::open_for_review(project.path()).unwrap();
            let db = InspectorDb::open(project.path()).unwrap();
            let kept = db.get_webhook("kept").await.unwrap();
            let new = InspectorDb::open(fresh.path()).unwrap();
            drop(review);
            let state = |db: &InspectorDb| (db.open_to_others(), db.ownership_ignored());
            (state(&reviewed), state(&db), kept, state(&new))
        });
        OWNERSHIP_IGNORED.set(false);

        assert_eq!(reviewed, (true, true));
        assert_eq!(existing, (true, true));
        assert_eq!(new, (true, true));
        assert!(kept.is_some());
        assert_eq!(std::fs::metadata(&db_path).unwrap().ino(), inode);
        assert!(!project.path().join(".lpm/inspector.db-copy").exists());
    }

    /// Attaches a new HFS+ image of `size` in `directory`, keeping or
    /// ignoring ownership on it.
    #[cfg(target_os = "macos")]
    fn attach_image(
        directory: &Path,
        size: &str,
        owners: bool,
    ) -> lpm_common::test_disk_image::AttachedImage {
        let mount_point = directory.join("mounted");
        std::fs::create_dir(&mount_point).unwrap();
        lpm_common::test_disk_image::AttachedImage::new(
            &directory.join("volume.dmg"),
            &mount_point,
            &["-size", size, "-fs", "HFS+", "-volname", "lpm-inspect-test"],
            &["-owners", if owners { "on" } else { "off" }],
        )
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_project_on_a_volume_mounted_without_owners_keeps_captures_and_says_they_re_open_to_others()
    {
        let directory = tempfile::tempdir().unwrap();
        let attached = attach_image(directory.path(), "8m", false);
        let project = attached.path().join("project");
        std::fs::create_dir(&project).unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (created, reopened, kept) = runtime.block_on(async {
            let db = InspectorDb::open(&project).unwrap();
            db.insert_durable_request(Arc::new(make_webhook("kept", 200)), None)
                .await
                .unwrap();
            let created = (db.open_to_others(), db.ownership_ignored());
            drop(db);
            let db = InspectorDb::open(&project).unwrap();
            let kept = db.get_webhook("kept").await.unwrap();
            (created, (db.open_to_others(), db.ownership_ignored()), kept)
        });
        drop(runtime);

        assert_eq!(created, (true, true));
        assert_eq!(reopened, (true, true));
        assert!(kept.is_some());
        assert!(!project.join(".lpm/inspector.db-copy").exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_disk_that_fills_while_the_database_is_checked_says_how_much_room_the_copy_needs() {
        let directory = tempfile::tempdir().unwrap();
        // Room for the retry, which the WAL folded in has grown.
        let attached = attach_image(directory.path(), "16m", true);
        let project = attached.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = InspectorDb::open(&project).unwrap();
            db.insert_durable_request(Arc::new(make_webhook("kept", 200)), None)
                .await
                .unwrap();
        });
        drop(runtime);
        let db_path = project.join(".lpm/inspector.db");
        // A WAL that leaving WAL has to fold into the database, which the
        // disk then has no room for.
        let writer = Connection::open(&db_path).unwrap();
        writer
            .set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )
            .unwrap();
        writer.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        writer
            .execute(
                "INSERT INTO requests (id, timestamp, method, path, request_body) \
                 VALUES ('bulk', '2026-04-06T12:00:00Z', 'POST', '/', zeroblob(600000))",
                [],
            )
            .unwrap();
        drop(writer);
        set_mode(&db_path, 0o644);
        let needed = room_to_copy(&db_path).unwrap();
        let filler = attached.path().join("filler");
        let free = lpm_common::filesystem_available_bytes(attached.path()).unwrap();
        std::fs::write(
            &filler,
            vec![0; usize::try_from(free - 200 * 1024).unwrap()],
        )
        .unwrap();

        AVAILABLE_BYTES.set(Some(u64::MAX));
        let full = InspectorDb::open(&project).map(drop);
        AVAILABLE_BYTES.set(None);

        let error = full.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull, "{error}");
        // The room taken before the WAL was folded in, which grew the database.
        let named = format!("needs about {} free", lpm_common::format_bytes(needed));
        assert!(error.to_string().contains(&named), "{error}");
        assert!(
            error
                .to_string()
                .ends_with(&format!("free that much, or {ADVICE}")),
            "{error}"
        );
        assert_eq!(mode(&db_path), 0o644);
        assert!(!capture_file(&db_path, "-copy").exists());

        std::fs::remove_file(&filler).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let kept = runtime.block_on(async {
            let db = InspectorDb::open(&project).unwrap();
            db.get_webhook("kept").await.unwrap()
        });
        assert!(kept.is_some());
        assert_eq!(mode(&db_path), 0o600);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_disk_too_full_for_the_check_s_shared_memory_says_how_much_room_the_copy_needs() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        // Room for the retry, which the WAL folded in has grown.
        let attached = attach_image(directory.path(), "16m", true);
        let project = attached.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = InspectorDb::open(&project).unwrap();
            db.insert_durable_request(Arc::new(make_webhook("kept", 200)), None)
                .await
                .unwrap();
        });
        drop(runtime);
        let db_path = project.join(".lpm/inspector.db");
        set_mode(&db_path, 0o644);
        // Room for the copy's empty file, but not for SQLite's first 32 KiB
        // of shared memory, which the check's first read sizes.
        let mut filler = std::fs::File::create(attached.path().join("filler")).unwrap();
        while filler.write_all(&[0; 4096]).is_ok() {}
        let filled = filler.metadata().unwrap().len();
        filler.set_len(filled - 8 * 1024).unwrap();
        drop(filler);

        AVAILABLE_BYTES.set(Some(u64::MAX));
        let full = InspectorDb::open(&project).map(drop);
        AVAILABLE_BYTES.set(None);

        let error = full.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull, "{error}");
        assert!(error.to_string().contains("free on its disk"), "{error}");
        assert_eq!(mode(&db_path), 0o644);
        assert!(!capture_file(&db_path, "-copy").exists());
        // What the check's connection left holds no captures.
        let wal = capture_file(&db_path, "-wal");
        assert!(!wal.exists() || std::fs::metadata(&wal).unwrap().len() == 0);

        std::fs::remove_file(attached.path().join("filler")).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let kept = runtime.block_on(async {
            let db = InspectorDb::open(&project).unwrap();
            db.get_webhook("kept").await.unwrap()
        });
        assert!(kept.is_some());
        assert_eq!(mode(&db_path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_connection_that_attaches_during_the_check_keeps_its_wal_files() {
        let project = project_with_a_capture();
        let db_path = project.path().join(".lpm/inspector.db");
        set_mode(&db_path, 0o644);
        // As an earlier release, which takes no opening lock, or another
        // tool can, once the room was taken and before the check opens it.
        let other = std::rc::Rc::new(std::cell::RefCell::new(None));
        let held = std::rc::Rc::clone(&other);
        let path = db_path.clone();
        BEFORE_CHECK.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move || {
                let connection = Connection::open(&path).unwrap();
                connection
                    .query_row("SELECT count(*) FROM requests", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap();
                *held.borrow_mut() = Some(connection);
            }));
        });
        let runtime = tokio::runtime::Runtime::new().unwrap();

        let error = runtime
            .block_on(async { InspectorDb::open(project.path()).map(drop) })
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::ResourceBusy, "{error}");
        for suffix in ["-wal", "-shm"] {
            assert!(capture_file(&db_path, suffix).exists(), "{suffix} removed");
        }
        let connection = other.borrow_mut().take().unwrap();
        connection
            .execute(
                "INSERT INTO requests (id, timestamp, method, path) \
                 VALUES ('later', '2026-04-06T12:00:00Z', 'POST', '/')",
                [],
            )
            .unwrap();
        let reader = Connection::open(&db_path).unwrap();
        let later: i64 = reader
            .query_row(
                "SELECT count(*) FROM requests WHERE id = 'later'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop((connection, reader));
        assert_eq!(later, 1);
        let integrity: String = Connection::open(&db_path)
            .unwrap()
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
    }

    /// Commits a capture `id` as a connection of an earlier release, which
    /// takes no opening lock, would, giving up at once on a lock.
    fn commit_unlocked(connection: &Connection, id: &str) -> rusqlite::Result<()> {
        connection.busy_timeout(std::time::Duration::ZERO)?;
        let _ = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get::<_, String>(0));
        connection
            .execute(
                "INSERT INTO requests (id, timestamp, method, path) \
                 VALUES (?1, '2026-04-06T12:00:00Z', 'POST', '/')",
                [id],
            )
            .map(drop)
    }

    #[cfg(unix)]
    fn capture_ids(db_path: &Path) -> Vec<String> {
        let reader = Connection::open(db_path).unwrap();
        let mut statement = reader
            .prepare("SELECT id FROM requests ORDER BY id")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn a_user_s_own_captures_leave_no_wal_files_once_closed() {
        let project = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let db = InspectorDb::open(project.path()).unwrap();
            assert!(!keeps_wal_files(&*db.write_conn.lock().await));
            assert!(!keeps_wal_files(&*db.read_conn.lock().await));
            assert!(!keeps_wal_files(&db.control_conn.lock().unwrap()));
        });
        drop(runtime);

        let db_path = project.path().join(".lpm/inspector.db");
        assert!(db_path.exists());
        assert!(!capture_file(&db_path, "-wal").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_capture_committed_while_the_database_is_replaced_is_refused_not_lost() {
        let project = project_with_a_capture();
        let db_path = project.path().join(".lpm/inspector.db");
        set_mode(&db_path, 0o644);
        let during = std::rc::Rc::new(std::cell::Cell::new(None));
        let committed = std::rc::Rc::clone(&during);
        let other = std::rc::Rc::new(std::cell::RefCell::new(None));
        let held = std::rc::Rc::clone(&other);
        let path = db_path.clone();
        AFTER_COPY.set(Some(Box::new(move || {
            let connection = Connection::open(&path).unwrap();
            committed.set(Some(commit_unlocked(&connection, "during").is_ok()));
            *held.borrow_mut() = Some(connection);
        })));
        let runtime = tokio::runtime::Runtime::new().unwrap();

        runtime
            .block_on(async { InspectorDb::open(project.path()).map(drop) })
            .unwrap();
        drop(runtime);
        // The connection opened while the copy took the database's place
        // still has the database it replaced.
        let late = commit_unlocked(&other.borrow_mut().take().unwrap(), "late");

        let ids = capture_ids(&db_path);
        let during = during.get().unwrap();
        assert!(!during || ids.contains(&"during".to_owned()), "{ids:?}");
        assert!(late.is_err() || ids.contains(&"late".to_owned()), "{ids:?}");
        assert!(ids.contains(&"kept".to_owned()), "{ids:?}");
        assert_eq!(mode(&db_path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_project_others_can_change_the_path_to_keeps_no_captures() {
        let directory = tempfile::tempdir().unwrap();
        let shared = directory.path().join("shared");
        let project = shared.join("project");
        std::fs::create_dir_all(&project).unwrap();
        set_mode(&shared, 0o777);
        let runtime = tokio::runtime::Runtime::new().unwrap();

        for opened in [
            runtime.block_on(async { InspectorDb::open(&project).map(drop) }),
            runtime.block_on(async { InspectorDb::open_for_review(&project).map(drop) }),
        ] {
            let error = opened.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            let message = error.to_string();
            assert!(
                message.contains(&shared.canonicalize().unwrap().display().to_string())
                    && message.contains("anyone may write to it"),
                "{message}"
            );
        }
        assert!(!project.join(".lpm").exists());

        set_mode(&shared, 0o1777);
        runtime
            .block_on(async { InspectorDb::open(&project).map(drop) })
            .unwrap();
        set_mode(&shared, 0o755);
        set_mode(&project, 0o777);
        let error = runtime
            .block_on(async { InspectorDb::open(&project).map(drop) })
            .unwrap_err();
        assert!(
            error.to_string().contains("anyone may write to it"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_filesystem_without_modes_lets_a_capture_open_while_a_review_has_the_database_open() {
        let project = project_with_a_capture();
        set_mode(&project.path().join(".lpm/inspector.db"), 0o644);
        MODELESS_FILESYSTEM.set(true);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let opened = runtime.block_on(async {
            let review = InspectorDb::open_for_review(project.path()).unwrap();
            let opened = InspectorDb::open(project.path()).map(|db| db.open_to_others());
            drop(review);
            opened
        });
        MODELESS_FILESYSTEM.set(false);

        assert!(matches!(opened, Ok(true)), "got {opened:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_capture_owner_owns_only_its_own_files_even_when_root_opens_them() {
        let directory = tempfile::tempdir().unwrap();
        let mine = std::fs::symlink_metadata(directory.path()).unwrap();
        let roots = std::fs::symlink_metadata("/").unwrap();
        for by_root in [false, true] {
            let me = CaptureOwner {
                uid: lpm_common::current_uid(),
                by_root,
            };
            let another = CaptureOwner {
                uid: lpm_common::current_uid() + 1,
                by_root,
            };

            assert!(me.owns(&mine));
            assert!(!another.owns(&mine));
            assert_eq!(me.owns(&roots), lpm_common::current_uid() == 0);
        }
    }

    /// A project, and a directory beside it, as root makes them: the project
    /// given to [`PROJECT_OWNER`], the other root's own.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn another_user_s_project_beside_root_s_directory() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        set_mode(root.path(), 0o755);
        let project = root.path().join("project");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::chown(&project, Some(PROJECT_OWNER), Some(PROJECT_GROUP)).unwrap();
        (root, project, elsewhere)
    }

    /// A user other than root, whose projects root's tests open, and the
    /// group of those projects: the user database knows neither, as a
    /// container's doesn't know the host's users.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    const PROJECT_OWNER: u32 = 65_000;
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    const PROJECT_GROUP: u32 = 65_001;

    /// Whether SQLite keeps `connection`'s WAL files when it closes.
    fn keeps_wal_files(connection: &Connection) -> bool {
        let mut persist: std::ffi::c_int = -1;
        // SAFETY: as in `keep_wal_files`; -1 only asks the setting.
        let code = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                (&raw mut persist).cast(),
            )
        };
        assert_eq!(code, rusqlite::ffi::SQLITE_OK);
        persist == 1
    }

    /// The owner and group of each of `project`'s capture files.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn capture_owners(project: &Path) -> Vec<(String, (u32, u32))> {
        use std::os::unix::fs::MetadataExt;

        let lpm_dir = project.join(".lpm");
        [
            "",
            "inspector.db",
            "inspector.db-wal",
            "inspector.db-shm",
            "inspector.db-lock",
            ".gitignore",
        ]
        .into_iter()
        .map(|name| {
            let metadata = std::fs::metadata(lpm_dir.join(name)).unwrap();
            (name.to_owned(), (metadata.uid(), metadata.gid()))
        })
        .collect()
    }

    /// Runs only as root, as in the root container the gate runs Linux
    /// tests in once more; CI's runner isn't root.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn as_root_another_user_s_captures_are_made_and_kept_as_that_user_s() {
        if lpm_common::current_uid() != 0 {
            return;
        }
        let (_root, project, _) = another_user_s_project_beside_root_s_directory();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let db = InspectorDb::open(&project).unwrap();
            assert!(keeps_wal_files(&*db.write_conn.lock().await));
            assert!(keeps_wal_files(&*db.read_conn.lock().await));
            assert!(keeps_wal_files(&db.control_conn.lock().unwrap()));
            drop(db);
            drop(InspectorDb::open_for_review(&project).unwrap());
        });
        // The connections close as the flush task ends.
        drop(runtime);

        let lpm_dir = project.join(".lpm");
        for (name, owners) in capture_owners(&project) {
            assert_eq!(owners, (PROJECT_OWNER, PROJECT_GROUP), "{name}");
        }
        assert_eq!(
            std::fs::metadata(lpm_dir.join("inspector.db-wal"))
                .unwrap()
                .len(),
            0
        );
        assert_eq!(lpm_common::thread_identity::filesystem_uid(), 0);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn as_root_another_user_moving_lpm_while_it_opens_can_t_have_root_write_elsewhere() {
        if lpm_common::current_uid() != 0 {
            return;
        }
        let (_root, project, elsewhere) = another_user_s_project_beside_root_s_directory();
        for name in ["inspector.db-copy", "inspector.db-wal"] {
            std::fs::write(elsewhere.join(name), b"root's").unwrap();
        }
        let lpm_dir = project.join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        std::os::unix::fs::chown(&lpm_dir, Some(PROJECT_OWNER), Some(PROJECT_OWNER)).unwrap();
        let moved = project.join("moved");
        let link = elsewhere.clone();
        AFTER_LPM_DIR.set(Some(Box::new(move || {
            std::fs::rename(&lpm_dir, &moved).unwrap();
            std::os::unix::fs::symlink(&link, &lpm_dir).unwrap();
        })));

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let opened = runtime.block_on(async { InspectorDb::open(&project).map(drop) });

        assert!(opened.is_err());
        let mut names: Vec<_> = std::fs::read_dir(&elsewhere)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["inspector.db-copy", "inspector.db-wal"]);
        for name in names {
            assert_eq!(std::fs::read(elsewhere.join(name)).unwrap(), b"root's");
        }
        assert_eq!(lpm_common::thread_identity::filesystem_uid(), 0);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn as_root_a_project_of_root_s_group_has_its_captures_in_no_group() {
        if lpm_common::current_uid() != 0 {
            return;
        }
        let (_root, project, _) = another_user_s_project_beside_root_s_directory();
        std::os::unix::fs::chown(&project, None, Some(0)).unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async { drop(InspectorDb::open(&project).unwrap()) });
        drop(runtime);

        for (name, owners) in capture_owners(&project) {
            assert_eq!(owners, (PROJECT_OWNER, 65_534), "{name}");
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn as_root_the_capture_files_root_made_in_its_own_lpm_are_given_to_the_project_s_owner() {
        if lpm_common::current_uid() != 0 {
            return;
        }
        let (_root, project, _) = another_user_s_project_beside_root_s_directory();
        // As root makes them in a project of its own, before the project
        // is given to its user.
        std::os::unix::fs::chown(&project, Some(0), Some(0)).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let db = InspectorDb::open(&project).unwrap();
            db.insert_durable_request(Arc::new(make_webhook("kept", 200)), None)
                .await
                .unwrap();
        });
        drop(runtime);
        std::os::unix::fs::chown(&project, Some(PROJECT_OWNER), Some(PROJECT_GROUP)).unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let kept = runtime.block_on(async {
            InspectorDb::open(&project)
                .unwrap()
                .get_webhook("kept")
                .await
                .unwrap()
        });
        drop(runtime);

        assert!(kept.is_some());
        for (name, owners) in capture_owners(&project) {
            assert_eq!(owners, (PROJECT_OWNER, PROJECT_GROUP), "{name}");
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn as_root_a_capture_file_of_root_s_in_the_owner_s_lpm_is_refused_by_name() {
        use std::os::unix::fs::MetadataExt;

        if lpm_common::current_uid() != 0 {
            return;
        }
        let (_root, project, _) = another_user_s_project_beside_root_s_directory();
        let lpm_dir = project.join(".lpm");
        std::fs::create_dir(&lpm_dir).unwrap();
        set_mode(&lpm_dir, 0o700);
        std::fs::write(lpm_dir.join("inspector.db"), b"").unwrap();
        set_mode(&lpm_dir.join("inspector.db"), 0o600);
        std::os::unix::fs::chown(&lpm_dir, Some(PROJECT_OWNER), Some(PROJECT_GROUP)).unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime
            .block_on(async { InspectorDb::open(&project).map(drop) })
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let message = error.to_string();
        assert!(
            message.contains(&format!(
                "{} belongs to root",
                lpm_dir.join("inspector.db").display()
            )) && message.contains("chown 65000"),
            "{message}"
        );
        assert_eq!(
            std::fs::metadata(lpm_dir.join("inspector.db"))
                .unwrap()
                .uid(),
            0
        );
        assert_eq!(lpm_common::thread_identity::filesystem_uid(), 0);
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn as_root_its_own_project_others_may_write_to_keeps_no_captures() {
        if lpm_common::current_uid() != 0 {
            return;
        }
        let (_root, project, _) = another_user_s_project_beside_root_s_directory();
        std::os::unix::fs::chown(&project, Some(0), Some(0)).unwrap();
        set_mode(&project, 0o777);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime
            .block_on(async { InspectorDb::open(&project).map(drop) })
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            error.to_string().contains("anyone may write to it"),
            "{error}"
        );
        assert!(!project.join(".lpm").exists());
    }

    #[cfg(target_os = "macos")]
    fn add_acl_entry(path: &Path, entry: &str) {
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", entry])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "macos")]
    fn has_acl(path: &Path) -> bool {
        lpm_common::macos_acl::has_extended_acl_at(path).unwrap()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_capture_file_with_an_extended_acl_is_open_to_others() {
        use std::os::unix::fs::MetadataExt;

        let project = project_with_a_capture();
        let db_path = project.path().join(".lpm/inspector.db");
        add_acl_entry(&db_path, "group:everyone allow read");
        let inode = std::fs::metadata(&db_path).unwrap().ino();

        let reviewing = tokio::runtime::Runtime::new().unwrap();
        let reviewed = reviewing.block_on(async {
            InspectorDb::open_for_review(project.path())
                .unwrap()
                .open_to_others()
        });
        drop(reviewing);
        assert!(reviewed);
        assert!(has_acl(&db_path));

        let (open_to_others, kept) = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let db = InspectorDb::open(project.path()).unwrap();
            (db.open_to_others(), db.get_webhook("kept").await.unwrap())
        });

        assert!(!open_to_others);
        assert!(kept.is_some());
        assert!(!has_acl(&db_path));
        assert_ne!(std::fs::metadata(&db_path).unwrap().ino(), inode);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn an_extended_acl_lpm_passes_on_reaches_no_capture_file() {
        const INHERITED: &str = "group:everyone allow read,write,file_inherit,directory_inherit";

        let reviewed = tempfile::tempdir().unwrap();
        let reviewed_lpm = reviewed.path().join(".lpm");
        std::fs::create_dir(&reviewed_lpm).unwrap();
        add_acl_entry(&reviewed_lpm, INHERITED);
        let db = InspectorDb::open_for_review(reviewed.path()).unwrap();
        db.rename_session("unknown", "renamed").await.unwrap();
        assert!(!db.open_to_others());
        assert!(has_acl(&reviewed_lpm));
        for name in ["inspector.db", "inspector.db-wal", "inspector.db-shm"] {
            assert!(!has_acl(&reviewed_lpm.join(name)), "{name}");
        }

        let captured = tempfile::tempdir().unwrap();
        let captured_lpm = captured.path().join(".lpm");
        std::fs::create_dir(&captured_lpm).unwrap();
        add_acl_entry(&captured_lpm, INHERITED);
        let db = InspectorDb::open(captured.path()).unwrap();
        db.insert_durable_request(Arc::new(make_webhook("kept", 200)), None)
            .await
            .unwrap();
        assert!(!db.open_to_others());
        assert!(!has_acl(&captured_lpm));
        for name in ["inspector.db", "inspector.db-wal", "inspector.db-shm"] {
            assert!(!has_acl(&captured_lpm.join(name)), "{name}");
        }
    }

    #[tokio::test]
    async fn a_capture_waits_out_another_writer_rather_than_failing() {
        let project = tempfile::tempdir().unwrap();
        let db = InspectorDb::open(project.path()).unwrap();
        let db_path = project.path().join(".lpm/inspector.db");
        let (began, holding) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let connection = Connection::open(&db_path).unwrap();
            connection
                .execute_batch("BEGIN IMMEDIATE; INSERT INTO sessions (id) VALUES ('held');")
                .unwrap();
            began.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));
            connection.execute_batch("COMMIT").unwrap();
        });
        holding.recv().unwrap();

        let inserted = db
            .insert_durable_request(Arc::new(make_webhook("kept", 200)), None)
            .await;
        holder.join().unwrap();

        assert_eq!(inserted, Ok(()));
        assert!(db.get_webhook("kept").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_batch_of_captures_waits_out_another_writer_rather_than_failing() {
        let project = tempfile::tempdir().unwrap();
        let db = InspectorDb::open(project.path()).unwrap();
        let db_path = project.path().join(".lpm/inspector.db");
        let (began, holding) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let connection = Connection::open(&db_path).unwrap();
            connection
                .execute_batch("BEGIN IMMEDIATE; INSERT INTO sessions (id) VALUES ('held');")
                .unwrap();
            began.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));
            connection.execute_batch("COMMIT").unwrap();
        });
        holding.recv().unwrap();

        db.insert_request(make_webhook("batched", 200), None);
        let flushed = db.flush_pending_writes().await;
        holder.join().unwrap();

        assert_eq!(flushed, Ok(()));
        assert!(db.get_webhook("batched").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn opening_accepts_a_database_whose_planner_statistics_were_gathered() {
        for open in [InspectorDb::open_for_review, InspectorDb::open] {
            let project = project_with_a_database(&format!(
                "{CAPTURE_SCHEMA} ALTER TABLE requests ADD COLUMN response_body_incomplete \
                 INTEGER NOT NULL DEFAULT 0; ANALYZE;"
            ));

            open(project.path()).map(drop).unwrap();
        }
    }

    /// SQL renaming the schema object `planted` to `name`, which SQLite
    /// reserves for its own and refuses to create, through the writable
    /// schema a crafted file could have been written with.
    fn named_like_sqlite(name: &str) -> String {
        format!(
            "PRAGMA writable_schema = ON; \
             UPDATE sqlite_master SET name = '{name}', sql = replace(sql, 'planted', '{name}') \
             WHERE name = 'planted'; \
             PRAGMA writable_schema = OFF;"
        )
    }

    /// A project whose capture database others could open, built by
    /// `build` on a connection that may write SQLite's own tables.
    fn project_with_a_database(build: &str) -> tempfile::TempDir {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let db_path = project.path().join(".lpm/inspector.db");
        Connection::open(&db_path)
            .unwrap()
            .execute_batch(build)
            .unwrap();
        #[cfg(unix)]
        set_mode(&db_path, 0o644);
        project
    }

    #[tokio::test]
    async fn opening_refuses_a_database_with_schema_lpm_never_creates() {
        let lpm_schema = format!(
            "{CAPTURE_SCHEMA} ALTER TABLE requests ADD COLUMN response_body_incomplete \
             INTEGER NOT NULL DEFAULT 0;"
        );
        let planted = [
            (
                "trigger copy_requests",
                format!(
                    "{lpm_schema} CREATE TRIGGER copy_requests AFTER INSERT ON requests \
                     BEGIN SELECT 1; END;"
                ),
            ),
            (
                "view recent",
                format!("{lpm_schema} CREATE VIEW recent AS SELECT * FROM requests;"),
            ),
            (
                "table requests",
                lpm_schema.replace(
                    "tags TEXT,",
                    "tags TEXT CHECK (length(hex(zeroblob(1000))) > 0),",
                ),
            ),
            (
                "table requests",
                lpm_schema.replace(
                    "tags TEXT,",
                    "tags TEXT, slow TEXT GENERATED ALWAYS AS (hex(zeroblob(1000))) VIRTUAL,",
                ),
            ),
            (
                "table sessions",
                lpm_schema.replace("name TEXT,", "name TEXT DEFAULT (hex(zeroblob(1000))),"),
            ),
            (
                "index slow_requests",
                format!(
                    "{lpm_schema} CREATE INDEX slow_requests ON requests(length(request_body));"
                ),
            ),
            (
                "index slow_index",
                format!(
                    "{lpm_schema} CREATE INDEX slow_index ON requests_fts_data(length(block));"
                ),
            ),
            (
                "table extra",
                format!("{lpm_schema} CREATE TABLE extra (x);"),
            ),
            (
                "trigger sqlite_stat_planted",
                format!(
                    "{lpm_schema} CREATE TRIGGER planted AFTER INSERT ON requests \
                     BEGIN SELECT 1; END; {}",
                    named_like_sqlite("sqlite_stat_planted")
                ),
            ),
            (
                "index sqlite_stat_planted",
                format!(
                    "{lpm_schema} CREATE INDEX planted ON requests(length(request_body)); {}",
                    named_like_sqlite("sqlite_stat_planted")
                ),
            ),
            (
                "table sessions",
                lpm_schema.replace("id TEXT PRIMARY KEY,", "id TEXT\u{a0}PRIMARY KEY,"),
            ),
            (
                "table sessions",
                lpm_schema.replacen("datetime('now')", "datetime(' now')", 1),
            ),
        ];
        for (named, build) in planted {
            for open in [InspectorDb::open, InspectorDb::open_for_review] {
                let project = project_with_a_database(&build);

                let error = open(project.path()).map(drop).unwrap_err();

                assert!(
                    error.to_string().contains("holds schema LPM never creates")
                        && error.to_string().contains(named)
                        && error.to_string().ends_with(ADVICE),
                    "{named}: {error}"
                );
                #[cfg(unix)]
                assert_eq!(
                    mode(&project.path().join(".lpm/inspector.db")),
                    0o644,
                    "{named}"
                );
            }
        }
    }

    #[tokio::test]
    async fn opening_upgrades_a_database_an_earlier_release_created() {
        let earlier = CAPTURE_SCHEMA
            .replace(
                "CREATE TABLE IF NOT EXISTS pending_sessions (
             session_id TEXT PRIMARY KEY,
             FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
         );",
                "",
            )
            .replace("\n             ", "\n\t");
        assert_ne!(earlier, CAPTURE_SCHEMA);
        // With the query planner's statistics, which a tool may have added.
        let project = project_with_a_database(&format!(
            "{earlier} INSERT INTO requests (id, timestamp, method, path) \
             VALUES ('kept', '2026-04-06T12:00:00Z', 'POST', '/'); ANALYZE;"
        ));

        let db = InspectorDb::open(project.path()).unwrap();

        assert_eq!(db.count().await.unwrap(), 1);
        let connection = Connection::open(project.path().join(".lpm/inspector.db")).unwrap();
        let tables: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'pending_sessions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 1);
        let owner_columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('sessions')
                 WHERE name IN ('owner_pid', 'owner_identity')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(owner_columns, 2);
        drop(db);
        assert_eq!(
            InspectorDb::open(project.path())
                .expect("an upgraded database must reopen")
                .count()
                .await
                .unwrap(),
            1
        );
    }

    #[test]
    fn canonical_sql_drops_the_spaces_around_parentheses_and_commas() {
        assert_eq!(
            canonical_sql("CREATE TABLE t (\n\t a  TEXT ,b\tINT )"),
            "CREATE TABLE t(a TEXT,b INT)"
        );
        assert_ne!(canonical_sql("summary TEXT"), canonical_sql("summ aryTEXT"));
        assert_eq!(
            canonical_sql("\n  CREATE TABLE t (x)\n"),
            "CREATE TABLE t(x)"
        );
    }

    #[test]
    fn canonical_sql_keeps_quoted_text_as_written() {
        for (written, respaced) in [
            ("DEFAULT (datetime('now'))", "DEFAULT (datetime(' now'))"),
            ("DEFAULT (datetime('now'))", "DEFAULT (datetime('now '))"),
            ("CREATE TABLE \"a b\" (x)", "CREATE TABLE \"a  b\" (x)"),
            ("CREATE TABLE `a b` (x)", "CREATE TABLE `a\tb` (x)"),
            ("CREATE TABLE [a b] (x)", "CREATE TABLE [a\nb] (x)"),
            ("DEFAULT ('it''s a')", "DEFAULT ('it''s  a')"),
        ] {
            assert_ne!(
                canonical_sql(written),
                canonical_sql(respaced),
                "{respaced}"
            );
        }
        assert_eq!(
            canonical_sql("DEFAULT ( 'it''s  a' ) , b"),
            "DEFAULT('it''s  a'),b"
        );
        assert_eq!(
            canonical_sql("CHECK (x IN ('a ]',  [b c] ))"),
            "CHECK(x IN('a ]',[b c]))"
        );
        assert_eq!(
            canonical_sql("CREATE TABLE [a]] b] (x)"),
            "CREATE TABLE [a]] b](x)"
        );
    }

    #[test]
    fn canonical_sql_keeps_apart_what_sqlite_reads_apart() {
        for (written, respaced) in [
            // One string against two.
            ("c 'a''b'", "c 'a' 'b'"),
            // Subtraction of a negative against a comment.
            ("DEFAULT (1 - -1)", "DEFAULT (1 --1\n)"),
            ("x <= 1", "x < = 1"),
            // A string against a blob literal.
            ("x '00'", "x'00'"),
            // A comment through the end against one ended by a newline.
            ("DEFAULT (1 --1)", "DEFAULT (1 --1\n)"),
            ("a /* x */ b", "a b"),
        ] {
            assert_ne!(
                canonical_sql(written),
                canonical_sql(respaced),
                "{written:?} against {respaced:?}"
            );
        }
        assert_eq!(
            canonical_sql("a /*/  b */  c -- d\n  e"),
            "a /*/  b */ c -- d\n e"
        );
        assert_eq!(
            canonical_sql("a /* ' */  b -- '\n  c"),
            "a /* ' */ b -- '\n c"
        );
        assert_eq!(
            canonical_sql("CREATE TABLE t (\n\t a  TEXT ,b\tINT )"),
            canonical_sql("CREATE TABLE t(a TEXT, b INT)")
        );
    }

    #[cfg(unix)]
    #[test]
    fn copying_onto_a_full_disk_says_how_much_room_the_copy_needs() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("inspector.db");
        let database = Connection::open(&db_path).unwrap();
        database
            .execute_batch("CREATE TABLE kept (x); INSERT INTO kept VALUES (zeroblob(100000));")
            .unwrap();
        let copy_path = capture_file(&db_path, "-copy");
        assert!(create_owner_only(&copy_path).unwrap());

        // The room taken before the database was opened, which this
        // database's room now would read as less.
        let needed = 3 * 1024 * 1024;
        assert!(room_to_copy(&db_path).unwrap() < needed);

        COPY_PAGE_LIMIT.set(Some(1));
        let copied = copy_database(&database, &copy_path, &db_path, Some(needed));
        COPY_PAGE_LIMIT.set(None);

        let Err(OpenError::Files(error)) = copied else {
            panic!("a full disk must stop the copy, got {copied:?}");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);
        assert!(
            error
                .to_string()
                .contains("needs about 3 MiB free on its disk"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_disk_without_room_for_the_replacement_says_so_before_the_database_is_opened() {
        let project = project_with_a_database(&format!(
            "{CAPTURE_SCHEMA} ALTER TABLE requests ADD COLUMN response_body_incomplete \
             INTEGER NOT NULL DEFAULT 0;"
        ));
        let db_path = project.path().join(".lpm/inspector.db");
        let needed = room_to_copy(&db_path).unwrap();

        BEFORE_CHECK.set(Some(Box::new(|| {})));
        AVAILABLE_BYTES.set(Some(needed - 1));
        let short = InspectorDb::open(project.path()).map(drop);
        AVAILABLE_BYTES.set(None);
        let opened = BEFORE_CHECK.with_borrow_mut(Option::take).is_none();

        let error = short.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);
        assert!(
            error.to_string().contains(&format!(
                "needs about {} free on its disk",
                lpm_common::format_bytes(needed)
            )),
            "{error}"
        );
        assert!(
            !opened,
            "the database was opened before its room was checked"
        );
        assert_eq!(mode(&db_path), 0o644);
        assert!(!capture_file(&db_path, "-copy").exists());

        AVAILABLE_BYTES.set(Some(needed));
        let enough = InspectorDb::open(project.path()).map(drop);
        AVAILABLE_BYTES.set(None);

        enough.unwrap();
        assert_eq!(mode(&db_path), 0o600);
    }

    #[test]
    fn the_room_a_replacement_needs_counts_the_wal_once_with_its_shared_memory() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("inspector.db");
        let mut database = vec![0; 10_000];
        database[16..18].copy_from_slice(&4096u16.to_be_bytes());
        std::fs::write(&db_path, &database).unwrap();
        // Without a WAL, the shared memory holds its first regions alone.
        assert_eq!(room_to_copy(&db_path), Some(10_000 + 64 * 1024));

        // 130,308 frames of the WAL's 4 KiB pages: 32 regions of the WAL
        // index, and one more. The WAL's header says what its frames hold.
        let mut wal = std::fs::File::create(capture_file(&db_path, "-wal")).unwrap();
        std::io::Write::write_all(&mut wal, &[0x37, 0x7f, 0x06, 0x82, 0, 0x2d, 0xe2, 0x18])
            .unwrap();
        std::io::Write::write_all(&mut wal, &4096u32.to_be_bytes()).unwrap();
        wal.set_len(512 * 1024 * 1024).unwrap();
        assert_eq!(
            room_to_copy(&db_path),
            Some(10_000 + 512 * 1024 * 1024 + 33 * 32 * 1024)
        );

        // A WAL without a header counts frames of SQLite's smallest pages,
        // whatever the database's own are.
        wal.set_len(0).unwrap();
        wal.set_len(512 * 1024 * 1024).unwrap();
        assert_eq!(page_size(&db_path), 512);
        assert_eq!(
            room_to_copy(&db_path),
            Some(10_000 + 512 * 1024 * 1024 + 246 * 32 * 1024)
        );

        std::fs::remove_file(&db_path).unwrap();
        assert_eq!(room_to_copy(&db_path), None);
    }

    #[test]
    fn the_room_check_counts_what_a_write_can_take_rather_than_what_is_reported_free() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("inspector.db");
        std::fs::write(&db_path, b"").unwrap();
        let available = lpm_common::filesystem_available_bytes(&db_path).unwrap();
        let writable = lpm_common::filesystem_writable_bytes(&db_path).unwrap();
        if writable >= available {
            return;
        }

        // Halfway, so other writers moving the free space by less than half
        // of what's held back don't change the answer.
        let error =
            ensure_room_to_copy(&db_path, Some(writable + (available - writable) / 2)).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull, "{error}");
    }

    #[test]
    fn the_room_for_shared_memory_follows_the_page_size_of_the_wal() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("inspector.db");
        let writer = Connection::open(&db_path).unwrap();
        writer
            .execute_batch(
                "PRAGMA page_size = 512; PRAGMA journal_mode = WAL; \
                 PRAGMA wal_autocheckpoint = 0; CREATE TABLE kept (x); BEGIN;",
            )
            .unwrap();
        for _ in 0..12_000 {
            writer
                .execute("INSERT INTO kept VALUES (zeroblob(400))", [])
                .unwrap();
        }
        writer.execute_batch("COMMIT;").unwrap();
        let wal = std::fs::metadata(capture_file(&db_path, "-wal"))
            .unwrap()
            .len();
        let shared_memory = std::fs::metadata(capture_file(&db_path, "-shm"))
            .unwrap()
            .len();

        assert_eq!(page_size(&db_path), 512);
        // Frames past the first region, which 4 KiB pages would need eight
        // times the WAL for.
        assert!(shared_memory > 32 * 1024, "{shared_memory}");
        assert!(shared_memory_room(wal, 4096) < shared_memory);
        assert!(shared_memory_room(wal, 512) >= shared_memory);
        drop(writer);
        assert_eq!(page_size(&db_path), 512);
    }

    #[test]
    fn the_page_size_comes_from_the_wal_alone() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("inspector.db");
        let writer = Connection::open(&db_path).unwrap();
        writer
            .execute_batch(
                "PRAGMA page_size = 4096; PRAGMA journal_mode = WAL; \
                 PRAGMA wal_autocheckpoint = 0; CREATE TABLE kept (x); \
                 INSERT INTO kept VALUES (1);",
            )
            .unwrap();

        assert_eq!(page_size(&db_path), 4096);
        writer
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
        assert_eq!(
            std::fs::metadata(capture_file(&db_path, "-wal"))
                .unwrap()
                .len(),
            0
        );
        // An empty WAL holds no frames; the database's 4 KiB pages aren't
        // read.
        assert_eq!(page_size(&db_path), 512);
    }

    /// Set in the child process [`reading_the_page_size_keeps_this_process_s_locks_on_the_database`]
    /// starts, to the database it tries to lock.
    #[cfg(unix)]
    const LOCKING_CHILD: &str = "LPM_INSPECT_TEST_LOCKING_CHILD";

    #[cfg(unix)]
    #[test]
    fn reading_the_page_size_keeps_this_process_s_locks_on_the_database() {
        if let Some(db_path) = std::env::var_os(LOCKING_CHILD) {
            use std::os::fd::AsRawFd as _;

            // SQLite's locks are on the bytes from 1 GiB: its exclusive
            // lock is a write lock on all 512 of them.
            const PENDING_BYTE: libc::off_t = 0x4000_0000;
            let file = std::fs::File::open(db_path).unwrap();
            // SAFETY: an all-zero `flock` is a valid value to fill in.
            let mut lock: libc::flock = unsafe { std::mem::zeroed() };
            lock.l_type = libc::F_WRLCK as _;
            lock.l_whence = libc::SEEK_SET as _;
            lock.l_start = PENDING_BYTE;
            lock.l_len = 512;
            // SAFETY: the descriptor is open, and F_GETLK only fills `lock`.
            let asked = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &raw mut lock) };
            assert_eq!(asked, 0, "{}", std::io::Error::last_os_error());
            assert_ne!(
                i64::from(lock.l_type),
                i64::from(libc::F_UNLCK),
                "nothing holds a lock on the database"
            );
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("inspector.db");
        let held = Connection::open(&db_path).unwrap();
        held.execute_batch(
            "PRAGMA journal_mode = WAL; CREATE TABLE kept (x); INSERT INTO kept VALUES (1);",
        )
        .unwrap();
        held.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
        held.query_row("SELECT count(*) FROM kept", [], |row| row.get::<_, i64>(0))
            .unwrap();

        page_size(&db_path);

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "db::tests::reading_the_page_size_keeps_this_process_s_locks_on_the_database",
                "--exact",
                "--nocapture",
            ])
            .env(LOCKING_CHILD, &db_path)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "another process took the lock:\n{}{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        drop(held);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_replacement_removes_files_left_beside_the_database_it_replaces() {
        let project = project_with_a_database(&format!(
            "{CAPTURE_SCHEMA} ALTER TABLE requests ADD COLUMN response_body_incomplete \
             INTEGER NOT NULL DEFAULT 0;"
        ));
        let db_path = project.path().join(".lpm/inspector.db");
        let left = [
            capture_file(&db_path, "-wal"),
            capture_file(&db_path, "-shm"),
        ];
        let journal = capture_file(&db_path, "-journal");
        let leaving = left.clone();
        let journal_left = journal.clone();
        AFTER_COPY.set(Some(Box::new(move || {
            for path in leaving.iter().chain([&journal_left]) {
                std::fs::write(path, b"left by another connection").unwrap();
                set_mode(path, 0o644);
            }
        })));

        // SQLite removes a journal it can't read as it opens the database,
        // and plays back one it can, so it's looked for before that.
        let journal_at_rename = std::rc::Rc::new(std::cell::Cell::new(None));
        let looked = std::rc::Rc::clone(&journal_at_rename);
        AFTER_RENAME.set(Some(Box::new(move || looked.set(Some(journal.exists())))));

        let db = InspectorDb::open(project.path());
        let copied = AFTER_COPY.with_borrow_mut(Option::take).is_none();

        let db = db.unwrap();
        assert!(copied);
        assert_eq!(journal_at_rename.get(), Some(false));
        assert_eq!(mode(&db_path), 0o600);
        for path in &left {
            assert_eq!(mode(path), 0o600, "{}", path.display());
            assert_ne!(
                std::fs::read(path).unwrap(),
                b"left by another connection",
                "{}",
                path.display()
            );
        }
        drop(db);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_disk_too_full_to_create_the_copy_says_how_much_room_it_needs() {
        for (kind, room) in [
            (std::io::ErrorKind::StorageFull, true),
            (std::io::ErrorKind::PermissionDenied, false),
        ] {
            let project = project_with_a_database(&format!(
                "{CAPTURE_SCHEMA} ALTER TABLE requests ADD COLUMN response_body_incomplete \
                 INTEGER NOT NULL DEFAULT 0;"
            ));
            let db_path = project.path().join(".lpm/inspector.db");

            COPY_CREATE_ERROR.set(Some(kind));
            let opened = InspectorDb::open(project.path()).map(drop);
            COPY_CREATE_ERROR.set(None);

            let error = opened.unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(
                error.to_string().contains(&format!(
                    "needs about {} free on its disk",
                    lpm_common::format_bytes(room_to_copy(&db_path).unwrap())
                )),
                room,
                "{error}"
            );
            assert_eq!(mode(&db_path), 0o644);
            assert!(!capture_file(&db_path, "-copy").exists());
        }
    }

    #[test]
    fn copying_refuses_an_unfinished_copy_when_a_lock_outlasts_the_wait() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("inspector.db");
        let database = Connection::open(&db_path).unwrap();
        database
            .execute_batch("CREATE TABLE kept (x); INSERT INTO kept VALUES (1);")
            .unwrap();
        database
            .busy_timeout(std::time::Duration::from_millis(100))
            .unwrap();
        let holder = Connection::open(&db_path).unwrap();
        holder
            .execute_batch("BEGIN EXCLUSIVE; INSERT INTO kept VALUES (2);")
            .unwrap();
        let copy_path = capture_file(&db_path, "-copy");
        assert!(create_owner_only(&copy_path).unwrap());

        let copied = copy_database(&database, &copy_path, &db_path, room_to_copy(&db_path));
        holder.execute_batch("COMMIT").unwrap();

        assert!(matches!(
            copied,
            Err(OpenError::Files(ref error)) if error.kind() == std::io::ErrorKind::ResourceBusy
        ));
    }

    #[test]
    fn copying_waits_out_a_lock_another_connection_holds_on_the_database() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("inspector.db");
        let database = Connection::open(&db_path).unwrap();
        database
            .execute_batch("CREATE TABLE kept (x); INSERT INTO kept VALUES (1);")
            .unwrap();
        let holder = Connection::open(&db_path).unwrap();
        holder
            .execute_batch("BEGIN EXCLUSIVE; INSERT INTO kept VALUES (2);")
            .unwrap();
        let released = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            holder.execute_batch("COMMIT").unwrap();
        });

        let copy_path = capture_file(&db_path, "-copy");
        assert!(create_owner_only(&copy_path).unwrap());
        copy_database(&database, &copy_path, &db_path, room_to_copy(&db_path)).unwrap();
        released.join().unwrap();

        let rows: i64 = Connection::open(capture_file(&db_path, "-copy"))
            .unwrap()
            .query_row("SELECT count(*) FROM kept", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 2);
    }

    #[cfg(unix)]
    #[test]
    fn replacing_refuses_a_database_with_a_damaged_full_text_index() {
        let project = project_with_a_capture();
        let db_path = project.path().join(".lpm/inspector.db");
        let damaging = Connection::open(&db_path).unwrap();
        damaging
            .execute_batch("UPDATE requests_fts_data SET block = zeroblob(64) WHERE id > 10;")
            .unwrap();
        drop(damaging);
        set_mode(&db_path, 0o644);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime
            .block_on(async { InspectorDb::open(project.path()).map(drop) })
            .unwrap_err();

        assert!(matches!(error, OpenError::Damaged { .. }), "{error}");
        assert!(error.to_string().ends_with(ADVICE), "{error}");
        assert_eq!(mode(&db_path), 0o644);
        assert!(!project.path().join(".lpm/inspector.db-copy").exists());
    }

    #[cfg(unix)]
    #[test]
    fn opening_takes_a_schema_sqlite_finds_corrupt_for_damage() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        for open in [InspectorDb::open, InspectorDb::open_for_review] {
            let project = project_with_a_capture();
            let db_path = project.path().join(".lpm/inspector.db");
            let connection = Connection::open(&db_path).unwrap();
            connection
                .execute_batch("PRAGMA journal_mode=DELETE;")
                .unwrap();
            drop(connection);
            // The b-tree header of page 1, which holds the schema, past the
            // 100-byte database header.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&db_path)
                .unwrap();
            use std::io::{Seek as _, Write as _};
            file.seek(std::io::SeekFrom::Start(100)).unwrap();
            file.write_all(&[0xff; 8]).unwrap();
            drop(file);
            set_mode(&db_path, 0o600);

            let error = runtime
                .block_on(async { open(project.path()).map(drop) })
                .unwrap_err();

            assert!(
                matches!(&error, OpenError::Damaged { detail, .. } if detail.contains("malformed")),
                "{error:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn replacing_refuses_a_database_with_damaged_pages() {
        let project = project_with_a_capture();
        let db_path = project.path().join(".lpm/inspector.db");
        let connection = Connection::open(&db_path).unwrap();
        let (page_size, pages): (u64, u64) = connection
            .query_row(
                "SELECT * FROM pragma_page_size, pragma_page_count",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(connection);
        assert!(pages > 3);
        // The header of page 2, the `sessions` table's root.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&db_path)
            .unwrap();
        use std::io::{Seek as _, Write as _};
        file.seek(std::io::SeekFrom::Start(page_size)).unwrap();
        file.write_all(&[0xff; 8]).unwrap();
        drop(file);
        set_mode(&db_path, 0o644);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime
            .block_on(async { InspectorDb::open(project.path()).map(drop) })
            .unwrap_err();

        assert!(matches!(error, OpenError::Damaged { .. }), "{error}");
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
        for pragma in ["cell_size_check", "secure_delete"] {
            let on: i64 = connection
                .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
                .unwrap();
            assert_eq!(on, 1, "{pragma}");
        }
        assert_eq!(
            connection
                .limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH)
                .unwrap(),
            LONGEST_VALUE_BYTES
        );
        assert!(
            connection
                .query_row(
                    "SELECT length(zeroblob(?1))",
                    [LONGEST_VALUE_BYTES + 1],
                    |row| { row.get::<_, i64>(0) }
                )
                .is_err()
        );
    }

    #[test]
    fn the_largest_capture_fits_the_longest_value() {
        let connection = Connection::open_in_memory().unwrap();
        harden_connection(&connection).unwrap();
        init_schema(&connection).unwrap();
        let body = vec![b'x'; 50 * 1024 * 1024];
        let mut webhook = make_webhook("largest", 200);
        webhook.request_body.clone_from(&body);
        webhook.response_body = body;

        insert_request_row(&connection, &webhook, None).unwrap();
    }

    #[test]
    fn bundled_sqlite_has_the_full_text_fix() {
        // 3.50.3 fixed CVE-2025-7709, a read past a damaged FTS5 index.
        assert!(
            rusqlite::version_number() >= 3_050_003,
            "{}",
            rusqlite::version()
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
    async fn opening_a_new_database_from_several_openers_at_once_succeeds() {
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
    async fn opening_waits_while_another_opener_holds_the_capture_lock() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let lock = hold_capture_lock(project.path());
        let path = project.path().to_path_buf();
        let opener = tokio::task::spawn_blocking(move || {
            InspectorDb::open(&path).map(drop)?;
            Ok::<_, OpenError>(std::time::Instant::now())
        });

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let released = std::time::Instant::now();
        drop(lock);
        let opened = opener.await.unwrap().unwrap();

        assert!(opened >= released, "opened before the lock was released");
    }

    #[test]
    fn opening_gives_up_once_another_opener_holds_the_lock_too_long() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let lock = hold_capture_lock(project.path());
        let wait = std::time::Duration::from_secs(1);
        let started = std::time::Instant::now();

        let path = project.path().to_path_buf();
        let error = std::thread::spawn(move || {
            OPEN_LOCK_WAIT.set(Some(wait));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async { InspectorDb::open(&path).map(drop) })
        })
        .join()
        .unwrap()
        .unwrap_err();

        let waited = started.elapsed();
        assert!(waited >= wait && waited < wait * 4, "{waited:?}");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            error.to_string().contains("another LPM process held"),
            "{error}"
        );
        assert!(!project.path().join(".lpm/inspector.db").exists());
        drop(lock);
    }

    #[cfg(unix)]
    #[test]
    fn openers_racing_to_replace_a_database_others_could_open_all_succeed() {
        for round in 0..30 {
            let project = project_with_a_capture();
            let db_path = project.path().join(".lpm/inspector.db");
            set_mode(&db_path, 0o644);
            let start = Arc::new(std::sync::Barrier::new(4));
            let openers: Vec<_> = (0..4)
                .map(|_| {
                    let start = Arc::clone(&start);
                    let project = project.path().to_path_buf();
                    std::thread::spawn(move || {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap();
                        start.wait();
                        runtime.block_on(async {
                            // Each keeps its database open while the others
                            // open theirs, as concurrent runs would.
                            let db = InspectorDb::open(&project)?;
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                            Ok::<_, OpenError>(db.open_to_others())
                        })
                    })
                })
                .collect();
            for opener in openers {
                assert!(!opener.join().unwrap().unwrap(), "round {round}");
            }
            assert_eq!(mode(&db_path), 0o600, "round {round}");
        }
    }

    #[tokio::test]
    async fn clearing_history_leaves_no_capture_on_disk_while_another_handle_stays_open() {
        const SECRET: &[u8] = b"zqxcapturedsecretzqx";

        let project = tempfile::tempdir().unwrap();
        let recording = InspectorDb::open(project.path()).unwrap();
        let mut webhook = make_webhook("secret", 200);
        webhook.request_body = SECRET.to_vec();
        webhook.summary = String::from_utf8(SECRET.to_vec()).unwrap();
        webhook.request_headers.insert(
            "authorization".into(),
            String::from_utf8(SECRET.to_vec()).unwrap(),
        );
        recording
            .insert_durable_request(Arc::new(webhook), None)
            .await
            .unwrap();
        let clearing = InspectorDb::open_for_review(project.path()).unwrap();

        clearing.clear_history().await.unwrap();

        for name in ["inspector.db", "inspector.db-wal"] {
            let path = project.path().join(".lpm").join(name);
            let bytes = std::fs::read(&path).unwrap_or_default();
            assert!(
                !bytes.windows(SECRET.len()).any(|window| window == SECRET),
                "{name} still holds the capture"
            );
        }
        assert_eq!(recording.count().await.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clearing_history_from_two_handles_at_once_succeeds() {
        // Each clear waits for the other's, whose checkpoint syncs to disk
        // while it holds the lock, which a loaded machine can keep past the
        // busy timeout. A clear that refuses without waiting, as a deferred
        // transaction does, fails at once whatever the timeout.
        BUSY_WAIT.set(Some(std::time::Duration::from_secs(60)));
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
        let write_conn = Arc::new(Mutex::new(write_conn));
        let db = InspectorDb {
            read_conn: Arc::new(Mutex::new(read_conn)),
            control_conn: Arc::new(std::sync::Mutex::new(control_conn)),
            write_tx,
            queued_capture_bytes: Arc::clone(&queued_capture_bytes),
            db_path,
            open_to_others: false,
            ownership_ignored: false,
            session_owners: None,
            _temp_dir: None,
            write_conn: Arc::clone(&write_conn),
        };

        db.start_session("saturated-session".to_string(), None, 3000)
            .unwrap();
        db.insert_request(
            make_webhook("queued-while-paused", 200),
            Some("saturated-session".to_string()),
        );
        assert_eq!(db.write_tx.capacity(), 0);
        db.end_session("saturated-session".to_string()).unwrap();

        let writer = tokio::spawn(flush_task(write_conn, write_rx, queued_capture_bytes));
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

    async fn ended_and_open_sessions(db: &InspectorDb, secret: &[u8]) {
        for (session, port) in [("ended", 4321), ("other-ended", 5173), ("open", 3000)] {
            db.start_session(session.to_string(), None, port).unwrap();
        }
        let mut captured = make_webhook("in-ended", 502);
        captured.request_body = secret.to_vec();
        captured.summary = String::from_utf8(secret.to_vec()).unwrap();
        db.insert_request(captured, Some("ended".to_string()));
        db.insert_request(
            make_webhook("in-other-ended", 200),
            Some("other-ended".to_string()),
        );
        db.insert_request(make_webhook("in-open", 200), Some("open".to_string()));
        db.flush_pending_writes().await.unwrap();
        db.end_session("ended".to_string()).unwrap();
        db.end_session("other-ended".to_string()).unwrap();
    }

    async fn session_ids(db: &InspectorDb) -> Vec<String> {
        let mut ids: Vec<String> = db
            .list_sessions(10)
            .await
            .unwrap()
            .into_iter()
            .map(|session| session.id)
            .collect();
        ids.sort();
        ids
    }

    #[tokio::test]
    async fn deleting_an_ended_session_leaves_no_trace_of_its_captures_on_disk() {
        const SECRET: &[u8] = b"zqxendedsessionsecretzqx";
        let project = tempfile::tempdir().unwrap();
        let db = InspectorDb::open(project.path()).unwrap();
        ended_and_open_sessions(&db, SECRET).await;

        let deletion = db.delete_session("ended").await.unwrap();

        assert_eq!(
            deletion,
            SessionDeletion::Deleted(vec!["in-ended".to_string()])
        );
        for name in ["inspector.db", "inspector.db-wal"] {
            let path = project.path().join(".lpm").join(name);
            let bytes = std::fs::read(&path).unwrap_or_default();
            assert!(
                !bytes.windows(SECRET.len()).any(|window| window == SECRET),
                "{name} still holds the deleted session's capture"
            );
        }
        assert!(db.get_webhook("in-ended").await.unwrap().is_none());
        assert!(db.get_webhook("in-other-ended").await.unwrap().is_some());
        assert_eq!(session_ids(&db).await, ["open", "other-ended"]);
        let found = db
            .search("zqxendedsessionsecretzqx", None, None, 10)
            .await
            .unwrap();
        assert!(found.is_empty(), "{found:?}");
    }

    #[tokio::test]
    async fn deleting_an_open_session_is_refused_and_keeps_its_captures() {
        let project = tempfile::tempdir().unwrap();
        let db = InspectorDb::open(project.path()).unwrap();
        ended_and_open_sessions(&db, b"unused").await;

        assert_eq!(
            db.delete_session("open").await.unwrap(),
            SessionDeletion::Open
        );
        assert_eq!(
            db.delete_session("missing").await.unwrap(),
            SessionDeletion::NotFound
        );
        assert!(db.get_webhook("in-open").await.unwrap().is_some());
        assert_eq!(session_ids(&db).await, ["ended", "open", "other-ended"]);
    }

    #[tokio::test]
    async fn deleting_ended_sessions_keeps_open_sessions_and_their_captures() {
        let project = tempfile::tempdir().unwrap();
        let db = InspectorDb::open(project.path()).unwrap();
        ended_and_open_sessions(&db, b"unused").await;

        let deleted = db.delete_ended_sessions().await.unwrap();

        let mut request_ids = deleted.request_ids;
        request_ids.sort();
        assert_eq!(
            (deleted.sessions, request_ids),
            (
                2,
                vec!["in-ended".to_string(), "in-other-ended".to_string()]
            )
        );
        assert_eq!(session_ids(&db).await, ["open"]);
        assert!(db.get_webhook("in-open").await.unwrap().is_some());
        assert_eq!(db.count().await.unwrap(), 1);
    }

    /// Owners for tests: `running` and `unknown` report so, anything else
    /// is gone.
    fn scripted_owner_state(_pid: u32, identity: &str) -> OwnerState {
        match identity {
            "running" => OwnerState::Running,
            "unknown" => OwnerState::Unknown,
            _ => OwnerState::Gone,
        }
    }

    fn owned(project: &Path, identity: &str) -> InspectorDb {
        InspectorDb::open(project)
            .unwrap()
            .with_session_ownership(SessionOwnership::new(
                7,
                identity.to_string(),
                scripted_owner_state,
            ))
    }

    fn session_ends(project: &Path) -> HashMap<String, Option<String>> {
        let connection = Connection::open(project.join(".lpm/inspector.db")).unwrap();
        let mut statement = connection
            .prepare("SELECT id, ended_at FROM sessions")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[tokio::test]
    async fn opening_ends_the_open_sessions_whose_recorder_is_gone() {
        let project = tempfile::tempdir().unwrap();
        let crashed = owned(project.path(), "crashed");
        let running = owned(project.path(), "running");
        let unreadable = owned(project.path(), "unknown");
        let unowned = InspectorDb::open(project.path()).unwrap();
        crashed.start_session("crashed".into(), None, 4321).unwrap();
        crashed.insert_request(make_webhook("last-capture", 200), Some("crashed".into()));
        crashed.flush_pending_writes().await.unwrap();
        crashed
            .start_session_named_reversible("never-published".into(), None, 4321, None)
            .unwrap();
        running.start_session("running".into(), None, 4321).unwrap();
        unreadable
            .start_session("unknown".into(), None, 4321)
            .unwrap();
        unowned
            .start_session("before-owners".into(), None, 4321)
            .unwrap();
        let connection = Connection::open(project.path().join(".lpm/inspector.db")).unwrap();
        let (last_capture, before_owners_start): (String, String) = connection
            .query_row(
                "SELECT (SELECT created_at FROM requests WHERE id = 'last-capture'),
                        (SELECT started_at FROM sessions WHERE id = 'before-owners')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        drop(owned(project.path(), "running"));

        let ends = session_ends(project.path());
        assert_eq!(ends["crashed"].as_deref(), Some(last_capture.as_str()));
        assert_eq!(
            ends["before-owners"].as_deref(),
            Some(before_owners_start.as_str())
        );
        assert_eq!(ends["running"], None);
        assert_eq!(ends["unknown"], None);
        assert!(
            !ends.contains_key("never-published"),
            "a pending session of a gone recorder is rolled back: {ends:?}"
        );
    }

    #[tokio::test]
    async fn listing_clearing_and_deleting_end_sessions_abandoned_since_opening() {
        let project = tempfile::tempdir().unwrap();
        let reviewer = owned(project.path(), "running");
        let crashed = owned(project.path(), "crashed");

        crashed.start_session("listed".into(), None, 4321).unwrap();
        let listed = reviewer.list_sessions(10).await.unwrap();
        crashed.start_session("deleted".into(), None, 4321).unwrap();
        let deleted = reviewer.delete_session("deleted").await.unwrap();
        crashed.start_session("cleared".into(), None, 4321).unwrap();
        reviewer.clear_history().await.unwrap();

        assert!(listed[0].ended_at.is_some(), "{listed:?}");
        assert_eq!(deleted, SessionDeletion::Deleted(Vec::new()));
        assert!(session_ends(project.path()).is_empty());
    }

    #[tokio::test]
    async fn a_handle_without_ownership_ends_no_session() {
        let project = tempfile::tempdir().unwrap();
        owned(project.path(), "crashed")
            .start_session("crashed".into(), None, 4321)
            .unwrap();
        let unowned = InspectorDb::open(project.path()).unwrap();

        unowned.list_sessions(10).await.unwrap();

        assert_eq!(
            unowned.delete_session("crashed").await.unwrap(),
            SessionDeletion::Open
        );
    }

    #[tokio::test]
    async fn a_request_reports_the_local_port_its_session_forwarded_to() {
        let project = tempfile::tempdir().unwrap();
        let db = InspectorDb::open(project.path()).unwrap();
        ended_and_open_sessions(&db, b"unused").await;
        db.insert_request(make_webhook("sessionless", 502), None);
        db.flush_pending_writes().await.unwrap();

        assert_eq!(db.request_local_port("in-ended").await.unwrap(), Some(4321));
        assert_eq!(db.request_local_port("sessionless").await.unwrap(), None);
        assert_eq!(db.request_local_port("missing").await.unwrap(), None);
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

        for open in [InspectorDb::open, InspectorDb::open_for_review] {
            let error = match open(project.path()) {
                Ok(_) => panic!("corrupt database must not open"),
                Err(error) => error,
            };

            assert!(matches!(error, OpenError::Damaged { .. }), "{error}");
            assert!(error.to_string().ends_with(ADVICE), "{error}");
        }
    }
}

#[cfg(test)]
#[path = "db/durable_tests.rs"]
mod durable_tests;
