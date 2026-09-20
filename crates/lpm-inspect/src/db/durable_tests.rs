use super::tests::make_webhook;
use super::*;

#[tokio::test]
async fn durable_capture_bypasses_saturated_queue_and_survives_reopen() {
    let project = tempfile::tempdir().unwrap();
    let db = InspectorDb::open(project.path()).unwrap();
    let _reservations = db
        .write_tx
        .reserve_many(WRITE_QUEUE_CAPACITY)
        .await
        .unwrap();
    db.queued_capture_bytes
        .store(WRITE_QUEUE_BYTE_BUDGET, Ordering::Relaxed);
    let webhook = Arc::new(make_webhook("durable", 200));
    db.insert_durable_request(Arc::clone(&webhook), None)
        .await
        .unwrap();
    {
        let connection = db.control_conn.lock().unwrap();
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            synchronous, 2,
            "acknowledged captures require FULL synchronization"
        );
    }
    let reopened = InspectorDb::open(project.path()).unwrap();
    let saved = reopened.get_webhook("durable").await.unwrap().unwrap();
    assert_eq!(saved.request_body, webhook.request_body);
    assert_eq!(saved.request_headers, webhook.request_headers);
}

#[tokio::test]
async fn durable_capture_reports_storage_failure_without_partial_request() {
    let project = tempfile::tempdir().unwrap();
    let db = InspectorDb::open(project.path()).unwrap();
    db.control_conn.lock().unwrap().execute_batch(
        "CREATE TRIGGER reject_capture BEFORE INSERT ON requests BEGIN SELECT RAISE(ABORT, 'storage unavailable'); END;"
    ).unwrap();
    let result = db
        .insert_durable_request(Arc::new(make_webhook("failed", 200)), None)
        .await;
    assert!(result.unwrap_err().contains("storage unavailable"));
    assert!(db.get_webhook("failed").await.unwrap().is_none());
}
