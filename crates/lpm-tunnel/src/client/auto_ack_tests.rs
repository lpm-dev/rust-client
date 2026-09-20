use super::*;

async fn failed_forward(
    webhook_tx: Option<tokio::sync::mpsc::Sender<CapturedWebhookEvent>>,
) -> ClientMessage {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        drop(socket);
    });
    let request = ServerMessage::HttpRequest {
        id: "needs-replay".into(),
        method: "POST".into(),
        url: "/webhook".into(),
        headers: HashMap::new(),
        body: "e30=".into(),
    };
    let (response, _) = forward_http_request(
        reqwest::Client::builder().no_proxy().build().unwrap(),
        lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, port),
        request,
        true,
        webhook_tx,
        Arc::new(tokio::sync::Semaphore::new(HTTP_RESPONSE_MEMORY_PERMITS)),
        None,
        None,
    )
    .await;
    server.await.unwrap();
    response
}

#[tokio::test]
async fn auto_ack_without_capture_returns_retryable_error() {
    assert_eq!(extract_response_data(&failed_forward(None).await).0, 503);
}

#[tokio::test]
async fn auto_ack_with_closed_capture_returns_retryable_error() {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    drop(rx);
    assert_eq!(
        extract_response_data(&failed_forward(Some(tx)).await).0,
        503
    );
}

#[tokio::test]
async fn auto_ack_requires_persistence_not_channel_delivery() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let consumer = tokio::spawn(async move {
        drop(rx.recv().await.unwrap());
    });
    assert_eq!(
        extract_response_data(&failed_forward(Some(tx)).await).0,
        503
    );
    consumer.await.unwrap();
}

#[tokio::test]
async fn auto_ack_waits_for_successful_persistence() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedWebhookEvent>(1);
    let forward = tokio::spawn(failed_forward(Some(tx)));
    let event = rx.recv().await.unwrap();
    assert!(event.requires_persistence());
    assert!(!forward.is_finished());
    event.complete_persistence(Ok(()));
    assert_eq!(extract_response_data(&forward.await.unwrap()).0, 200);
}

#[tokio::test]
async fn auto_ack_persistence_failure_returns_retryable_error() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedWebhookEvent>(1);
    let consumer = tokio::spawn(async move {
        rx.recv()
            .await
            .unwrap()
            .complete_persistence(Err("disk full".into()));
    });
    assert_eq!(
        extract_response_data(&failed_forward(Some(tx)).await).0,
        503
    );
    consumer.await.unwrap();
}

#[tokio::test]
async fn auto_ack_with_full_capture_queue_returns_retryable_error() {
    let (tx, _rx) = tokio::sync::mpsc::channel::<CapturedWebhookEvent>(1);
    let _reserved = tx.reserve().await.unwrap();
    assert_eq!(
        extract_response_data(&failed_forward(Some(tx.clone())).await).0,
        503
    );
}

#[tokio::test(start_paused = true)]
async fn auto_ack_persistence_deadline_returns_retryable_error() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedWebhookEvent>(1);
    let forward = tokio::spawn(failed_forward(Some(tx)));
    let event = rx.recv().await.unwrap();
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    assert_eq!(extract_response_data(&forward.await.unwrap()).0, 503);
    event.complete_persistence(Ok(()));
}
