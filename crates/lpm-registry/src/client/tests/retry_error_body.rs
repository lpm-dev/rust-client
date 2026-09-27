use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

enum BodyDelivery {
    Complete,
    Delayed,
    Stalled,
    Trickle,
}

struct ResponsePlan {
    status: u16,
    body: &'static str,
    delivery: BodyDelivery,
}

struct Server {
    url: reqwest::Url,
    attempts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(plans: Vec<ResponsePlan>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/metadata", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            for plan in plans {
                let (socket, _) = listener.accept().await.unwrap();
                let observed = Arc::clone(&observed);
                connections.spawn(async move {
                    let mut socket = BufReader::new(socket);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
                        if line == "\r\n" {
                            break;
                        }
                    }
                    observed.fetch_add(1, Ordering::SeqCst);
                    let incomplete = matches!(
                        plan.delivery,
                        BodyDelivery::Stalled | BodyDelivery::Trickle
                    );
                    let length = plan.body.len() + if incomplete { 1024 } else { 0 };
                    socket
                        .get_mut()
                        .write_all(
                            format!(
                                "HTTP/1.1 {} Test\r\nContent-Length: {length}\r\nRetry-After: 0\r\nConnection: close\r\n\r\n",
                                plan.status
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                    if matches!(plan.delivery, BodyDelivery::Delayed) {
                        tokio::time::sleep(Duration::from_millis(750)).await;
                    }
                    socket.get_mut().write_all(plan.body.as_bytes()).await.unwrap();
                    match plan.delivery {
                        BodyDelivery::Stalled => std::future::pending::<()>().await,
                        BodyDelivery::Trickle => {
                            for _ in 0..100 {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                if socket.get_mut().write_all(b"x").await.is_err() {
                                    break;
                                }
                            }
                        }
                        BodyDelivery::Complete | BodyDelivery::Delayed => {}
                    }
                });
            }
            while let Some(result) = connections.join_next().await {
                result.unwrap();
            }
        });
        Self {
            url,
            attempts,
            task,
        }
    }

    async fn request(
        &self,
        headers: reqwest::header::HeaderMap,
    ) -> Result<reqwest::Response, LpmError> {
        let mut request = reqwest::Request::new(reqwest::Method::GET, self.url.clone());
        *request.headers_mut() = headers;
        let http = reqwest::Client::builder()
            .no_proxy()
            .read_timeout(Duration::from_secs(60))
            .build()
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(12),
            RegistryClient::new().send_request_with_retry_and_npmrc_auth(request, Some(http), None),
        )
        .await
        .expect("diagnostic bodies must not hold the retry loop open")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn stalled_retry_bodies_preserve_attempt_budget_and_final_status_without_partial_text() {
    let server = Server::start(
        [408, 500, 502, 504]
            .into_iter()
            .map(|status| ResponsePlan {
                status,
                body: "reflected-secret",
                delivery: BodyDelivery::Stalled,
            })
            .collect(),
    )
    .await;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("authorization", "Bearer reflected-secret".parse().unwrap());
    let error = server.request(headers).await.unwrap_err();
    assert_eq!(server.attempts.load(Ordering::SeqCst), 4);
    match error {
        LpmError::Http { status, message } => {
            assert_eq!(status, 504);
            assert!(message.is_empty(), "{message}");
        }
        error => panic!("expected final HTTP status, got {error}"),
    }
}

#[tokio::test]
async fn trickled_retry_body_cannot_extend_the_total_diagnostic_deadline() {
    let server = Server::start(vec![
        ResponsePlan {
            status: 503,
            body: "prefix",
            delivery: BodyDelivery::Trickle,
        },
        ResponsePlan {
            status: 200,
            body: "{}",
            delivery: BodyDelivery::Complete,
        },
    ])
    .await;
    let response = tokio::time::timeout(Duration::from_secs(3), server.request(Default::default()))
        .await
        .expect("progress in a diagnostic body must not reset its deadline")
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(server.attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn complete_retry_bodies_preserve_context_and_redact_credentials() {
    let server = Server::start(
        (0..4)
            .map(|_| ResponsePlan {
                status: 503,
                body: "denied bearer-secret proxy-secret 123456 654321",
                delivery: BodyDelivery::Complete,
            })
            .collect(),
    )
    .await;
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in [
        ("authorization", "Bearer bearer-secret"),
        ("proxy-authorization", "Bearer proxy-secret"),
        ("npm-otp", "123456"),
        ("x-otp", "654321"),
    ] {
        headers.insert(name, value.parse().unwrap());
    }
    match server.request(headers).await.unwrap_err() {
        LpmError::Http { status, message } => {
            assert_eq!(status, 503);
            assert_eq!(
                message,
                "denied <redacted> <redacted> <redacted> <redacted>"
            );
        }
        error => panic!("expected HTTP diagnostic, got {error}"),
    }
    assert_eq!(server.attempts.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn nonretryable_bodies_keep_their_existing_status_and_body_contract() {
    for status in [403, 404, 422] {
        let server = Server::start(vec![ResponsePlan {
            status,
            body: "complete diagnostic",
            delivery: BodyDelivery::Delayed,
        }])
        .await;
        let error = server.request(Default::default()).await.unwrap_err();
        match (status, error) {
            (403, LpmError::Forbidden(body)) | (404, LpmError::NotFound(body)) => {
                assert_eq!(body, "complete diagnostic");
            }
            (
                422,
                LpmError::Http {
                    status: 422,
                    message,
                },
            ) => {
                assert_eq!(message, "complete diagnostic");
            }
            (_, error) => panic!("changed nonretryable contract for {status}: {error}"),
        }
        assert_eq!(server.attempts.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn rate_limit_retry_ignores_a_stalled_body_and_honors_zero_retry_after() {
    let server = Server::start(vec![
        ResponsePlan {
            status: 429,
            body: "prefix",
            delivery: BodyDelivery::Stalled,
        },
        ResponsePlan {
            status: 200,
            body: "{}",
            delivery: BodyDelivery::Complete,
        },
    ])
    .await;
    let response = server.request(Default::default()).await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(server.attempts.load(Ordering::SeqCst), 2);
}
