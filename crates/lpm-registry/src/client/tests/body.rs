use super::*;

#[tokio::test]
async fn parse_capped_metadata_rejects_declared_oversized_content_length() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let declared = MAX_METADATA_BYTES + 1;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                     Content-Length: {declared}\r\n\
                     Content-Type: application/json\r\n\
                     Connection: close\r\n\
                     \r\n",
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    let response = reqwest::get(format!("http://{addr}/"))
        .await
        .expect("connect should succeed");
    let result: Result<serde_json::Value, _> =
        parse_capped_metadata(response, "oversized-test").await;
    let err = result.expect_err("oversized Content-Length must reject pre-stream");
    let msg = format!("{err}");
    assert!(
        msg.contains("declared body length"),
        "expected pre-stream rejection, got: {msg}"
    );
}

#[tokio::test]
async fn parse_capped_metadata_accepts_response_under_cap() {
    use wiremock::matchers::{method, path as match_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = serde_json::json!({"name":"@scope/p","versions":{"1.0.0":{"name":"@scope/p","version":"1.0.0"}}});
    Mock::given(method("GET"))
        .and(match_path("/p"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&server)
        .await;

    let response = reqwest::get(format!("{}/p", server.uri()))
        .await
        .expect("connect");
    let parsed: serde_json::Value = parse_capped_metadata(response, "under-cap-test")
        .await
        .expect("under-cap response must parse");
    assert_eq!(parsed["name"], "@scope/p");
}

#[tokio::test]
async fn parse_capped_metadata_accepts_utf8_bom_prefixed_response() {
    use wiremock::matchers::{method, path as match_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let mut body = Vec::from(UTF8_BOM_BYTES);
    body.extend_from_slice(br#"{"name":"bom-prefixed","versions":{}}"#);
    Mock::given(method("GET"))
        .and(match_path("/p"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let response = reqwest::get(format!("{}/p", server.uri()))
        .await
        .expect("connect");
    let parsed: serde_json::Value = parse_capped_metadata(response, "bom-test")
        .await
        .expect("BOM-prefixed response must parse");
    assert_eq!(parsed["name"], "bom-prefixed");
}

#[tokio::test]
async fn parse_capped_api_json_rejects_oversized_declared_length() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let declared = MAX_API_RESPONSE_BYTES + 1;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                     Content-Length: {declared}\r\n\
                     Content-Type: application/json\r\n\
                     Connection: close\r\n\
                     \r\n",
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    let response = reqwest::get(format!("http://{addr}/"))
        .await
        .expect("connect");
    let result: Result<serde_json::Value, _> =
        parse_capped_api_json(response, "api-cap-test").await;
    let err = result.expect_err("oversized Content-Length must reject pre-stream");
    let msg = format!("{err}");
    assert!(
        msg.contains("declared body length"),
        "expected pre-stream rejection, got: {msg}"
    );
}

#[tokio::test]
async fn read_capped_error_text_rejects_oversized_declared_length() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let declared = MAX_API_RESPONSE_BYTES + 1;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 503 Service Unavailable\r\n\
                     Content-Length: {declared}\r\n\
                     Content-Type: text/plain\r\n\
                     Connection: close\r\n\
                     \r\n",
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    let response = reqwest::get(format!("http://{addr}/"))
        .await
        .expect("connect");
    let body = read_capped_error_text(response).await;
    assert_eq!(
        body, "",
        "cap-overflow on the error body must collapse to empty string, got {body:?}"
    );
}
