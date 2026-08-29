use super::*;
use serde::de::{self, Visitor};

#[derive(Debug)]
struct ParseThread {
    id: String,
}

impl<'de> serde::Deserialize<'de> for ParseThread {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ParseThreadVisitor;

        impl Visitor<'_> for ParseThreadVisitor {
            type Value = ParseThread;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON string")
            }

            fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ParseThread {
                    id: format!("{:?}", std::thread::current().id()),
                })
            }
        }

        deserializer.deserialize_str(ParseThreadVisitor)
    }
}

#[test]
fn metadata_response_cap_has_headroom_for_large_proxy_packuments() {
    const LARGE_PROXY_PACKUMENT_BYTES: usize = 42 * 1024 * 1024;
    const MINIMUM_GROWTH_HEADROOM_BYTES: usize = 16 * 1024 * 1024;

    const {
        assert!(
            MAX_METADATA_BYTES >= LARGE_PROXY_PACKUMENT_BYTES + MINIMUM_GROWTH_HEADROOM_BYTES,
            "metadata cap must accept a large proxy packument with growth headroom"
        );
    }
}

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
    let mut body = Vec::from(b"\xEF\xBB\xBF".as_slice());
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
async fn parse_capped_metadata_with_timing_reports_body_size() {
    use wiremock::matchers::{method, path as match_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = r#"{"name":"timed","versions":{}}"#;
    Mock::given(method("GET"))
        .and(match_path("/timed"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let response = reqwest::get(format!("{}/timed", server.uri()))
        .await
        .expect("connect");
    let (parsed, timings): (serde_json::Value, _) =
        parse_capped_metadata_with_timing(response, "timed-test")
            .await
            .expect("timed response must parse");

    assert_eq!(parsed["name"], "timed");
    assert_eq!(timings.body_bytes, body.len() as u64);
}

#[tokio::test(flavor = "current_thread")]
async fn parse_capped_metadata_parses_small_json_on_caller_thread() {
    use wiremock::matchers::{method, path as match_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = serde_json::to_string(&"x".repeat(1024)).unwrap();
    Mock::given(method("GET"))
        .and(match_path("/small"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let response = reqwest::get(format!("{}/small", server.uri()))
        .await
        .expect("connect");
    let caller_thread = format!("{:?}", std::thread::current().id());
    let parsed: ParseThread = parse_capped_metadata(response, "small-parse-test")
        .await
        .expect("small JSON string must parse");

    assert_eq!(
        parsed.id, caller_thread,
        "small metadata JSON parse should avoid blocking-pool dispatch"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn parse_capped_metadata_offloads_large_json_parse() {
    use wiremock::matchers::{method, path as match_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let body = serde_json::to_string(&"x".repeat(70 * 1024)).unwrap();
    Mock::given(method("GET"))
        .and(match_path("/large"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let response = reqwest::get(format!("{}/large", server.uri()))
        .await
        .expect("connect");
    let caller_thread = format!("{:?}", std::thread::current().id());
    let parsed: ParseThread = parse_capped_metadata(response, "large-parse-test")
        .await
        .expect("large JSON string must parse");

    assert_ne!(
        parsed.id, caller_thread,
        "large metadata JSON parse should run on a blocking worker"
    );
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
