use super::*;

#[derive(Clone)]
pub struct HttpProxyState {
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        axum::body::Body,
    >,
    forwarded_proto: &'static str,
    fallback_upstream: Option<lpm_common::LocalTarget>,
}

impl HttpProxyState {
    pub fn new(registry: Arc<tokio::sync::Mutex<RouteRegistry>>) -> Self {
        Self::with_forwarded_proto(registry, "http")
    }

    pub(crate) fn with_forwarded_proto(
        registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
        forwarded_proto: &'static str,
    ) -> Self {
        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        Self {
            registry,
            client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build(connector),
            forwarded_proto,
            fallback_upstream: None,
        }
    }

    pub(crate) fn for_upstream(
        upstream: lpm_common::LocalTarget,
        forwarded_proto: &'static str,
    ) -> Self {
        let mut state = Self::with_forwarded_proto(
            Arc::new(tokio::sync::Mutex::new(RouteRegistry::new())),
            forwarded_proto,
        );
        state.fallback_upstream = Some(upstream);
        state
    }
}

#[derive(Clone)]
struct HttpRedirectState {
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    https_port: u16,
}

pub struct HttpProxyHandle {
    pub(crate) addr: SocketAddr,
    pub(crate) shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl HttpProxyHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

impl Drop for HttpProxyHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

pub async fn start_http_proxy(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    port: u16,
) -> Result<HttpProxyHandle, ProxyError> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .map_err(|err| ProxyError::Http(format_loopback_bind_error("HTTP proxy", port, &err)))?;
    start_http_proxy_on_listener(registry, listener)
}

pub fn start_http_proxy_on_listener(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    listener: tokio::net::TcpListener,
) -> Result<HttpProxyHandle, ProxyError> {
    use axum::Router;
    use axum::routing::any;

    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Http(format!("read HTTP proxy bind addr: {err}")))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let app = Router::new()
        .fallback(any(proxy_http_request))
        .with_state(HttpProxyState::new(registry));

    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
    })
}

/// Start an HTTP frontend on an already-bound listener for a verified loopback target.
pub fn start_http_frontend_on_listener(
    listener: tokio::net::TcpListener,
    upstream: lpm_common::LocalTarget,
) -> Result<HttpProxyHandle, ProxyError> {
    use axum::Router;
    use axum::routing::any;

    validate_frontend_upstream(&upstream)?;
    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Http(format!("read HTTP frontend bind addr: {err}")))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let app = Router::new()
        .fallback(any(proxy_http_request))
        .with_state(HttpProxyState::for_upstream(upstream, "http"));

    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
    })
}

pub(crate) fn validate_frontend_upstream(
    upstream: &lpm_common::LocalTarget,
) -> Result<(), ProxyError> {
    if !upstream.is_loopback() {
        return Err(ProxyError::Http(format!(
            "dev frontend upstream must be loopback, got {}",
            upstream.authority()
        )));
    }
    if upstream.scheme != lpm_common::LocalScheme::Http {
        return Err(ProxyError::Http(format!(
            "dev frontend requires an HTTP upstream, got {}",
            upstream.url()
        )));
    }
    Ok(())
}

pub(crate) async fn start_http_redirect(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    port: u16,
    https_port: u16,
) -> Result<HttpProxyHandle, ProxyError> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .map_err(|err| ProxyError::Http(format_loopback_bind_error("HTTP redirect", port, &err)))?;
    start_http_redirect_on_listener(registry, listener, https_port)
}

fn start_http_redirect_on_listener(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    listener: tokio::net::TcpListener,
    https_port: u16,
) -> Result<HttpProxyHandle, ProxyError> {
    use axum::Router;
    use axum::routing::any;

    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Http(format!("read HTTP redirect bind addr: {err}")))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let app = Router::new()
        .fallback(any(redirect_http_request))
        .with_state(HttpRedirectState {
            registry,
            https_port,
        });

    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
    })
}

pub(crate) fn format_loopback_bind_error(
    listener: &str,
    port: u16,
    err: &std::io::Error,
) -> String {
    let mut message = format!("bind {listener} on 127.0.0.1:{port}: {err}");
    if port != 0 && port < 1024 && err.kind() == std::io::ErrorKind::PermissionDenied {
        message.push_str(
            ". Binding ports below 1024 requires privileged bind rights on macOS/Linux. Use `lpm proxy install --privileged-ports` for persistent Unix 80/443 forwarding, or set `proxy.port` to a high port such as 9443 for foreground starts.",
        );
    }
    message
}

async fn redirect_http_request(
    axum::extract::State(state): axum::extract::State<HttpRedirectState>,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    let Some(host_header) = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return (StatusCode::MISDIRECTED_REQUEST, "missing Host header").into_response();
    };
    let Some(route) = state
        .registry
        .lock()
        .await
        .lookup_host_header(&host_header)
        .cloned()
    else {
        return (StatusCode::MISDIRECTED_REQUEST, "unknown local proxy host").into_response();
    };

    let path = request.uri().path_and_query().map_or("/", |p| p.as_str());
    let host = if state.https_port == 443 {
        route.host
    } else {
        format!("{}:{}", route.host, state.https_port)
    };
    let location = format!("https://{host}{path}");
    axum::http::Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, location)
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response())
}

async fn proxy_http_request(
    axum::extract::State(state): axum::extract::State<HttpProxyState>,
    request: axum::extract::Request,
) -> axum::response::Response {
    match proxy_http_request_inner(state, request).await {
        Ok(response) => response,
        Err(response) => response,
    }
}

pub(crate) async fn proxy_http_request_inner(
    state: HttpProxyState,
    request: axum::extract::Request,
) -> Result<axum::response::Response, axum::response::Response> {
    use axum::body::Body;
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    let Some(host_header) = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return Err((StatusCode::MISDIRECTED_REQUEST, "missing Host header").into_response());
    };
    let upstream = state
        .registry
        .lock()
        .await
        .lookup_host_header(&host_header)
        .map(|route| {
            lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, route.upstream_port)
        })
        .or_else(|| state.fallback_upstream.clone());
    let Some(upstream) = upstream else {
        return Err((StatusCode::MISDIRECTED_REQUEST, "unknown local proxy host").into_response());
    };

    if is_upgrade_request(request.headers()) {
        return proxy_upgrade_request(request, upstream, host_header, state.forwarded_proto).await;
    }

    let (parts, body) = request.into_parts();
    let method = parts.method;
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let upstream_url = format!(
        "{}://{}{}",
        upstream.scheme,
        upstream.authority(),
        upstream.upstream_path(path)
    );
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(upstream_url);

    for (name, value) in &parts.headers {
        if is_forwardable_http_header(name.as_str()) {
            builder = builder.header(name.clone(), value.clone());
        }
    }
    builder = builder
        .header(header::HOST, upstream.authority())
        .header("x-forwarded-host", host_header)
        .header("x-forwarded-proto", state.forwarded_proto);

    let upstream_request = builder.body(body).map_err(|_| {
        (StatusCode::BAD_GATEWAY, "failed to build upstream request").into_response()
    })?;
    let upstream = state.client.request(upstream_request).await.map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "upstream dev server request failed",
        )
            .into_response()
    })?;

    let (upstream_parts, upstream_body) = upstream.into_parts();
    let mut response_builder = axum::http::Response::builder().status(upstream_parts.status);
    for (name, value) in &upstream_parts.headers {
        if is_forwardable_http_header(name.as_str()) {
            response_builder = response_builder.header(name.clone(), value.clone());
        }
    }
    response_builder
        .body(Body::new(upstream_body))
        .map_err(|_| (StatusCode::BAD_GATEWAY, "failed to build proxy response").into_response())
}

async fn proxy_upgrade_request(
    mut request: axum::extract::Request,
    upstream: lpm_common::LocalTarget,
    host_header: String,
    forwarded_proto: &'static str,
) -> Result<axum::response::Response, axum::response::Response> {
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use tokio::io::AsyncWriteExt;

    let on_upgrade = hyper::upgrade::on(&mut request);
    let upstream_request =
        build_upgrade_request_bytes(&request, &upstream, &host_header, forwarded_proto);
    let mut upstream_stream = tokio::net::TcpStream::connect((upstream.address, upstream.port))
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "upstream dev server is not reachable",
            )
                .into_response()
        })?;
    upstream_stream
        .write_all(&upstream_request)
        .await
        .map_err(|_| {
            (StatusCode::BAD_GATEWAY, "upstream upgrade request failed").into_response()
        })?;

    let (head, leftover) = read_http_head(&mut upstream_stream)
        .await
        .map_err(bad_gateway_response)?;
    let (status, headers) = parse_http_response_head(&head).map_err(bad_gateway_response)?;
    let mut response_builder = axum::http::Response::builder().status(status);
    for (name, value) in headers {
        if is_upgrade_response_header_forwardable(&name) {
            response_builder = response_builder.header(name, value);
        }
    }

    tokio::spawn(async move {
        let Ok(upgraded) = on_upgrade.await else {
            return;
        };
        let mut downstream = hyper_util::rt::TokioIo::new(upgraded);
        if !leftover.is_empty() && downstream.write_all(&leftover).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream).await;
    });

    response_builder
        .body(Body::empty())
        .map_err(|_| (StatusCode::BAD_GATEWAY, "failed to build upgrade response").into_response())
}

fn build_upgrade_request_bytes(
    request: &axum::extract::Request,
    upstream: &lpm_common::LocalTarget,
    host_header: &str,
    forwarded_proto: &str,
) -> Vec<u8> {
    use axum::http::header;

    let request_path = request.uri().path_and_query().map_or("/", |p| p.as_str());
    let path = upstream.upstream_path(request_path);
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(request.method().as_str().as_bytes());
    bytes.extend_from_slice(b" ");
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(b" HTTP/1.1\r\n");

    for (name, value) in request.headers() {
        if is_forwardable_upgrade_request_header(name.as_str()) {
            bytes.extend_from_slice(name.as_str().as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
    }

    bytes.extend_from_slice(b"host: ");
    bytes.extend_from_slice(upstream.authority().as_bytes());
    bytes.extend_from_slice(b"\r\nx-forwarded-host: ");
    bytes.extend_from_slice(host_header.as_bytes());
    bytes.extend_from_slice(b"\r\nx-forwarded-proto: ");
    bytes.extend_from_slice(forwarded_proto.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    if request.headers().get(header::CONNECTION).is_none() {
        bytes.extend_from_slice(b"connection: upgrade\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    bytes
}

async fn read_http_head(
    stream: &mut tokio::net::TcpStream,
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    use tokio::io::AsyncReadExt;

    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| "upstream upgrade response failed")?;
        if read == 0 {
            return Err("upstream closed before upgrade response");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_header_end(&buffer) {
            let body_start = index + 4;
            let leftover = buffer[body_start..].to_vec();
            buffer.truncate(body_start);
            return Ok((buffer, leftover));
        }
        if buffer.len() > HTTP_HEAD_CAP_BYTES {
            return Err("upstream upgrade response headers are too large");
        }
    }
}

fn parse_http_response_head(head: &[u8]) -> Result<ParsedHttpResponseHead, &'static str> {
    use axum::http::{HeaderName, HeaderValue, StatusCode};

    let text =
        std::str::from_utf8(head).map_err(|_| "upstream upgrade response was not valid HTTP")?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or("missing upstream upgrade status")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .ok_or("invalid upstream upgrade status")?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("invalid upstream upgrade header");
        };
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "invalid upstream upgrade header name")?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|_| "invalid upstream upgrade header value")?;
        headers.push((name, value));
    }
    Ok((status, headers))
}

fn bad_gateway_response(message: &'static str) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    (StatusCode::BAD_GATEWAY, message).into_response()
}

pub(crate) fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn is_forwardable_http_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "x-forwarded-host"
            | "x-forwarded-proto"
    )
}

fn is_forwardable_upgrade_request_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "content-length" | "transfer-encoding" | "x-forwarded-host" | "x-forwarded-proto"
    )
}

fn is_upgrade_response_header_forwardable(name: &axum::http::HeaderName) -> bool {
    !matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "content-length" | "transfer-encoding"
    )
}

fn is_upgrade_request(headers: &axum::http::HeaderMap) -> bool {
    use axum::http::header;

    headers.get(header::UPGRADE).is_some()
        && headers
            .get_all(header::CONNECTION)
            .iter()
            .any(|value| value.to_str().is_ok_and(header_has_upgrade_token))
}

fn header_has_upgrade_token(value: &str) -> bool {
    value
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}
