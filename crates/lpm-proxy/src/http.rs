use super::*;

const HTTP_CONNECTION_LIMIT: usize = 64;
const HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct FrontendUpstream {
    target: Arc<RwLock<lpm_common::LocalTarget>>,
}

impl FrontendUpstream {
    pub fn new(target: lpm_common::LocalTarget) -> Result<Self, ProxyError> {
        validate_frontend_upstream(&target)?;
        Ok(Self {
            target: Arc::new(RwLock::new(target)),
        })
    }

    pub fn update(&self, target: lpm_common::LocalTarget) -> Result<(), ProxyError> {
        validate_frontend_upstream(&target)?;
        *self
            .target
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = target;
        Ok(())
    }

    fn current(&self) -> lpm_common::LocalTarget {
        self.target
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[derive(Clone)]
pub struct HttpProxyState {
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        axum::body::Body,
    >,
    forwarded_proto: &'static str,
    fallback_upstream: Option<FrontendUpstream>,
    upstream_header_timeout: Duration,
    upgrade_capacity: Arc<tokio::sync::Semaphore>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl HttpProxyState {
    pub fn new(registry: Arc<tokio::sync::Mutex<RouteRegistry>>) -> Self {
        Self::with_forwarded_proto(registry, "http")
    }

    pub(crate) fn with_forwarded_proto(
        registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
        forwarded_proto: &'static str,
    ) -> Self {
        let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
        connector.set_connect_timeout(Some(UPSTREAM_CONNECT_TIMEOUT));
        let (shutdown, _) = tokio::sync::watch::channel(false);
        Self {
            registry,
            client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build(connector),
            forwarded_proto,
            fallback_upstream: None,
            upstream_header_timeout: Duration::from_secs(10),
            upgrade_capacity: Arc::new(tokio::sync::Semaphore::new(64)),
            shutdown,
        }
    }

    pub(crate) fn for_upstream(upstream: FrontendUpstream, forwarded_proto: &'static str) -> Self {
        let mut state = Self::with_forwarded_proto(
            Arc::new(tokio::sync::Mutex::new(RouteRegistry::new())),
            forwarded_proto,
        );
        state.fallback_upstream = Some(upstream);
        state
    }

    pub(crate) fn with_shutdown(mut self, shutdown: tokio::sync::watch::Sender<bool>) -> Self {
        self.shutdown = shutdown;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_limits(
        mut self,
        upstream_header_timeout: Duration,
        upgrades: usize,
    ) -> Self {
        self.upstream_header_timeout = upstream_header_timeout;
        self.upgrade_capacity = Arc::new(tokio::sync::Semaphore::new(upgrades));
        self
    }
}

#[derive(Clone)]
struct HttpRedirectState {
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    https_port: u16,
}

#[derive(Clone)]
enum HttpFrontendState {
    Proxy(Arc<HttpProxyState>),
    Redirect(HttpRedirectState),
}

pub struct HttpProxyHandle {
    pub(crate) addr: SocketAddr,
    pub(crate) shutdown: Option<tokio::sync::watch::Sender<bool>>,
    pub(crate) upstream: Option<FrontendUpstream>,
}

impl HttpProxyHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn update_upstream(&self, upstream: lpm_common::LocalTarget) -> Result<(), ProxyError> {
        self.validate_upstream_update(&upstream)?;
        let target = self.upstream.as_ref().ok_or_else(|| {
            ProxyError::Http("proxy handle does not have a direct upstream".to_string())
        })?;
        target.update(upstream)
    }

    pub fn validate_upstream_update(
        &self,
        upstream: &lpm_common::LocalTarget,
    ) -> Result<(), ProxyError> {
        validate_frontend_upstream(upstream)?;
        self.upstream.as_ref().ok_or_else(|| {
            ProxyError::Http("proxy handle does not have a direct upstream".to_string())
        })?;
        Ok(())
    }

    pub fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(true);
        }
    }
}

impl Drop for HttpProxyHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(true);
        }
    }
}

pub(crate) async fn wait_for_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow_and_update() {
        if shutdown.changed().await.is_err() {
            break;
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
    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Http(format!("read HTTP proxy bind addr: {err}")))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let state = HttpProxyState::new(registry).with_shutdown(shutdown_tx.clone());

    tokio::spawn(run_http_listener(
        listener,
        HttpFrontendState::Proxy(Arc::new(state)),
        shutdown_rx,
    ));

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
        upstream: None,
    })
}

/// Start an HTTP frontend on an already-bound listener for a verified loopback target.
pub fn start_http_frontend_on_listener(
    listener: tokio::net::TcpListener,
    upstream: lpm_common::LocalTarget,
) -> Result<HttpProxyHandle, ProxyError> {
    start_http_frontend_on_listener_with_upstream(listener, FrontendUpstream::new(upstream)?)
}

pub fn start_http_frontend_on_listener_with_upstream(
    listener: tokio::net::TcpListener,
    upstream: FrontendUpstream,
) -> Result<HttpProxyHandle, ProxyError> {
    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Http(format!("read HTTP frontend bind addr: {err}")))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let state =
        HttpProxyState::for_upstream(upstream.clone(), "http").with_shutdown(shutdown_tx.clone());

    tokio::spawn(run_http_listener(
        listener,
        HttpFrontendState::Proxy(Arc::new(state)),
        shutdown_rx,
    ));

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
        upstream: Some(upstream),
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
    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Http(format!("read HTTP redirect bind addr: {err}")))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let state = HttpFrontendState::Redirect(HttpRedirectState {
        registry,
        https_port,
    });

    tokio::spawn(run_http_listener(listener, state, shutdown_rx));

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
        upstream: None,
    })
}

async fn run_http_listener(
    listener: tokio::net::TcpListener,
    state: HttpFrontendState,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let capacity = Arc::new(tokio::sync::Semaphore::new(HTTP_CONNECTION_LIMIT));
    let mut connections = tokio::task::JoinSet::new();

    loop {
        while connections.try_join_next().is_some() {}
        let permit = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => break,
            permit = Arc::clone(&capacity).acquire_owned() => {
                let Ok(permit) = permit else {
                    break;
                };
                permit
            }
        };
        let accepted = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => break,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else {
            continue;
        };
        let state = state.clone();
        let mut connection_shutdown = shutdown.clone();
        connections.spawn(async move {
            let _permit = permit;
            tokio::select! {
                biased;
                _ = wait_for_shutdown(&mut connection_shutdown) => {}
                _ = serve_http_connection(stream, state) => {}
            }
        });
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn serve_http_connection(stream: tokio::net::TcpStream, state: HttpFrontendState) {
    let io = hyper_util::rt::TokioIo::new(stream);
    let service =
        hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let state = state.clone();
            async move {
                let request = request.map(axum::body::Body::new);
                let response = match state {
                    HttpFrontendState::Proxy(state) => proxy_http_request_inner(state, request)
                        .await
                        .unwrap_or_else(|response| response),
                    HttpFrontendState::Redirect(state) => {
                        redirect_http_request_inner(state, request).await
                    }
                };
                Ok::<_, Infallible>(response)
            }
        });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HTTP_HEADER_TIMEOUT)
        .max_buf_size(HTTP_HEAD_CAP_BYTES);
    let _ = builder.serve_connection(io, service).with_upgrades().await;
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

async fn redirect_http_request_inner(
    state: HttpRedirectState,
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

pub(crate) async fn proxy_http_request_inner(
    state: Arc<HttpProxyState>,
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
        .or_else(|| {
            state
                .fallback_upstream
                .as_ref()
                .map(|upstream| upstream.current())
        });
    let Some(upstream) = upstream else {
        return Err((StatusCode::MISDIRECTED_REQUEST, "unknown local proxy host").into_response());
    };

    if is_upgrade_request(request.headers()) {
        return proxy_upgrade_request(request, upstream, host_header, state).await;
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
        if is_forwardable_http_header(name.as_str())
            && !connection_header_nominates(&parts.headers, name)
        {
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
    let upstream = match tokio::time::timeout(
        state.upstream_header_timeout,
        state.client.request(upstream_request),
    )
    .await
    {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(_)) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                "upstream dev server request failed",
            )
                .into_response());
        }
        Err(_) => {
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                "upstream dev server response headers timed out",
            )
                .into_response());
        }
    };

    let (upstream_parts, upstream_body) = upstream.into_parts();
    let mut response_builder = axum::http::Response::builder().status(upstream_parts.status);
    for (name, value) in &upstream_parts.headers {
        if is_forwardable_http_header(name.as_str())
            && !connection_header_nominates(&upstream_parts.headers, name)
        {
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
    state: Arc<HttpProxyState>,
) -> Result<axum::response::Response, axum::response::Response> {
    use axum::body::Body;
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    let permit = Arc::clone(&state.upgrade_capacity)
        .try_acquire_owned()
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "proxy upgrade capacity is exhausted",
            )
                .into_response()
        })?;
    let downstream_upgrade = hyper::upgrade::on(&mut request);
    let requested_upgrade = request
        .headers()
        .get(header::UPGRADE)
        .cloned()
        .ok_or_else(|| bad_gateway_response("upgrade request is missing its protocol"))?;
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str());
    let mut upstream_builder = axum::http::Request::builder()
        .method(request.method())
        .uri(upstream.upstream_path(path));
    for (name, value) in request.headers() {
        if is_forwardable_upgrade_request_header(name.as_str())
            && !connection_header_nominates(request.headers(), name)
        {
            upstream_builder = upstream_builder.header(name, value);
        }
    }
    upstream_builder = upstream_builder
        .header(header::HOST, upstream.authority())
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, requested_upgrade.clone())
        .header("x-forwarded-host", host_header)
        .header("x-forwarded-proto", state.forwarded_proto);
    let upstream_request = upstream_builder.body(Body::empty()).map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "failed to build upstream upgrade request",
        )
            .into_response()
    })?;
    let upstream_result = tokio::time::timeout(state.upstream_header_timeout, async {
        let upstream_stream = tokio::net::TcpStream::connect((upstream.address, upstream.port))
            .await
            .map_err(|_| "upstream dev server is not reachable")?;
        let io = hyper_util::rt::TokioIo::new(upstream_stream);
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(HTTP_HEAD_CAP_BYTES)
            .handshake(io)
            .await
            .map_err(|_| "upstream upgrade handshake failed")?;
        tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
        sender
            .send_request(upstream_request)
            .await
            .map_err(|_| "upstream upgrade request failed")
    })
    .await;
    let mut upstream_response = match upstream_result {
        Ok(Ok(response)) => response,
        Ok(Err(message)) => return Err(bad_gateway_response(message)),
        Err(_) => {
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                "upstream upgrade response headers timed out",
            )
                .into_response());
        }
    };

    if upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (parts, body) = upstream_response.into_parts();
        let mut response_builder = axum::http::Response::builder().status(parts.status);
        for (name, value) in &parts.headers {
            if is_forwardable_http_header(name.as_str())
                && !connection_header_nominates(&parts.headers, name)
            {
                response_builder = response_builder.header(name, value);
            }
        }
        return response_builder.body(Body::new(body)).map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "failed to build declined upgrade response",
            )
                .into_response()
        });
    }

    let Some(response_upgrade) = upstream_response.headers().get(header::UPGRADE).cloned() else {
        return Err(bad_gateway_response(
            "upstream upgrade response is missing its protocol",
        ));
    };
    if !same_upgrade_protocol(&requested_upgrade, &response_upgrade) {
        return Err(bad_gateway_response(
            "upstream selected a different upgrade protocol",
        ));
    }
    let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
    let (parts, _body) = upstream_response.into_parts();
    let mut response_builder = axum::http::Response::builder().status(parts.status);
    for (name, value) in &parts.headers {
        if is_forwardable_upgrade_response_header(name.as_str())
            && !connection_header_nominates(&parts.headers, name)
        {
            response_builder = response_builder.header(name, value);
        }
    }
    response_builder = response_builder
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, response_upgrade);
    let response = response_builder.body(Body::empty()).map_err(|_| {
        (StatusCode::BAD_GATEWAY, "failed to build upgrade response").into_response()
    })?;
    let mut shutdown = state.shutdown.subscribe();
    tokio::spawn(async move {
        let _permit = permit;
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {}
            _ = async {
                let Ok(downstream_upgraded) = downstream_upgrade.await else {
                    return;
                };
                let Ok(upstream_upgraded) = upstream_upgrade.await else {
                    return;
                };
                let mut downstream = hyper_util::rt::TokioIo::new(downstream_upgraded);
                let mut upstream = hyper_util::rt::TokioIo::new(upstream_upgraded);
                let _ = tokio::io::copy_bidirectional(
                    &mut downstream,
                    &mut upstream,
                )
                .await;
            } => {}
        }
    });

    Ok(response)
}

fn bad_gateway_response(message: &'static str) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    (StatusCode::BAD_GATEWAY, message).into_response()
}

#[cfg(test)]
pub(crate) fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn is_forwardable_http_header(name: &str) -> bool {
    ![
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "x-forwarded-host",
        "x-forwarded-proto",
    ]
    .iter()
    .any(|blocked| name.eq_ignore_ascii_case(blocked))
}

fn is_forwardable_upgrade_request_header(name: &str) -> bool {
    ![
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "host",
        "content-length",
        "x-forwarded-host",
        "x-forwarded-proto",
    ]
    .iter()
    .any(|blocked| name.eq_ignore_ascii_case(blocked))
}

fn is_forwardable_upgrade_response_header(name: &str) -> bool {
    ![
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "content-length",
    ]
    .iter()
    .any(|blocked| name.eq_ignore_ascii_case(blocked))
}

fn connection_header_nominates(
    headers: &axum::http::HeaderMap,
    candidate: &axum::http::HeaderName,
) -> bool {
    headers
        .get_all(axum::http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(candidate.as_str()))
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

fn same_upgrade_protocol(
    requested: &axum::http::HeaderValue,
    selected: &axum::http::HeaderValue,
) -> bool {
    requested
        .to_str()
        .ok()
        .zip(selected.to_str().ok())
        .is_some_and(|(requested, selected)| requested.trim().eq_ignore_ascii_case(selected.trim()))
}
