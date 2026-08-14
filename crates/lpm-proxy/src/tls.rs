use super::*;

const TLS_CONNECTION_LIMIT: usize = 64;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Default)]
pub(crate) struct TlsCertificateStore {
    keys_by_host: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl TlsCertificateStore {
    pub(crate) fn snapshot(&self) -> Result<HashMap<String, Arc<CertifiedKey>>, ProxyError> {
        self.keys_by_host
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| ProxyError::Tls("TLS certificate store lock is poisoned".to_string()))
    }

    pub(crate) fn replace(
        &self,
        keys_by_host: HashMap<String, Arc<CertifiedKey>>,
    ) -> Result<(), ProxyError> {
        let mut guard = self
            .keys_by_host
            .write()
            .map_err(|_| ProxyError::Tls("TLS certificate store lock is poisoned".to_string()))?;
        *guard = keys_by_host;
        Ok(())
    }

    pub(crate) fn get(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = canonical_host(host).ok()?;
        self.keys_by_host.read().ok()?.get(&host).cloned()
    }
}

#[derive(Clone)]
struct TlsCertResolver {
    store: TlsCertificateStore,
}

#[derive(Clone)]
struct FixedTlsCertResolver {
    key: Arc<CertifiedKey>,
}

struct LeaseBoundSigningKey {
    inner: Arc<dyn rustls::sign::SigningKey>,
    _lease: lpm_cert::RuntimeCertificateLease,
}

impl fmt::Debug for LeaseBoundSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseBoundSigningKey")
            .finish_non_exhaustive()
    }
}

impl rustls::sign::SigningKey for LeaseBoundSigningKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.inner.choose_scheme(offered)
    }

    fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.inner.algorithm()
    }
}

impl fmt::Debug for FixedTlsCertResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedTlsCertResolver")
            .finish_non_exhaustive()
    }
}

impl rustls::server::ResolvesServerCert for FixedTlsCertResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }
}

impl fmt::Debug for TlsCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsCertResolver").finish_non_exhaustive()
    }
}

impl rustls::server::ResolvesServerCert for TlsCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.store.get(client_hello.server_name()?)
    }
}

pub(crate) async fn start_tls_proxy(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    cert_store: TlsCertificateStore,
    port: u16,
) -> Result<HttpProxyHandle, ProxyError> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .map_err(|err| ProxyError::Tls(format_loopback_bind_error("TLS proxy", port, &err)))?;
    start_tls_proxy_on_listener(registry, cert_store, listener)
}

/// Terminate TLS on an already-bound listener and forward to a plain HTTP loopback target.
pub async fn start_tls_frontend_on_listener(
    listener: tokio::net::TcpListener,
    cert_path: &Path,
    key_path: &Path,
    upstream: lpm_common::LocalTarget,
) -> Result<HttpProxyHandle, ProxyError> {
    let upstream = super::http::FrontendUpstream::new(upstream)?;
    let key = load_certified_key(cert_path, key_path)?;
    start_tls_frontend_with_key(listener, key, upstream).await
}

async fn start_tls_frontend_with_key(
    listener: tokio::net::TcpListener,
    key: Arc<CertifiedKey>,
    upstream: super::http::FrontendUpstream,
) -> Result<HttpProxyHandle, ProxyError> {
    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Tls(format!("read TLS frontend bind addr: {err}")))?;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedTlsCertResolver { key }));
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let state = Arc::new(
        HttpProxyState::for_upstream(upstream.clone(), "https").with_shutdown(shutdown_tx.clone()),
    );

    tokio::spawn(run_tls_listener(listener, acceptor, state, shutdown_rx));

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
        upstream: Some(upstream),
    })
}

/// Terminate TLS with already verified in-memory PEM material.
pub async fn start_tls_frontend_on_listener_with_pem(
    listener: tokio::net::TcpListener,
    cert_pem: &[u8],
    key_pem: &[u8],
    upstream: lpm_common::LocalTarget,
) -> Result<HttpProxyHandle, ProxyError> {
    let upstream = super::http::FrontendUpstream::new(upstream)?;
    let key = load_certified_key_bytes(cert_pem, key_pem, "project certificate")?;
    start_tls_frontend_with_key(listener, key, upstream).await
}

/// Terminate TLS with verified PEM material and a shared upstream target.
pub async fn start_tls_frontend_on_listener_with_pem_and_upstream(
    listener: tokio::net::TcpListener,
    cert_pem: &[u8],
    key_pem: &[u8],
    upstream: super::http::FrontendUpstream,
) -> Result<HttpProxyHandle, ProxyError> {
    let key = load_certified_key_bytes(cert_pem, key_pem, "project certificate")?;
    start_tls_frontend_with_key(listener, key, upstream).await
}

fn start_tls_proxy_on_listener(
    registry: Arc<tokio::sync::Mutex<RouteRegistry>>,
    cert_store: TlsCertificateStore,
    listener: tokio::net::TcpListener,
) -> Result<HttpProxyHandle, ProxyError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Tls(format!("read TLS proxy bind addr: {err}")))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(TlsCertResolver { store: cert_store }));
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let state = Arc::new(
        HttpProxyState::with_forwarded_proto(registry, "https").with_shutdown(shutdown_tx.clone()),
    );

    tokio::spawn(run_tls_listener(listener, acceptor, state, shutdown_rx));

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
        upstream: None,
    })
}

async fn run_tls_listener(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    state: Arc<HttpProxyState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let capacity = Arc::new(tokio::sync::Semaphore::new(TLS_CONNECTION_LIMIT));
    let mut connections = tokio::task::JoinSet::new();

    loop {
        while connections.try_join_next().is_some() {}
        let permit = tokio::select! {
            biased;
            _ = super::http::wait_for_shutdown(&mut shutdown) => break,
            permit = Arc::clone(&capacity).acquire_owned() => {
                let Ok(permit) = permit else {
                    break;
                };
                permit
            }
        };
        let accepted = tokio::select! {
            biased;
            _ = super::http::wait_for_shutdown(&mut shutdown) => break,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else {
            continue;
        };
        let acceptor = acceptor.clone();
        let state = state.clone();
        let mut connection_shutdown = shutdown.clone();
        connections.spawn(async move {
            let _permit = permit;
            tokio::select! {
                biased;
                _ = super::http::wait_for_shutdown(&mut connection_shutdown) => {}
                _ = serve_tls_http_connection(acceptor, stream, state) => {}
            }
        });
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn serve_tls_http_connection(
    acceptor: tokio_rustls::TlsAcceptor,
    stream: tokio::net::TcpStream,
    state: Arc<HttpProxyState>,
) {
    let Ok(Ok(tls_stream)) =
        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
    else {
        return;
    };
    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let service =
        hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let state = state.clone();
            async move {
                let request = request.map(axum::body::Body::new);
                let response = proxy_http_request_inner(state, request)
                    .await
                    .unwrap_or_else(|response| response);
                Ok::<_, Infallible>(response)
            }
        });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(TLS_HTTP_HEADER_TIMEOUT)
        .max_buf_size(HTTP_HEAD_CAP_BYTES);
    let _ = builder.serve_connection(io, service).with_upgrades().await;
}

pub(crate) fn refresh_tls_cert_store(
    cert_store: &TlsCertificateStore,
    routes: &[RouteStatus],
) -> Result<(), ProxyError> {
    let mut keys_by_host = HashMap::with_capacity(routes.len());
    let mut hosts_by_project = BTreeMap::<PathBuf, Vec<String>>::new();
    for route in routes {
        hosts_by_project
            .entry(route.project_dir.clone())
            .or_default()
            .push(route.host.clone());
    }
    for (project_dir, mut hosts) in hosts_by_project {
        hosts.sort_unstable();
        hosts.dedup();
        let material = lpm_cert::load_project_https_material(&project_dir, &hosts)
            .map_err(cert_error_to_tls)?;
        let key = load_certified_key_bytes_with_lease(
            &material.cert_pem,
            &material.key_pem,
            &project_dir.display().to_string(),
            material.runtime_lease,
        )?;
        for host in hosts {
            keys_by_host.insert(host, Arc::clone(&key));
        }
    }
    cert_store.replace(keys_by_host)
}

pub(crate) async fn prepare_tls_certificates_if_enabled(
    tls_cert_store: Option<&TlsCertificateStore>,
    routes: &[Route],
) -> Result<(), ProxyError> {
    if tls_cert_store.is_some() {
        prepare_tls_certificates_for_routes(routes).await?;
    }
    Ok(())
}

async fn prepare_tls_certificates_for_routes(routes: &[Route]) -> Result<(), ProxyError> {
    let groups = group_tls_hosts_by_project(routes)?;
    tokio::task::spawn_blocking(move || prepare_tls_certificates_blocking(groups))
        .await
        .map_err(|err| ProxyError::Tls(format!("prepare TLS certificates: {err}")))?
}

fn group_tls_hosts_by_project(
    routes: &[Route],
) -> Result<BTreeMap<PathBuf, Vec<String>>, ProxyError> {
    if routes.is_empty() {
        return Err(ProxyError::EmptyRouteSet);
    }

    let mut groups: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    let mut seen = HashSet::with_capacity(routes.len());
    for route in routes {
        let host = canonical_host(&route.host)?;
        if !seen.insert(host.clone()) {
            return Err(ProxyError::DuplicateHostInRouteSet { host });
        }
        groups
            .entry(route.project_dir.clone())
            .or_default()
            .push(host);
    }

    for hosts in groups.values_mut() {
        hosts.sort_unstable();
        hosts.dedup();
    }
    Ok(groups)
}

fn prepare_tls_certificates_blocking(
    groups: BTreeMap<PathBuf, Vec<String>>,
) -> Result<(), ProxyError> {
    for (project_dir, hosts) in groups {
        if project_leaf_is_ready_for_hosts(&project_dir, &hosts).unwrap_or(false) {
            continue;
        }
        lpm_cert::ensure_https_with_consent(
            &project_dir,
            &hosts,
            lpm_cert::TrustStoreConsent::Decline,
        )
        .map_err(|err| {
            ProxyError::Tls(format!(
                "prepare project certificate for {}: {err}",
                project_dir.display()
            ))
        })?;
    }
    Ok(())
}

fn project_leaf_is_ready_for_hosts(
    project_dir: &Path,
    hosts: &[String],
) -> Result<bool, ProxyError> {
    let cert_dir = project_dir.join(".lpm").join("certs");
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    if !cert_path.is_file() || !key_path.is_file() {
        return Ok(false);
    }
    if !lpm_cert::cert::project_cert_key_matches(&cert_path, &key_path)
        .map_err(cert_error_to_tls)?
    {
        return Ok(false);
    }
    let ca_path = lpm_cert::paths::ca_cert_path().map_err(cert_error_to_tls)?;
    if !ca_path.is_file() {
        return Ok(false);
    }
    Ok(lpm_cert::cert::validate_project_server_chain(&cert_path, &ca_path, hosts).is_ok())
}

fn cert_error_to_tls(err: lpm_common::LpmError) -> ProxyError {
    ProxyError::Tls(err.to_string())
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>, ProxyError> {
    let cert_pem =
        lpm_common::read_file_capped(cert_path, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
            .map_err(|err| ProxyError::Tls(format!("read {}: {err}", cert_path.display())))?;
    let key_pem =
        lpm_common::read_file_capped(key_path, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
            .map_err(|err| ProxyError::Tls(format!("read {}: {err}", key_path.display())))?;
    load_certified_key_bytes(&cert_pem, &key_pem, &cert_path.display().to_string())
}

fn load_certified_key_bytes(
    cert_pem: &[u8],
    key_pem: &[u8],
    label: &str,
) -> Result<Arc<CertifiedKey>, ProxyError> {
    parse_certified_key_bytes(cert_pem, key_pem, label).map(Arc::new)
}

fn load_certified_key_bytes_with_lease(
    cert_pem: &[u8],
    key_pem: &[u8],
    label: &str,
    runtime_lease: lpm_cert::RuntimeCertificateLease,
) -> Result<Arc<CertifiedKey>, ProxyError> {
    let mut certified_key = parse_certified_key_bytes(cert_pem, key_pem, label)?;
    certified_key.key = Arc::new(LeaseBoundSigningKey {
        inner: Arc::clone(&certified_key.key),
        _lease: runtime_lease,
    });
    Ok(Arc::new(certified_key))
}

fn parse_certified_key_bytes(
    cert_pem: &[u8],
    key_pem: &[u8],
    label: &str,
) -> Result<CertifiedKey, ProxyError> {
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };

    let certs = pem::parse_many(cert_pem)
        .map_err(|err| ProxyError::Tls(format!("parse {label}: {err}")))?
        .into_iter()
        .filter(|pem| pem.tag() == "CERTIFICATE")
        .map(|pem| CertificateDer::from(pem.contents().to_vec()))
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(ProxyError::Tls(format!(
            "{} does not contain a certificate",
            label
        )));
    }
    let key = pem::parse_many(key_pem)
        .map_err(|err| ProxyError::Tls(format!("parse {label} private key: {err}")))?
        .into_iter()
        .find_map(|pem| match pem.tag() {
            "PRIVATE KEY" => Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                pem.contents().to_vec(),
            ))),
            "EC PRIVATE KEY" => Some(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(
                pem.contents().to_vec(),
            ))),
            "RSA PRIVATE KEY" => Some(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
                pem.contents().to_vec(),
            ))),
            _ => None,
        })
        .ok_or_else(|| {
            ProxyError::Tls(format!(
                "{} does not contain a supported private key",
                label
            ))
        })?;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let certified_key = CertifiedKey::from_der(certs, key, &provider)
        .map_err(|err| ProxyError::Tls(format!("load TLS keypair: {err}")))?;
    Ok(certified_key)
}

#[cfg(all(test, unix))]
pub(crate) fn cert_covers_hostname(cert_path: &Path, host: &str) -> Result<bool, ProxyError> {
    let cert_pem =
        lpm_common::read_file_capped(cert_path, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
            .map_err(|err| ProxyError::Tls(format!("read {}: {err}", cert_path.display())))?;
    let pem = pem::parse(cert_pem)
        .map_err(|err| ProxyError::Tls(format!("parse {}: {err}", cert_path.display())))?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|err| ProxyError::Tls(format!("parse X.509 {}: {err}", cert_path.display())))?;
    let Some(san) = cert.subject_alternative_name().ok().flatten() else {
        return Ok(false);
    };
    Ok(san.value.general_names.iter().any(|name| {
        matches!(
            name,
            x509_parser::extensions::GeneralName::DNSName(name)
                if name.eq_ignore_ascii_case(host)
        )
    }))
}

#[cfg(test)]
mod renewal_tests {
    use super::*;

    #[test]
    fn expired_project_certificate_is_not_ready_for_tls_publication() {
        let project = tempfile::tempdir().unwrap();
        let cert_dir = project.path().join(".lpm/certs");
        std::fs::create_dir_all(&cert_dir).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["app.localhost".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(cert_dir.join("key.pem"), key.serialize_pem()).unwrap();

        let ready = project_leaf_is_ready_for_hosts(project.path(), &["app.localhost".to_string()])
            .unwrap();

        assert!(!ready);
    }
}
