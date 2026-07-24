use super::*;

#[derive(Clone, Default)]
pub(crate) struct TlsCertificateStore {
    keys_by_host: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl TlsCertificateStore {
    fn replace(&self, keys_by_host: HashMap<String, Arc<CertifiedKey>>) {
        if let Ok(mut guard) = self.keys_by_host.write() {
            *guard = keys_by_host;
        }
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
    super::http::validate_frontend_upstream(&upstream)?;
    let key = load_certified_key(cert_path, key_path)?;
    let addr = listener
        .local_addr()
        .map_err(|err| ProxyError::Tls(format!("read TLS frontend bind addr: {err}")))?;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedTlsCertResolver { key }));
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let state = HttpProxyState::for_upstream(upstream, "https");

    tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    let state = state.clone();
                    tokio::spawn(async move {
                        serve_tls_http_connection(acceptor, stream, state).await;
                    });
                }
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }
    });

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
    })
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
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(TlsCertResolver { store: cert_store }));
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let state = HttpProxyState::with_forwarded_proto(registry, "https");

    tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    let state = state.clone();
                    tokio::spawn(async move {
                        serve_tls_http_connection(acceptor, stream, state).await;
                    });
                }
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }
    });

    Ok(HttpProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
    })
}

async fn serve_tls_http_connection(
    acceptor: tokio_rustls::TlsAcceptor,
    stream: tokio::net::TcpStream,
    state: HttpProxyState,
) {
    let Ok(tls_stream) = acceptor.accept(stream).await else {
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
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await;
}

pub(crate) fn refresh_tls_cert_store(cert_store: &TlsCertificateStore, routes: &[RouteStatus]) {
    let mut keys_by_host = HashMap::with_capacity(routes.len());
    for route in routes {
        if let Ok(Some(key)) = load_project_certified_key(&route.project_dir, &route.host) {
            keys_by_host.insert(route.host.clone(), key);
        }
    }
    cert_store.replace(keys_by_host);
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
    if lpm_cert::cert::needs_renewal(&cert_path).map_err(cert_error_to_tls)? {
        return Ok(false);
    }
    if !lpm_cert::cert::covers_requested_hostnames(&cert_path, hosts).map_err(cert_error_to_tls)? {
        return Ok(false);
    }
    if !hosts.is_empty()
        && !lpm_cert::cert::project_cert_has_intermediate(&cert_path).map_err(cert_error_to_tls)?
    {
        return Ok(false);
    }
    let ca_path = lpm_cert::paths::ca_cert_path().map_err(cert_error_to_tls)?;
    if !ca_path.is_file() {
        return Ok(false);
    }
    lpm_cert::cert::project_cert_chains_to_root(&cert_path, &ca_path).map_err(cert_error_to_tls)
}

fn cert_error_to_tls(err: lpm_common::LpmError) -> ProxyError {
    ProxyError::Tls(err.to_string())
}

fn load_project_certified_key(
    project_dir: &Path,
    host: &str,
) -> Result<Option<Arc<CertifiedKey>>, ProxyError> {
    let cert_dir = project_dir.join(".lpm").join("certs");
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    if !cert_path.is_file() || !key_path.is_file() {
        return Ok(None);
    }

    if !cert_covers_hostname(&cert_path, host)? {
        return Ok(None);
    }

    load_certified_key(&cert_path, &key_path).map(Some)
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>, ProxyError> {
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };

    let cert_pem =
        lpm_common::read_file_capped(cert_path, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
            .map_err(|err| ProxyError::Tls(format!("read {}: {err}", cert_path.display())))?;
    let certs = pem::parse_many(cert_pem)
        .map_err(|err| ProxyError::Tls(format!("parse {}: {err}", cert_path.display())))?
        .into_iter()
        .filter(|pem| pem.tag() == "CERTIFICATE")
        .map(|pem| CertificateDer::from(pem.contents().to_vec()))
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(ProxyError::Tls(format!(
            "{} does not contain a certificate",
            cert_path.display()
        )));
    }

    let key_pem =
        lpm_common::read_file_capped(key_path, lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES)
            .map_err(|err| ProxyError::Tls(format!("read {}: {err}", key_path.display())))?;
    let key = pem::parse_many(key_pem)
        .map_err(|err| ProxyError::Tls(format!("parse {}: {err}", key_path.display())))?
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
                key_path.display()
            ))
        })?;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let certified_key = CertifiedKey::from_der(certs, key, &provider)
        .map_err(|err| ProxyError::Tls(format!("load TLS keypair: {err}")))?;
    Ok(Arc::new(certified_key))
}

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
