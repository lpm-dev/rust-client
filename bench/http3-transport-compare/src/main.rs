use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures_util::SinkExt as _;
use serde::Serialize;
use tokio::net::{UdpSocket, lookup_host};
use tokio_quiche::http3::driver::{
    ClientH3Event, H3Event, InboundFrame, NewClientRequest, OutboundFrame,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::settings::{ConnectionParams, Hooks, QuicSettings};
use url::Url;

#[derive(Debug, Parser)]
#[command(about = "Compare reqwest HTTP/3 and tokio-quiche for LPM Worker metadata RPCs")]
struct Args {
    #[arg(long, default_value = "https://lpm.dev/api/registry/batch-metadata")]
    url: String,
    #[arg(long, default_value_t = 5)]
    runs: usize,
    #[arg(long, value_delimiter = ',', default_value = "axios,react,zod,debug")]
    packages: Vec<String>,
    #[arg(long, default_value_t = true)]
    deep: bool,
    #[arg(long, value_delimiter = ',', default_value = "reqwest-h3,tokio-quiche")]
    transports: Vec<Transport>,
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Transport {
    ReqwestH3,
    TokioQuiche,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReqwestH3 => "reqwest-h3",
            Self::TokioQuiche => "tokio-quiche",
        }
    }
}

#[derive(Debug, Serialize)]
struct Output {
    url: String,
    runs: usize,
    packages: Vec<String>,
    deep: bool,
    timeout_ms: u64,
    samples: Vec<Sample>,
    summary: Vec<Summary>,
}

#[derive(Debug, Serialize)]
struct Sample {
    transport: &'static str,
    sample: usize,
    wall_ms: u128,
    success: bool,
    status: Option<u16>,
    body_bytes: Option<usize>,
    body_lines: Option<usize>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct Summary {
    transport: &'static str,
    samples: usize,
    failures: usize,
    wall_ms_median: Option<f64>,
    body_bytes_median: Option<f64>,
    body_lines_median: Option<f64>,
    statuses: BTreeMap<u16, usize>,
}

struct ProbeResponse {
    status: u16,
    body: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.runs == 0 {
        bail!("--runs must be >= 1");
    }
    if args.packages.is_empty() {
        bail!("--packages must contain at least one package name");
    }
    if args.transports.is_empty() {
        bail!("--transports must contain at least one transport");
    }

    let url = Url::parse(&args.url).with_context(|| format!("invalid URL: {}", args.url))?;
    if url.scheme() != "https" {
        bail!("HTTP/3 probes require an https URL");
    }

    let body = serde_json::to_vec(&serde_json::json!({
        "packages": args.packages,
        "deep": args.deep,
    }))?;
    let timeout = Duration::from_millis(args.timeout_ms);

    let mut samples = Vec::with_capacity(args.runs * args.transports.len());
    for sample in 1..=args.runs {
        for transport in ordered_transports(&args.transports, sample) {
            let started = Instant::now();
            let result = match transport {
                Transport::ReqwestH3 => {
                    tokio::time::timeout(timeout, send_reqwest_h3(url.as_str(), &body, timeout))
                        .await
                        .context("reqwest HTTP/3 probe timed out")?
                }
                Transport::TokioQuiche => {
                    tokio::time::timeout(timeout, send_tokio_quiche(&url, &body))
                        .await
                        .context("tokio-quiche probe timed out")?
                }
            };
            let wall_ms = started.elapsed().as_millis();
            samples.push(sample_record(transport, sample, wall_ms, result));
        }
    }

    let output = Output {
        url: args.url,
        runs: args.runs,
        packages: args.packages,
        deep: args.deep,
        timeout_ms: args.timeout_ms,
        summary: summarize(&samples),
        samples,
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn ordered_transports(transports: &[Transport], sample: usize) -> Vec<Transport> {
    let mut ordered = transports.to_vec();
    ordered.sort_unstable();
    if sample.is_multiple_of(2) {
        ordered.reverse();
    }
    ordered
}

fn sample_record(
    transport: Transport,
    sample: usize,
    wall_ms: u128,
    result: Result<ProbeResponse>,
) -> Sample {
    match result {
        Ok(response) => Sample {
            transport: transport.as_str(),
            sample,
            wall_ms,
            success: (200..300).contains(&response.status),
            status: Some(response.status),
            body_bytes: Some(response.body.len()),
            body_lines: Some(response.body.iter().filter(|&&b| b == b'\n').count()),
            error: None,
        },
        Err(error) => Sample {
            transport: transport.as_str(),
            sample,
            wall_ms,
            success: false,
            status: None,
            body_bytes: None,
            body_lines: None,
            error: Some(format!("{error:#}")),
        },
    }
}

async fn send_reqwest_h3(url: &str, body: &[u8], timeout: Duration) -> Result<ProbeResponse> {
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .connect_timeout(timeout)
        .timeout(timeout)
        .user_agent("lpm-http3-transport-compare/0.1")
        .build()
        .context("build reqwest HTTP/3 client")?;
    let response = client
        .post(url)
        .version(reqwest::Version::HTTP_3)
        .header("accept", "application/x-ndjson")
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .context("send reqwest HTTP/3 request")?;
    if response.version() != reqwest::Version::HTTP_3 {
        bail!("reqwest response negotiated {:?}", response.version());
    }
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .context("read reqwest response body")?;
    Ok(ProbeResponse {
        status,
        body: body.to_vec(),
    })
}

async fn send_tokio_quiche(url: &Url, body: &[u8]) -> Result<ProbeResponse> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL must include a host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL must include or imply a port"))?;
    let remote_addr = resolve_one(host, port).await?;
    let socket = bind_connected_udp(remote_addr).await?;

    let mut settings = QuicSettings::default();
    settings.verify_peer = true;
    settings.max_idle_timeout = Some(Duration::from_secs(30));
    settings.handshake_timeout = Some(Duration::from_secs(10));
    let params = ConnectionParams::new_client(settings, None, Hooks::default());

    let (driver, mut controller) = tokio_quiche::ClientH3Driver::new(Http3Settings::default());
    let _connection =
        tokio_quiche::quic::connect_with_config(socket.try_into()?, Some(host), &params, driver)
            .await
            .map_err(|error| anyhow!("connect tokio-quiche HTTP/3: {error}"))?;

    let (body_sender_tx, body_sender_rx) = tokio::sync::oneshot::channel();
    controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 1,
            headers: request_headers(url, body.len())?,
            body_writer: Some(body_sender_tx),
        })
        .map_err(|_| anyhow!("tokio-quiche request channel closed"))?;

    let mut body_sender = body_sender_rx
        .await
        .context("tokio-quiche body sender was not returned")?;
    body_sender
        .send(OutboundFrame::Body(Bytes::copy_from_slice(body), true))
        .await
        .context("send tokio-quiche request body")?;

    let mut status = None;
    while let Some(event) = controller.event_receiver_mut().recv().await {
        match event {
            ClientH3Event::Core(H3Event::IncomingHeaders(headers)) => {
                status = Some(response_status(&headers.headers)?);
                let mut body = Vec::new();
                if headers.read_fin {
                    return Ok(ProbeResponse {
                        status: status.unwrap_or(0),
                        body,
                    });
                }
                let mut recv = headers.recv;
                while let Some(frame) = recv.recv().await {
                    match frame {
                        InboundFrame::Body(chunk, fin) => {
                            body.extend_from_slice(&chunk);
                            if fin {
                                return Ok(ProbeResponse {
                                    status: status.unwrap_or(0),
                                    body,
                                });
                            }
                        }
                        InboundFrame::Datagram(_) => {}
                    }
                }
                bail!("tokio-quiche response body stream closed before FIN");
            }
            ClientH3Event::Core(H3Event::ConnectionError(error)) => {
                bail!("tokio-quiche connection error: {error}");
            }
            ClientH3Event::Core(H3Event::ConnectionShutdown(Some(error))) => {
                bail!("tokio-quiche connection shutdown: {error}");
            }
            ClientH3Event::Core(H3Event::ConnectionShutdown(None)) => {
                bail!("tokio-quiche connection shutdown before response");
            }
            _ => {}
        }
    }

    bail!(
        "tokio-quiche event stream ended before response{}",
        status
            .map(|s| format!(" with status {s}"))
            .unwrap_or_default()
    )
}

async fn resolve_one(host: &str, port: u16) -> Result<SocketAddr> {
    lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("no addresses resolved for {host}:{port}"))
}

async fn bind_connected_udp(remote_addr: SocketAddr) -> Result<UdpSocket> {
    let bind_addr = if remote_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("bind UDP socket at {bind_addr}"))?;
    socket
        .connect(remote_addr)
        .await
        .with_context(|| format!("connect UDP socket to {remote_addr}"))?;
    Ok(socket)
}

fn request_headers(url: &Url, body_len: usize) -> Result<Vec<Header>> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL must include a host"))?;
    let authority = match url.port() {
        Some(port) if Some(port) != url.port_or_known_default() => format!("{host}:{port}"),
        _ => host.to_string(),
    };
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    Ok(vec![
        Header::new(b":method", b"POST"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", authority.as_bytes()),
        Header::new(b":path", path.as_bytes()),
        Header::new(b"accept", b"application/x-ndjson"),
        Header::new(b"content-type", b"application/json"),
        Header::new(b"content-length", body_len.to_string().as_bytes()),
        Header::new(b"user-agent", b"lpm-http3-transport-compare/0.1"),
    ])
}

fn response_status(headers: &[Header]) -> Result<u16> {
    for header in headers {
        if header.name() == b":status" {
            let value = std::str::from_utf8(header.value()).context("status is not UTF-8")?;
            return value
                .parse()
                .with_context(|| format!("invalid status code: {value}"));
        }
    }
    bail!("response did not include :status")
}

fn summarize(samples: &[Sample]) -> Vec<Summary> {
    let mut by_transport: BTreeMap<&'static str, Vec<&Sample>> = BTreeMap::new();
    for sample in samples {
        by_transport
            .entry(sample.transport)
            .or_default()
            .push(sample);
    }

    by_transport
        .into_iter()
        .map(|(transport, samples)| {
            let successes: Vec<&Sample> = samples.iter().copied().filter(|s| s.success).collect();
            let mut statuses = BTreeMap::new();
            for sample in &successes {
                if let Some(status) = sample.status {
                    *statuses.entry(status).or_insert(0) += 1;
                }
            }
            Summary {
                transport,
                samples: samples.len(),
                failures: samples.len() - successes.len(),
                wall_ms_median: median(successes.iter().map(|s| s.wall_ms as f64)),
                body_bytes_median: median(
                    successes
                        .iter()
                        .filter_map(|s| s.body_bytes.map(|v| v as f64)),
                ),
                body_lines_median: median(
                    successes
                        .iter()
                        .filter_map(|s| s.body_lines.map(|v| v as f64)),
                ),
                statuses,
            }
        })
        .collect()
}

fn median(values: impl IntoIterator<Item = f64>) -> Option<f64> {
    let mut values: Vec<_> = values.into_iter().collect();
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        Some((values[mid - 1] + values[mid]) / 2.0)
    } else {
        Some(values[mid])
    }
}
