//! A front for a mock server that holds the requests a test picks until the
//! test lets each one through, so a test can tell how many requests a
//! command keeps in flight from the order of events alone. The times
//! requests start measure the runner's scheduling as much as the command.
//! It can stall the requests a test picks instead, for a command that must
//! finish without waiting for them.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::http::request::Parts;
use hyper::{HeaderMap, Request, Response, StatusCode, header};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::{mpsc, oneshot};

/// How long a step waits for what it needs. It only bounds a failure.
pub const WAIT_LIMIT: Duration = Duration::from_secs(60);

/// How long a test watches for a request that must not start while others
/// are held. One that starts later goes unseen here, so a slow runner can
/// only hide an extra request, never fail a command that keeps its limit.
pub const QUIET_PERIOD: Duration = Duration::from_millis(250);

/// How often a stalled response sends a byte, well inside lpm's own read
/// timeout, which each byte starts again.
const STALL_TRICKLE: Duration = Duration::from_secs(1);

/// What the gate does with a request: hold it, stall it, or, for `None`,
/// pass it straight through.
type Picks = dyn Fn(&Parts) -> Option<Picked> + Send + Sync;
type Body = BoxBody<Bytes, Infallible>;

/// What the gate does with a request its test picks.
#[derive(Clone, Copy)]
pub enum Picked {
    /// Hold it until the test lets it through.
    Hold,
    /// Answer it at once and never finish its body, a byte at a time so the
    /// command's read timeout never passes: the command finishes only if it
    /// stops waiting for it.
    Stall,
}

pub struct RequestGate {
    url: String,
    events: mpsc::UnboundedReceiver<Event>,
    counts: Arc<Counts>,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// What the gate tells the test, in the order it happens.
enum Event {
    Held(HeldRequest),
    /// The command closed a held request's connection before the test let
    /// it through.
    Abandoned(String),
}

#[derive(Default)]
struct Counts {
    /// Held requests whose response the command hasn't been handed yet.
    open: AtomicUsize,
    peak: AtomicUsize,
    held: AtomicUsize,
    abandoned: AtomicUsize,
    /// Set once the command abandons a held request after its own read
    /// timeout, and sends it again. The gate holds nothing more, so the
    /// command can finish and the test can say why it failed.
    stopped_holding: AtomicBool,
}

/// A request the gate holds. Dropping it without releasing it answers the
/// command with 503.
pub struct HeldRequest {
    target: String,
    release: oneshot::Sender<()>,
}

impl HeldRequest {
    /// The request's path and query.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Lets the request through to the mock server.
    pub fn release(self) {
        let _ = self.release.send(());
    }
}

struct Front {
    upstream: String,
    picks: Box<Picks>,
    events: mpsc::UnboundedSender<Event>,
    counts: Arc<Counts>,
    client: reqwest::Client,
}

/// Counts a held request as open until its response is handed back, or
/// until the command gives up on it and the connection closes, which hyper
/// shows by dropping the request.
struct OpenRequest<'a> {
    front: &'a Front,
    target: String,
    waiting: bool,
}

impl<'a> OpenRequest<'a> {
    fn begin(front: &'a Front, target: &str) -> Self {
        let counts = &front.counts;
        let open = counts.open.fetch_add(1, Ordering::SeqCst) + 1;
        counts.peak.fetch_max(open, Ordering::SeqCst);
        counts.held.fetch_add(1, Ordering::SeqCst);
        Self {
            front,
            target: target.to_owned(),
            waiting: true,
        }
    }

    /// The test let the request through or dropped it, so the command no
    /// longer waits on the gate.
    fn settle(&mut self) {
        self.waiting = false;
    }
}

impl Drop for OpenRequest<'_> {
    fn drop(&mut self) {
        let counts = &self.front.counts;
        counts.open.fetch_sub(1, Ordering::SeqCst);
        if self.waiting {
            counts.abandoned.fetch_add(1, Ordering::SeqCst);
            counts.stopped_holding.store(true, Ordering::SeqCst);
            let target = std::mem::take(&mut self.target);
            let _ = self.front.events.send(Event::Abandoned(target));
        }
    }
}

impl RequestGate {
    /// Starts a front for the mock server at `upstream` that holds every
    /// request `holds` picks and passes the others straight through.
    pub fn start(upstream: &str, holds: impl Fn(&Parts) -> bool + Send + Sync + 'static) -> Self {
        Self::choosing(upstream, move |request| {
            holds(request).then_some(Picked::Hold)
        })
    }

    /// Starts a front for the mock server at `upstream` that stalls every
    /// request `stalls` picks and passes the others straight through.
    pub fn stalling(
        upstream: &str,
        stalls: impl Fn(&Parts) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self::choosing(upstream, move |request| {
            stalls(request).then_some(Picked::Stall)
        })
    }

    /// Starts a front for the mock server at `upstream` that does with each
    /// request what `picks` chooses, and passes the others straight through.
    pub fn choosing(
        upstream: &str,
        picks: impl Fn(&Parts) -> Option<Picked> + Send + Sync + 'static,
    ) -> Self {
        let picks: Box<Picks> = Box::new(picks);
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind the request gate listener");
        listener
            .set_nonblocking(true)
            .expect("make the request gate listener non-blocking");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("request gate address")
        );
        let (events_sender, events) = mpsc::unbounded_channel();
        let counts = Arc::new(Counts::default());
        let front = Arc::new(Front {
            upstream: upstream.trim_end_matches('/').to_owned(),
            picks,
            events: events_sender,
            counts: Arc::clone(&counts),
            client: reqwest::Client::builder()
                .no_proxy()
                .no_gzip()
                .no_brotli()
                .no_zstd()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("build the request gate's client"),
        });
        let (shutdown, mut stopped) = oneshot::channel::<()>();
        // The test may block on the command it runs, so the gate serves from
        // a runtime of its own.
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("request gate runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .expect("register the request gate listener");
                loop {
                    let stream = tokio::select! {
                        accepted = listener.accept() => match accepted {
                            Ok((stream, _)) => stream,
                            Err(_) => {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                continue;
                            }
                        },
                        _ = &mut stopped => break,
                    };
                    let front = Arc::clone(&front);
                    tokio::spawn(async move {
                        let service = hyper::service::service_fn(move |request| {
                            let front = Arc::clone(&front);
                            async move { Ok::<_, Infallible>(front.serve(request).await) }
                        });
                        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
        });
        Self {
            url,
            events,
            counts,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>`, the URL a command uses in place of the
    /// mock server's.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// How many requests the gate has held or stalled.
    pub fn held(&self) -> usize {
        self.counts.held.load(Ordering::SeqCst)
    }

    /// The most held requests that were in flight at once.
    pub fn peak(&self) -> usize {
        self.counts.peak.load(Ordering::SeqCst)
    }

    /// Wait until the gate has held or stalled `count` requests, at most
    /// [`WAIT_LIMIT`].
    pub async fn wait_until_held(&self, count: usize) {
        let waited = tokio::time::timeout(WAIT_LIMIT, async {
            while self.held() < count {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "only {} of {count} requests were held or stalled within {WAIT_LIMIT:?}",
            self.held()
        );
    }

    /// The next request the gate holds, in the order they arrived.
    pub async fn next(&mut self) -> HeldRequest {
        let held = self.held();
        match tokio::time::timeout(WAIT_LIMIT, self.events.recv()).await {
            Ok(Some(Event::Held(request))) => request,
            Ok(Some(Event::Abandoned(target))) => panic!("{}", abandoned(&target, held)),
            Ok(None) => panic!("the request gate stopped"),
            Err(_) => {
                panic!("no further request was held within {WAIT_LIMIT:?}; {held} were before")
            }
        }
    }

    /// Fails the test, saying `claim`, if the gate holds another request
    /// within [`QUIET_PERIOD`].
    pub async fn assert_quiet(&mut self, claim: &str) {
        match tokio::time::timeout(QUIET_PERIOD, self.events.recv()).await {
            Ok(Some(Event::Held(extra))) => panic!("{claim}: {} started too", extra.target()),
            Ok(Some(Event::Abandoned(target))) => {
                panic!("{}", abandoned(&target, self.held()))
            }
            Ok(None) | Err(_) => {}
        }
    }

    /// Fails unless the command waited for every request the gate held, and
    /// the gate held `total`.
    pub fn assert_held(&self, total: usize) {
        let abandoned = self.counts.abandoned.load(Ordering::SeqCst);
        assert_eq!(
            abandoned, 0,
            "lpm gave up on {abandoned} requests the test held, after its own read timeout: {GAVE_UP}"
        );
        assert_eq!(self.held(), total, "how many requests the gate held");
    }

    /// Holds the first `limit` requests and checks that no other starts
    /// while they're held. Then, until `total` have started, it lets the
    /// oldest through, waits for another to start while the rest are still
    /// held, and checks again that no other starts; then it lets the rest
    /// through.
    ///
    /// A command that runs fewer than `limit` at once, or waits for a whole
    /// wave before it starts more, never sends a request this waits for,
    /// and one that runs more than `limit` at once sends one this sees.
    pub async fn hold_a_bounded_pool(&mut self, limit: usize, total: usize) {
        assert!(
            (1..=total).contains(&limit),
            "a pool of {limit} for {total} requests"
        );
        let over_the_limit = format!("more than {limit} requests were in flight");
        let mut held = VecDeque::with_capacity(limit);
        for _ in 0..limit {
            held.push_back(self.next().await);
        }
        self.assert_quiet(&over_the_limit).await;
        for _ in limit..total {
            held.pop_front().expect("a held request").release();
            held.push_back(self.next().await);
            self.assert_quiet(&over_the_limit).await;
        }
        held.into_iter().for_each(HeldRequest::release);
        assert_eq!(self.peak(), limit, "the most requests in flight at once");
    }
}

impl Drop for RequestGate {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What a held request lpm gave up on means.
const GAVE_UP: &str =
    "lpm runs fewer requests at once than the test waits for, or the runner stalled that long";

fn abandoned(target: &str, held: usize) -> String {
    format!(
        "lpm gave up on {target} after its own read timeout, with {held} requests held: {GAVE_UP}"
    )
}

impl Front {
    async fn serve(&self, request: Request<Incoming>) -> Response<Body> {
        let (parts, body) = request.into_parts();
        let Ok(body) = body.collect().await.map(|body| body.to_bytes()) else {
            return status_only(StatusCode::BAD_REQUEST);
        };
        let picked = (self.picks)(&parts);
        let Some(picked) = picked.filter(|_| !self.counts.stopped_holding.load(Ordering::SeqCst))
        else {
            return self.forward(&parts, body).await;
        };
        if let Picked::Stall = picked {
            self.counts.held.fetch_add(1, Ordering::SeqCst);
            return stalled();
        }
        let target = target(&parts);
        let mut open = OpenRequest::begin(self, target);
        let (release, released) = oneshot::channel();
        let held = HeldRequest {
            target: target.to_owned(),
            release,
        };
        let released = self.events.send(Event::Held(held)).is_ok() && released.await.is_ok();
        open.settle();
        if !released {
            return status_only(StatusCode::SERVICE_UNAVAILABLE);
        }
        self.forward(&parts, body).await
    }

    async fn forward(&self, parts: &Parts, body: Bytes) -> Response<Body> {
        let mut request = self
            .client
            .request(
                parts.method.clone(),
                format!("{}{}", self.upstream, target(parts)),
            )
            .headers(end_to_end(&parts.headers));
        if !body.is_empty() {
            request = request.body(body);
        }
        let Ok(mut upstream) = request.send().await else {
            return status_only(StatusCode::BAD_GATEWAY);
        };
        let status = upstream.status();
        let headers = end_to_end(&std::mem::take(upstream.headers_mut()));
        let Ok(body) = upstream.bytes().await else {
            return status_only(StatusCode::BAD_GATEWAY);
        };
        let mut response = Response::new(Full::new(body).boxed());
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        response
    }
}

fn target(parts: &Parts) -> &str {
    parts
        .uri
        .path_and_query()
        .map_or("/", |target| target.as_str())
}

/// `headers` without the ones that describe a single connection or message
/// framing, which each side of the gate sets for itself.
fn end_to_end(headers: &HeaderMap) -> HeaderMap {
    let mut kept = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let per_hop = name == header::CONNECTION
            || name == header::HOST
            || name == header::CONTENT_LENGTH
            || name == header::TRANSFER_ENCODING
            || name == header::TE
            || name == header::TRAILER
            || name == header::UPGRADE
            || name.as_str() == "keep-alive"
            || name.as_str() == "proxy-connection";
        if !per_hop {
            kept.append(name, value.clone());
        }
    }
    kept
}

/// A 200 JSON answer whose body never ends, a space at a time.
fn stalled() -> Response<Body> {
    let trickle = futures_util::stream::unfold((), |()| async {
        tokio::time::sleep(STALL_TRICKLE).await;
        Some((Ok(Frame::data(Bytes::from_static(b" "))), ()))
    });
    let mut response = Response::new(StreamBody::new(trickle).boxed());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response
}

fn status_only(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Full::default().boxed());
    *response.status_mut() = status;
    response
}

/// The decoded value of `key` in the request's query.
pub fn query_value(parts: &Parts, key: &str) -> Option<String> {
    let query = parts.uri.query()?;
    reqwest::Url::parse(&format!("http://gate/?{query}"))
        .ok()?
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

/// Runs `command` while `drive` lets the requests it holds through, and
/// returns the command's output once both are done. The test fails, showing
/// that output, if the command exits before `drive` is done, if `drive`
/// fails, or if the command doesn't finish after it.
pub async fn run_while(command: std::process::Command, drive: impl Future<Output = ()>) -> Output {
    use futures_util::FutureExt as _;
    let mut command = tokio::process::Command::from(command);
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // A group of its own, so stopping it stops what it started too, which
    // can hold its output open.
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn().expect("spawn lpm");
    let stdout = Captured::read(child.stdout.take().expect("piped stdout"));
    let stderr = Captured::read(child.stderr.take().expect("piped stderr"));
    let driven = std::panic::AssertUnwindSafe(drive).catch_unwind();
    tokio::pin!(driven);
    let early = tokio::select! {
        biased;
        driven = &mut driven => match driven {
            Ok(()) => None,
            Err(panic) => Some(format!("the test failed: {}", panic_message(&*panic))),
        },
        status = child.wait() => Some(format!(
            "lpm exited ({}) before the test let its requests through",
            status.expect("wait for lpm")
        )),
    };
    let status = match early {
        Some(reason) => Err(reason),
        None => tokio::time::timeout(WAIT_LIMIT, child.wait())
            .await
            .map_err(|_| format!("lpm didn't finish within {WAIT_LIMIT:?} of the test's last step"))
            .map(|status| status.expect("wait for lpm")),
    };
    if status.is_err() {
        stop(&mut child).await;
    }
    let (stdout, stderr) = (stdout.finish().await, stderr.finish().await);
    match status {
        Ok(status) => Output {
            status,
            stdout,
            stderr,
        },
        Err(reason) => panic!(
            "{reason}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
        ),
    }
}

/// Stop `child`, and on Unix everything in its group, then wait for it, at
/// most [`WAIT_LIMIT`].
async fn stop(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(group) = child.id().and_then(|id| libc::pid_t::try_from(id).ok()) {
        // SAFETY: killpg takes a process group ID and a signal, and touches
        // no memory of this process.
        unsafe {
            libc::killpg(group, libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
    let _ = tokio::time::timeout(WAIT_LIMIT, child.wait()).await;
}

/// What a command writes to a pipe, read alongside it.
struct Captured {
    bytes: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    reading: tokio::task::JoinHandle<()>,
}

impl Captured {
    fn read(mut pipe: impl tokio::io::AsyncRead + Unpin + Send + 'static) -> Self {
        let bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let read = std::sync::Arc::clone(&bytes);
        let reading = tokio::spawn(async move {
            use tokio::io::AsyncReadExt as _;
            let mut chunk = [0_u8; 8192];
            while let Ok(count @ 1..) = pipe.read(&mut chunk).await {
                read.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend_from_slice(&chunk[..count]);
            }
        });
        Self { bytes, reading }
    }

    /// Everything read once the pipe closes, or what was read by
    /// [`WAIT_LIMIT`], as a process the command started can hold it open.
    async fn finish(self) -> Vec<u8> {
        let _ = tokio::time::timeout(WAIT_LIMIT, self.reading).await;
        std::mem::take(
            &mut self
                .bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("a panic without a message")
}
