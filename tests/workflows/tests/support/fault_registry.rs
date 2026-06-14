use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::mock_registry::{MockRegistry, compute_integrity};

#[derive(Clone)]
pub enum MetadataReply {
    Ok(serde_json::Value),
    NotFound(String),
}

#[derive(Clone)]
pub enum TarballReply {
    Bytes(Vec<u8>),
    Status { code: u16, body: String },
}

#[derive(Clone)]
pub struct FaultCounter {
    count: Arc<AtomicUsize>,
}

impl FaultCounter {
    fn new() -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn get(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

pub struct FaultRegistry {
    mock: MockRegistry,
}

impl FaultRegistry {
    pub async fn start() -> Self {
        Self {
            mock: MockRegistry::start().await,
        }
    }

    pub fn url(&self) -> String {
        self.mock.url()
    }

    pub fn server(&self) -> &MockServer {
        self.mock.server()
    }

    pub fn tarball_url(&self, name: &str, version: &str) -> String {
        self.mock.tarball_url(name, version)
    }

    pub fn tarball_path(name: &str, version: &str) -> String {
        MockRegistry::tarball_path(name, version)
    }

    pub fn package_metadata(
        &self,
        name: &str,
        version: &str,
        tarball_bytes: &[u8],
    ) -> serde_json::Value {
        self.mock.package_metadata(name, version, tarball_bytes)
    }

    pub fn package_metadata_with_tarball_url(
        &self,
        name: &str,
        version: &str,
        tarball_url: &str,
        integrity: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "dist-tags": { "latest": version },
            "versions": {
                version: {
                    "name": name,
                    "version": version,
                    "dist": {
                        "tarball": tarball_url,
                        "integrity": integrity,
                    },
                    "dependencies": {}
                }
            },
            "time": { version: "2025-01-01T00:00:00.000Z" }
        })
    }

    pub async fn with_batch_metadata(&self, packages: Vec<serde_json::Value>) -> &Self {
        self.mock.with_batch_metadata(packages).await;
        self
    }

    pub async fn with_package_metadata_reply(&self, name: &str, reply: MetadataReply) -> &Self {
        self.with_package_metadata_sequence(name, vec![reply]).await
    }

    pub async fn with_package_metadata_sequence(
        &self,
        name: &str,
        replies: Vec<MetadataReply>,
    ) -> &Self {
        let state = SequenceState::new(replies);
        for metadata_path in [format!("/api/registry/{name}"), format!("/{name}")] {
            Mock::given(method("GET"))
                .and(path(metadata_path.as_str()))
                .respond_with(MetadataSequenceResponder {
                    state: state.clone(),
                })
                .mount(self.mock.server())
                .await;
        }
        self
    }

    pub async fn with_tarball_reply(
        &self,
        tarball_path: &str,
        reply: TarballReply,
    ) -> FaultCounter {
        self.with_tarball_sequence(tarball_path, vec![reply]).await
    }

    pub async fn with_tarball_sequence(
        &self,
        tarball_path: &str,
        replies: Vec<TarballReply>,
    ) -> FaultCounter {
        let counter = FaultCounter::new();
        Mock::given(method("GET"))
            .and(path(tarball_path))
            .respond_with(TarballSequenceResponder {
                state: SequenceState::new(replies),
                counter: counter.clone(),
            })
            .mount(self.mock.server())
            .await;
        counter
    }

    pub async fn with_single_winner_publish(&self) -> PublishCounter {
        let counter = PublishCounter::new();
        Mock::given(method("PUT"))
            .and(path_regex("/api/registry/.*"))
            .respond_with(SingleWinnerPublishResponder {
                counter: counter.clone(),
            })
            .mount(self.mock.server())
            .await;
        counter
    }

    pub async fn with_whoami(&self, username: &str, email: &str) -> &Self {
        self.mock.with_whoami(username, email).await;
        self
    }
}

pub fn missing_tarball_reply() -> TarballReply {
    TarballReply::Status {
        code: 404,
        body: "missing tarball".to_string(),
    }
}

pub fn integrity_for(bytes: &[u8]) -> String {
    compute_integrity(bytes)
}

#[derive(Clone)]
struct SequenceState<T> {
    replies: Arc<Mutex<VecDeque<T>>>,
    last: T,
}

impl<T: Clone> SequenceState<T> {
    fn new(replies: Vec<T>) -> Self {
        assert!(
            !replies.is_empty(),
            "fault-registry sequence must contain at least one reply"
        );
        let last = replies.last().expect("checked non-empty").clone();
        Self {
            replies: Arc::new(Mutex::new(VecDeque::from(replies))),
            last,
        }
    }

    fn next(&self) -> T {
        let mut replies = self
            .replies
            .lock()
            .expect("fault-registry sequence mutex poisoned");
        replies.pop_front().unwrap_or_else(|| self.last.clone())
    }
}

struct MetadataSequenceResponder {
    state: SequenceState<MetadataReply>,
}

impl Respond for MetadataSequenceResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        match self.state.next() {
            MetadataReply::Ok(metadata) => ResponseTemplate::new(200).set_body_json(metadata),
            MetadataReply::NotFound(body) => ResponseTemplate::new(404)
                .insert_header("content-type", "application/json")
                .set_body_string(body),
        }
    }
}

struct TarballSequenceResponder {
    state: SequenceState<TarballReply>,
    counter: FaultCounter,
}

impl Respond for TarballSequenceResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.counter.count.fetch_add(1, Ordering::SeqCst);
        match self.state.next() {
            TarballReply::Bytes(bytes) => ResponseTemplate::new(200)
                .insert_header("content-type", "application/octet-stream")
                .set_body_bytes(bytes),
            TarballReply::Status { code, body } => {
                ResponseTemplate::new(code).set_body_string(body)
            }
        }
    }
}

#[derive(Clone)]
pub struct PublishCounter {
    count: Arc<AtomicUsize>,
}

impl PublishCounter {
    fn new() -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn get(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

struct SingleWinnerPublishResponder {
    counter: PublishCounter,
}

impl Respond for SingleWinnerPublishResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        match self.counter.count.fetch_add(1, Ordering::SeqCst) {
            0 => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "message": "Package published",
            })),
            _ => ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "error": "Conflict",
                "message": "package version already exists",
            })),
        }
    }
}
