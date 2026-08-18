use super::*;

struct ScopedAuthEnv {
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl ScopedAuthEnv {
    fn file_backed(home: &std::path::Path) -> Self {
        let values = [
            ("HOME", Some(home.as_os_str().to_owned())),
            ("LPM_HOME", Some(home.join(".lpm").into_os_string())),
            ("LPM_FORCE_FILE_AUTH", Some(std::ffi::OsString::from("1"))),
            ("LPM_TEST_FAST_SCRYPT", Some(std::ffi::OsString::from("1"))),
            ("LPM_TOKEN", None),
        ];
        let previous = values
            .iter()
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect();
        for (key, value) in values {
            // SAFETY: tests changing auth environment variables hold `auth_env_lock`.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
        Self { previous }
    }
}

impl Drop for ScopedAuthEnv {
    fn drop(&mut self) {
        for (key, value) in self.previous.iter().rev() {
            // SAFETY: tests changing auth environment variables hold `auth_env_lock`.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

async fn auth_env_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

mod api;
mod body;
mod cache;
mod firewall;
mod http_tls;
mod install_accounting;
mod metadata;
mod tarball;
mod transport;
mod url_gate;

#[derive(Clone)]
struct AuthorizationRecorder {
    saw_authorization: std::sync::Arc<std::sync::atomic::AtomicBool>,
    body: Vec<u8>,
}

impl wiremock::Respond for AuthorizationRecorder {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        if request.headers.get("authorization").is_some() {
            self.saw_authorization
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        wiremock::ResponseTemplate::new(200).set_body_bytes(self.body.clone())
    }
}

/// Helper: create a RegistryClient with a temporary cache directory.
fn client_with_temp_cache() -> (RegistryClient, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let mut client = RegistryClient::new();
    client.cache_dir = Some(tmp.path().to_path_buf());
    (client, tmp)
}

/// Helper: build a minimal PackageMetadata for testing.
fn test_metadata(name: &str) -> PackageMetadata {
    PackageMetadata {
        name: name.to_string(),
        description: Some("test package".to_string()),
        dist_tags: {
            let mut m = std::collections::HashMap::new();
            m.insert("latest".to_string(), "1.0.0".to_string());
            m
        },
        versions: std::collections::HashMap::new(),
        time: std::collections::HashMap::new(),
        modified: None,
        downloads: Some(42),
        distribution_mode: None,
        package_type: None,
        latest_version: Some("1.0.0".to_string()),
        ecosystem: None,
    }
}

/// Helper: create a RegistryClient pointed at a mock server with temp cache.
///
/// These mock-server tests verify "first fetch caches; second fetch is a
/// hit" round-trips, which depend on the cache write landing before the
/// next read. We flip `synchronous_cache_writes` so the test doesn't race
/// the spawn_blocking write against its own next request. Production-shape
/// behavior (spawn_blocking, fire-and-forget) is exercised by the
/// integration suite.
fn client_with_mock_server(server_uri: &str) -> (RegistryClient, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let mut client = RegistryClient::new()
        .with_base_url(server_uri)
        .with_synchronous_cache_writes(true);
    client.cache_dir = Some(tmp.path().to_path_buf());
    (client, tmp)
}

/// Helper: build a JSON response body for PackageMetadata.
fn test_metadata_json(name: &str) -> String {
    serde_json::json!({
        "name": name,
        "description": "test package",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": name,
                "version": "1.0.0",
                "dist": {
                    "tarball": "https://example.com/pkg-1.0.0.tgz",
                    "integrity": "sha512-test"
                },
                "dependencies": {}
            }
        }
    })
    .to_string()
}

/// Bind a localhost TCP listener, return `(url, join_handle)`. The
/// spawned task accepts ONE connection, reads until end-of-headers,
/// and writes a chunked-encoded NDJSON response. Lines are emitted
/// every `chunk_interval`; total stream time is
/// `chunk_interval * line_count`.
async fn slow_streaming_ndjson_server(
    packages: Vec<String>,
    chunk_interval: std::time::Duration,
) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("addr");
    let base_url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let (read_half, mut write_half) = stream.into_split();

        // Skim the request line + headers until the blank line. We
        // don't validate — just need to clear the buffer so the
        // server appears HTTP-compliant.
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        while reader
            .read_line(&mut line)
            .await
            .expect("read request line")
            > 0
        {
            let is_blank = line == "\r\n" || line == "\n";
            line.clear();
            if is_blank {
                break;
            }
        }

        // Status + headers.
        write_half
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/x-ndjson\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .expect("write status+headers");
        write_half.flush().await.expect("flush headers");

        // Stream one NDJSON line per chunk, sleeping between.
        for name in packages {
            let body = serde_json::json!({
                "name": &name,
                "metadata": {
                    "name": &name,
                    "description": "test package",
                    "dist-tags": { "latest": "1.0.0" },
                    "versions": {
                        "1.0.0": {
                            "name": &name,
                            "version": "1.0.0",
                            "dist": {
                                "tarball": "https://example.com/pkg-1.0.0.tgz",
                                "integrity": "sha512-test"
                            },
                            "dependencies": {}
                        }
                    }
                }
            })
            .to_string();
            let line = format!("{body}\n");
            let chunk = format!("{:x}\r\n{}\r\n", line.len(), line);
            write_half
                .write_all(chunk.as_bytes())
                .await
                .expect("write chunk");
            write_half.flush().await.expect("flush chunk");
            tokio::time::sleep(chunk_interval).await;
        }

        // Terminating zero-length chunk + trailing CRLF.
        write_half
            .write_all(b"0\r\n\r\n")
            .await
            .expect("write terminator");
        write_half.flush().await.expect("flush terminator");
    });

    (base_url, handle)
}

/// Helper: build a RegistryAuth::Bearer scoped to the wiremock
/// server's origin. Encapsulates the URL parsing test code does
/// over and over.
fn bearer_for(server_uri: &str, token: &str) -> crate::npmrc::RegistryAuth {
    let origin = crate::npmrc::OriginKey::from_request_url(&format!("{server_uri}/_"))
        .expect("mock server URI must parse");
    crate::npmrc::RegistryAuth::Bearer {
        origin,
        token: SecretString::from(token.to_string()),
    }
}

fn basic_for(server_uri: &str, b64: &str) -> crate::npmrc::RegistryAuth {
    let origin = crate::npmrc::OriginKey::from_request_url(&format!("{server_uri}/_"))
        .expect("mock server URI must parse");
    crate::npmrc::RegistryAuth::Basic {
        origin,
        credential: SecretString::from(b64.to_string()),
    }
}

/// Helper for the host-keyed cache test — needs a `latestVersion`
/// field for round-trip comparison (the default `test_metadata_json`
/// builder is light; this one parameterizes the version).
fn test_metadata_json_with_version(name: &str, version: &str) -> String {
    serde_json::json!({
        "name": name,
        "description": "test",
        "latestVersion": version,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": name,
                "version": version,
                "dist": {
                    "tarball": format!("https://example.com/{name}-{version}.tgz"),
                    "integrity": "sha512-test"
                },
                "dependencies": {}
            }
        }
    })
    .to_string()
}

use crate::npmrc::{TaggedBool, TaggedRoot};

fn rcgen_pem() -> Vec<u8> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("rcgen self-signed cert");
    cert.cert.pem().into_bytes()
}

/// Test helper: wrap a `reqwest::Client` in a `CachedClient` with
/// no identity fingerprint. The dispatch tests don't exercise
/// principal_fingerprint (that's its own test), so identity_fp
/// stays None.
fn cached(client: reqwest::Client) -> CachedClient {
    CachedClient {
        policy_metadata_client: client.clone(),
        client,
        identity_fp: None,
    }
}
