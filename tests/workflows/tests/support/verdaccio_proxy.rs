//! Same-origin proxy harness in front of Verdaccio for transport-layer tests.

use std::io::Write;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use flate2::{Compression, write::GzEncoder};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::verdaccio::VerdaccioRegistry;

const DEFAULT_PROXY_TOKEN: &str = "PHASE65-PROXY-TOKEN";

pub enum MetadataBehavior {
    VerdaccioMirror,
    MissingTarballField,
    ExtraFields,
    NpmInstallV1Abbreviated,
}

pub enum TarballBehavior {
    Direct,
    Redirect,
    HttpGzip,
    Retry429ThenSuccess,
    Unauthorized,
}

pub struct VerdaccioProxyRegistry {
    server: MockServer,
    base_url: String,
    token: String,
    metadata_path: String,
    tarball_path: String,
    redirect_target_path: Option<String>,
}

impl VerdaccioProxyRegistry {
    pub async fn start(
        registry: &VerdaccioRegistry,
        package_name: &str,
        version: &str,
        behavior: TarballBehavior,
    ) -> Self {
        Self::start_with_metadata_behavior(
            registry,
            package_name,
            version,
            MetadataBehavior::VerdaccioMirror,
            behavior,
        )
        .await
    }

    pub async fn start_with_metadata_behavior(
        registry: &VerdaccioRegistry,
        package_name: &str,
        version: &str,
        metadata_behavior: MetadataBehavior,
        tarball_behavior: TarballBehavior,
    ) -> Self {
        let server = MockServer::start().await;
        let base_url = server.uri();
        let token = DEFAULT_PROXY_TOKEN.to_string();
        let metadata_path = metadata_path(package_name);
        let tarball_path = tarball_path(package_name, version);
        let redirect_target_path = match tarball_behavior {
            TarballBehavior::Direct => None,
            TarballBehavior::Redirect => Some(format!(
                "/__verdaccio_proxy__/redirect-target/{}-{}.tgz",
                package_leaf_name(package_name),
                version,
            )),
            TarballBehavior::HttpGzip
            | TarballBehavior::Retry429ThenSuccess
            | TarballBehavior::Unauthorized => None,
        };

        let metadata = build_metadata(
            registry,
            package_name,
            version,
            metadata_behavior,
            &base_url,
            &tarball_path,
        );

        let tarball_bytes = registry.read_tarball_bytes(package_name, version);
        let auth_header = format!("Bearer {token}");

        Mock::given(method("GET"))
            .and(path(metadata_path.clone()))
            .and(header("authorization", auth_header.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(&server)
            .await;

        match tarball_behavior {
            TarballBehavior::Direct => {
                Mock::given(method("GET"))
                    .and(path(tarball_path.clone()))
                    .and(header("authorization", auth_header.as_str()))
                    .respond_with(tarball_response(&tarball_bytes, false))
                    .mount(&server)
                    .await;
            }
            TarballBehavior::Redirect => {
                let redirect_target_path = redirect_target_path
                    .as_ref()
                    .expect("redirect target path must exist for redirect behavior")
                    .clone();
                Mock::given(method("GET"))
                    .and(path(tarball_path.clone()))
                    .and(header("authorization", auth_header.as_str()))
                    .respond_with(
                        ResponseTemplate::new(302)
                            .append_header("location", format!("{base_url}{redirect_target_path}")),
                    )
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path(redirect_target_path.clone()))
                    .and(header("authorization", auth_header.as_str()))
                    .respond_with(tarball_response(&tarball_bytes, false))
                    .mount(&server)
                    .await;
            }
            TarballBehavior::HttpGzip => {
                Mock::given(method("GET"))
                    .and(path(tarball_path.clone()))
                    .and(header("authorization", auth_header.as_str()))
                    .respond_with(tarball_response(&tarball_bytes, true))
                    .mount(&server)
                    .await;
            }
            TarballBehavior::Retry429ThenSuccess => {
                let request_count = Arc::new(AtomicUsize::new(0));
                let request_count_for_responder = Arc::clone(&request_count);
                let tarball_bytes = tarball_bytes.clone();

                Mock::given(method("GET"))
                    .and(path(tarball_path.clone()))
                    .and(header("authorization", auth_header.as_str()))
                    .respond_with(move |_request: &wiremock::Request| {
                        let attempt = request_count_for_responder.fetch_add(1, Ordering::SeqCst);
                        if attempt == 0 {
                            ResponseTemplate::new(429).append_header("retry-after", "0")
                        } else {
                            tarball_response(&tarball_bytes, false)
                        }
                    })
                    .expect(2)
                    .mount(&server)
                    .await;
            }
            TarballBehavior::Unauthorized => {
                Mock::given(method("GET"))
                    .and(path(tarball_path.clone()))
                    .and(header("authorization", auth_header.as_str()))
                    .respond_with(
                        ResponseTemplate::new(401).set_body_string("proxy tarball auth failed"),
                    )
                    .mount(&server)
                    .await;
            }
        }

        VerdaccioProxyRegistry {
            server,
            base_url,
            token,
            metadata_path,
            tarball_path,
            redirect_target_path,
        }
    }

    pub fn url(&self) -> &str {
        &self.base_url
    }

    pub fn metadata_path(&self) -> &str {
        &self.metadata_path
    }

    pub fn tarball_path(&self) -> &str {
        &self.tarball_path
    }

    pub fn redirect_target_path(&self) -> Option<&str> {
        self.redirect_target_path.as_deref()
    }

    pub async fn received_paths(&self) -> Vec<String> {
        self.server
            .received_requests()
            .await
            .expect("wiremock must expose received requests")
            .into_iter()
            .map(|request| request.url.path().to_string())
            .collect()
    }

    pub async fn received_request_summaries(&self) -> Vec<(String, String, Option<String>)> {
        self.server
            .received_requests()
            .await
            .expect("wiremock must expose received requests")
            .into_iter()
            .map(|request| {
                (
                    request.method.as_str().to_string(),
                    request.url.path().to_string(),
                    request
                        .headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned),
                )
            })
            .collect()
    }

    pub fn write_project_npmrc(&self, project_dir: &Path) {
        super::write_private_file(
            &project_dir.join(".npmrc"),
            format!(
                "registry={}/\n//{}/:_authToken={}\nalways-auth=true\n",
                self.url(),
                host_port(self.url()),
                self.token,
            ),
        );
    }
}

fn tarball_response(bytes: &[u8], http_gzip: bool) -> ResponseTemplate {
    if http_gzip {
        ResponseTemplate::new(200)
            .append_header("content-encoding", "gzip")
            .set_body_bytes(gzip_bytes(bytes))
    } else {
        ResponseTemplate::new(200).set_body_bytes(bytes.to_vec())
    }
}

fn gzip_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .expect("failed to gzip verdaccio proxy body");
    encoder
        .finish()
        .expect("failed to finish verdaccio proxy gzip body")
}

fn build_metadata(
    registry: &VerdaccioRegistry,
    package_name: &str,
    version: &str,
    behavior: MetadataBehavior,
    base_url: &str,
    tarball_path: &str,
) -> serde_json::Value {
    let mut metadata = registry.read_package_metadata(package_name);
    metadata["versions"][version]["dist"]["tarball"] =
        serde_json::Value::String(format!("{base_url}{tarball_path}"));

    match behavior {
        MetadataBehavior::VerdaccioMirror => metadata,
        MetadataBehavior::MissingTarballField => {
            metadata["versions"][version]["dist"]
                .as_object_mut()
                .expect("verdaccio metadata dist must be an object")
                .remove("tarball");
            metadata
        }
        MetadataBehavior::ExtraFields => {
            metadata["_rev"] = serde_json::Value::String("step7-extra-fields".to_string());
            metadata["users"] = serde_json::json!({
                "someone@example.test": true,
            });
            metadata["versions"][version]["_npmUser"] = serde_json::json!({
                "name": "step7-publisher",
                "email": "publisher@example.test",
            });
            metadata["versions"][version]["dist"]["fileCount"] = serde_json::json!(3);
            metadata["versions"][version]["dist"]["unpackedSize"] = serde_json::json!(4096);
            metadata
        }
        MetadataBehavior::NpmInstallV1Abbreviated => {
            let integrity = metadata["versions"][version]["dist"]["integrity"].clone();
            serde_json::json!({
                "name": package_name,
                "dist-tags": {
                    "latest": version,
                },
                "versions": {
                    version: {
                        "name": package_name,
                        "version": version,
                        "dependencies": {},
                        "dist": {
                            "tarball": format!("{base_url}{tarball_path}"),
                            "integrity": integrity,
                        },
                    }
                }
            })
        }
    }
}

fn metadata_path(package_name: &str) -> String {
    format!("/{}", encode_package_name(package_name))
}

fn tarball_path(package_name: &str, version: &str) -> String {
    format!(
        "/{}/-/{}-{}.tgz",
        package_name,
        package_leaf_name(package_name),
        version,
    )
}

fn encode_package_name(package_name: &str) -> String {
    package_name.replace('/', "%2F")
}

fn host_port(url: &str) -> &str {
    url.strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .expect("proxy url must include a scheme")
}

fn package_leaf_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}
