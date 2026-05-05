//! Local Verdaccio registry harness for real-registry workflow tests.
//!
//! This complements `MockRegistry` when a test needs a real npm-compatible
//! registry server: auth bootstrap, `npm publish`, and install through a
//! project `.npmrc`. The first phase-65.1 slice uses it for a smoke test
//! proving that `lpm install` records the actual mirror URL in `lpm.lock`.

use std::fs::File;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use tempfile::TempDir;

const VERDACCIO_VERSION: &str = "6.5.2";
const DEFAULT_USERNAME: &str = "lpm-workflows";
const DEFAULT_PASSWORD: &str = "lpm-workflows-password";
const DEFAULT_EMAIL: &str = "lpm-workflows@example.test";

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_child_tree(child: &mut Child) {
    let pgid = child.id() as i32;
    if pgid > 0 {
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn terminate_child_tree(child: &mut Child) {
    let _ = child.kill();
}

pub struct VerdaccioRegistry {
    child: Child,
    config_dir: TempDir,
    base_url: String,
    token: String,
}

impl VerdaccioRegistry {
    pub async fn start() -> Self {
        let config_dir = TempDir::new().expect("failed to create verdaccio temp dir");
        let port = reserve_port();
        let base_url = format!("http://127.0.0.1:{port}");
        let config_path = config_dir.path().join("config.yaml");

        write_config(config_dir.path());

        let stdout = File::create(config_dir.path().join("verdaccio.stdout.log"))
            .expect("failed to create verdaccio stdout log");
        let stderr = File::create(config_dir.path().join("verdaccio.stderr.log"))
            .expect("failed to create verdaccio stderr log");

        let mut command = Command::new("npx");
        command
            .arg("--yes")
            .arg(format!("verdaccio@{VERDACCIO_VERSION}"))
            .arg("--config")
            .arg(&config_path)
            .arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .current_dir(config_dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // `npx verdaccio` may outlive the front launcher process; put the
        // whole launcher tree in its own Unix process group so drop cleanup
        // can kill every descendant, not just the tracked front PID.
        configure_process_group(&mut command);
        let child = command
            .spawn()
            .expect("failed to spawn verdaccio via npx");

        let mut registry = VerdaccioRegistry {
            child,
            config_dir,
            base_url,
            token: String::new(),
        };

        registry.wait_until_ready().await;
        registry.token = registry
            .bootstrap_user(DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_EMAIL)
            .await;
        registry
    }

    pub fn url(&self) -> &str {
        &self.base_url
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn host_port(&self) -> &str {
        self.base_url
            .strip_prefix("http://")
            .expect("verdaccio base url must be http://host:port")
    }

    pub fn write_project_npmrc(&self, project_dir: &Path) {
        self.write_project_npmrc_with_token(project_dir, self.token());
    }

    pub fn write_project_npmrc_with_token(&self, project_dir: &Path, token: &str) {
        std::fs::write(
            project_dir.join(".npmrc"),
            format!(
                "registry={}/\n//{}/:_authToken={}\nalways-auth=true\n",
                self.url(),
                self.host_port(),
                token
            ),
        )
        .expect("failed to write project .npmrc for verdaccio");
    }

    pub fn publish_package(&self, name: &str, version: &str) {
        self.publish_package_with_files(name, version, &[("index.js", "module.exports = 42\n")]);
    }

    pub fn read_tarball_bytes(&self, name: &str, version: &str) -> Vec<u8> {
        std::fs::read(self.tarball_path(name, version)).unwrap_or_else(|err| {
            panic!(
                "failed to read verdaccio tarball bytes for {name}@{version}: {err}"
            )
        })
    }

    pub fn read_package_metadata(&self, name: &str) -> serde_json::Value {
        let metadata_path = self.package_storage_dir(name).join("package.json");
        let raw = std::fs::read_to_string(&metadata_path).unwrap_or_else(|err| {
            panic!(
                "failed to read verdaccio metadata for {name} at {}: {err}",
                metadata_path.display()
            )
        });

        serde_json::from_str(&raw).unwrap_or_else(|err| {
            panic!(
                "failed to parse verdaccio metadata for {name} at {}: {err}",
                metadata_path.display()
            )
        })
    }

    pub fn overwrite_tarball_bytes(&self, name: &str, version: &str, bytes: &[u8]) {
        let tarball_path = self.tarball_path(name, version);
        std::fs::write(&tarball_path, bytes).unwrap_or_else(|err| {
            panic!(
                "failed to overwrite verdaccio tarball for {name}@{version} at {}: {err}",
                tarball_path.display()
            )
        });
    }

    pub fn delete_tarball(&self, name: &str, version: &str) {
        let tarball_path = self.tarball_path(name, version);
        std::fs::remove_file(&tarball_path).unwrap_or_else(|err| {
            panic!(
                "failed to delete verdaccio tarball for {name}@{version} at {}: {err}",
                tarball_path.display()
            )
        });
    }

    pub fn rewrite_dist(
        &self,
        name: &str,
        version: &str,
        tarball_url: Option<&str>,
        integrity: Option<&str>,
    ) {
        let metadata_path = self.package_storage_dir(name).join("package.json");
        let mut value = self.read_package_metadata(name);
        let dist = value
            .get_mut("versions")
            .and_then(|versions| versions.get_mut(version))
            .and_then(|version_obj| version_obj.get_mut("dist"))
            .and_then(serde_json::Value::as_object_mut)
            .unwrap_or_else(|| {
                panic!(
                    "verdaccio metadata missing versions[{version}].dist for {name} at {}",
                    metadata_path.display()
                )
            });

        if let Some(tarball_url) = tarball_url {
            dist.insert(
                "tarball".to_string(),
                serde_json::Value::String(tarball_url.to_string()),
            );
        }
        if let Some(integrity) = integrity {
            dist.insert(
                "integrity".to_string(),
                serde_json::Value::String(integrity.to_string()),
            );
        }

        std::fs::write(
            &metadata_path,
            serde_json::to_vec_pretty(&value)
                .expect("verdaccio metadata rewrite should serialize"),
        )
        .unwrap_or_else(|err| {
            panic!(
                "failed to write verdaccio metadata for {name}@{version} at {}: {err}",
                metadata_path.display()
            )
        });
    }

    pub fn publish_package_with_files(&self, name: &str, version: &str, files: &[(&str, &str)]) {
        let pkg_dir = TempDir::new().expect("failed to create verdaccio package temp dir");
        let pkg_json = serde_json::json!({
            "name": name,
            "version": version,
            "main": "index.js",
        });

        std::fs::write(
            pkg_dir.path().join("package.json"),
            serde_json::to_string_pretty(&pkg_json).unwrap() + "\n",
        )
        .expect("failed to write verdaccio fixture package.json");

        for (rel_path, contents) in files {
            let dest = pkg_dir.path().join(rel_path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .expect("failed to create verdaccio fixture package parent");
            }
            std::fs::write(&dest, contents).expect("failed to write verdaccio fixture file");
        }

        std::fs::write(
            pkg_dir.path().join(".npmrc"),
            format!(
                "registry={}/\n//{}/:_authToken={}\nalways-auth=true\n",
                self.url(),
                self.host_port(),
                self.token()
            ),
        )
        .expect("failed to write verdaccio publish .npmrc");

        let npm_home = TempDir::new().expect("failed to create verdaccio npm home");
        let mut command = Command::new("npm");
        command.arg("publish").arg("--registry").arg(self.url());
        if name.starts_with('@') {
            command.args(["--access", "public"]);
        }
        let output = command
            .current_dir(pkg_dir.path())
            .env("HOME", npm_home.path())
            .env("NPM_CONFIG_USERCONFIG", pkg_dir.path().join(".npmrc"))
            .env("NO_COLOR", "1")
            .output()
            .expect("failed to run npm publish against verdaccio");

        assert!(
            output.status.success(),
            "npm publish to verdaccio failed:\nstdout:\n{}\nstderr:\n{}\nverdaccio logs:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            self.logs(),
        );
    }

    async fn wait_until_ready(&mut self) {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("failed to build reqwest client for verdaccio readiness");
        let deadline = Instant::now() + Duration::from_secs(20);

        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("failed to poll verdaccio child process")
            {
                panic!(
                    "verdaccio exited before readiness probe succeeded (status: {status})\n{}",
                    self.logs()
                );
            }

            match http.get(format!("{}/-/ping", self.url())).send().await {
                Ok(resp) if resp.status() == StatusCode::OK => return,
                _ if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                Ok(resp) => {
                    panic!(
                        "verdaccio readiness probe timed out with status {}\n{}",
                        resp.status(),
                        self.logs()
                    )
                }
                Err(err) => {
                    panic!(
                        "verdaccio readiness probe failed after timeout: {err}\n{}",
                        self.logs()
                    )
                }
            }
        }
    }

    async fn bootstrap_user(&self, username: &str, password: &str, email: &str) -> String {
        let http = reqwest::Client::new();
        let response = http
            .put(format!("{}/-/user/org.couchdb.user:{username}", self.url()))
            .json(&serde_json::json!({
                "name": username,
                "password": password,
                "email": email,
            }))
            .send()
            .await
            .expect("failed to create verdaccio bootstrap user");

        assert!(
            response.status().is_success(),
            "verdaccio user bootstrap failed with status {}\n{}",
            response.status(),
            self.logs(),
        );

        let value: serde_json::Value = response
            .json()
            .await
            .expect("verdaccio bootstrap user response must be JSON");
        value
            .get("token")
            .and_then(|token| token.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                panic!(
                    "verdaccio bootstrap user response missing token: {}",
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
                )
            })
    }

    fn logs(&self) -> String {
        let stdout = read_optional_file(self.config_dir.path().join("verdaccio.stdout.log"));
        let stderr = read_optional_file(self.config_dir.path().join("verdaccio.stderr.log"));
        format!("--- verdaccio stdout ---\n{stdout}\n--- verdaccio stderr ---\n{stderr}")
    }

    fn package_storage_dir(&self, name: &str) -> PathBuf {
        let storage_root = self.config_dir.path().join("storage");
        if let Some((scope, package)) = name.split_once('/') {
            storage_root.join(scope).join(package)
        } else {
            storage_root.join(name)
        }
    }

    fn tarball_path(&self, name: &str, version: &str) -> PathBuf {
        self.package_storage_dir(name)
            .join(format!("{}-{version}.tgz", package_leaf_name(name)))
    }
}

impl Drop for VerdaccioRegistry {
    fn drop(&mut self) {
        terminate_child_tree(&mut self.child);
        let _ = self.child.wait();
    }
}

fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind an ephemeral tcp port");
    let port = listener
        .local_addr()
        .expect("failed to read bound local addr")
        .port();
    drop(listener);
    port
}

fn write_config(dir: &Path) {
    let storage_dir = dir.join("storage");
    let htpasswd = dir.join("htpasswd");
    std::fs::create_dir_all(&storage_dir).expect("failed to create verdaccio storage dir");

    let config = format!(
        concat!(
            "storage: {}\n",
            "auth:\n",
            "  htpasswd:\n",
            "    file: {}\n",
            "uplinks:\n",
            "  npmjs:\n",
            "    url: https://registry.npmjs.org/\n",
            "packages:\n",
            "  '@*/*':\n",
            "    access: $authenticated\n",
            "    publish: $authenticated\n",
            "    unpublish: $authenticated\n",
            "    proxy: npmjs\n",
            "  '**':\n",
            "    access: $authenticated\n",
            "    publish: $authenticated\n",
            "    unpublish: $authenticated\n",
            "    proxy: npmjs\n",
            "server:\n",
            "  keepAliveTimeout: 60\n",
            "log:\n",
            "  type: stdout\n",
            "  format: pretty\n",
            "  level: http\n"
        ),
        yaml_path(&storage_dir),
        yaml_path(&htpasswd),
    );

    std::fs::write(dir.join("config.yaml"), config).expect("failed to write verdaccio config");
}

fn yaml_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn package_leaf_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

fn read_optional_file(path: PathBuf) -> String {
    let mut buf = String::new();
    if let Ok(mut file) = File::open(path) {
        let _ = file.read_to_string(&mut buf);
    }
    buf
}
