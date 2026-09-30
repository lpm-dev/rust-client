//! When package downloads start relative to the firewall verdict.
//!
//! Monitor mode can't stop an install, so its downloads don't wait for the
//! verdict; the verdict is still reported when the command finishes. Enforce
//! mode must hold every download until the verdict allows it.

mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use support::mock_registry::{MockRegistry, make_tarball};
use support::{
    TempProject, lpm_with_registry, write_lpm_proxy_npmrc, write_npm_firewall_global_config,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

const PACKAGE: &str = "firewall-timing";
const VERSION: &str = "1.0.0";
const VERDICT_DELAY: Duration = Duration::from_secs(3);

type Arrivals = Arc<Mutex<Vec<Instant>>>;

#[derive(Clone)]
struct RecordArrival {
    arrivals: Arrivals,
    response: ResponseTemplate,
}

impl Respond for RecordArrival {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.arrivals
            .lock()
            .expect("record request arrival")
            .push(Instant::now());
        self.response.clone()
    }
}

fn warn_verdict(mode: &str) -> serde_json::Value {
    serde_json::json!({
        "requestId": "firewall-timing",
        "policyMode": mode,
        "summary": { "total": 1, "allow": 0, "warn": 1, "block": 0, "unknown": 0, "matched": 1 },
        "decisions": [{
            "decisionId": "firewall-timing",
            "name": PACKAGE,
            "version": VERSION,
            "action": "warn",
            "verdict": "suspicious",
            "reason": "Local policy reason",
            "matchSource": "package",
            "policyMode": mode,
            "enqueueScan": false
        }]
    })
}

struct TimedRegistry {
    mock: MockRegistry,
    verdicts: Arrivals,
    tarballs: Arrivals,
}

impl TimedRegistry {
    async fn start(mode: &str) -> Self {
        let mock = MockRegistry::start().await;
        let tarball = make_tarball(PACKAGE, VERSION);
        mock.with_package(PACKAGE, VERSION, &tarball).await;

        let tarballs = Arrivals::default();
        Mock::given(method("GET"))
            .and(path(MockRegistry::tarball_path(PACKAGE, VERSION)))
            .respond_with(RecordArrival {
                arrivals: Arc::clone(&tarballs),
                response: ResponseTemplate::new(200).set_body_bytes(tarball),
            })
            .with_priority(1)
            .mount(mock.server())
            .await;

        let verdicts = Arrivals::default();
        Mock::given(method("POST"))
            .and(path("/api/registry/-/npm-firewall/verdicts"))
            .respond_with(RecordArrival {
                arrivals: Arc::clone(&verdicts),
                response: ResponseTemplate::new(200)
                    .set_delay(VERDICT_DELAY)
                    .set_body_json(warn_verdict(mode)),
            })
            .with_priority(1)
            .mount(mock.server())
            .await;

        Self {
            mock,
            verdicts,
            tarballs,
        }
    }

    fn install(&self, project: &TempProject) -> std::process::Output {
        self.install_with(project, &[])
    }

    fn install_with(&self, project: &TempProject, extra: &[&str]) -> std::process::Output {
        lpm_with_registry(project, &self.mock.url())
            .args([
                "--color",
                "never",
                "install",
                "--no-skills",
                "--no-editor-setup",
            ])
            .args(extra)
            .output()
            .expect("run lpm install")
    }

    fn reset_arrivals(&self) {
        self.verdicts.lock().unwrap().clear();
        self.tarballs.lock().unwrap().clear();
    }

    /// Time from the verdict request's arrival to the first tarball request.
    /// Negative when the download started first.
    fn download_start_after_verdict_request(&self) -> f64 {
        let verdicts = self.verdicts.lock().unwrap();
        let tarballs = self.tarballs.lock().unwrap();
        assert_eq!(verdicts.len(), 1, "expected one verdict request");
        assert_eq!(tarballs.len(), 1, "expected one tarball download");
        let (verdict, tarball) = (verdicts[0], tarballs[0]);
        if tarball >= verdict {
            tarball.duration_since(verdict).as_secs_f64()
        } else {
            -verdict.duration_since(tarball).as_secs_f64()
        }
    }
}

fn consumer_project() -> TempProject {
    TempProject::empty(&format!(
        r#"{{"name":"consumer","version":"1.0.0","dependencies":{{"{PACKAGE}":"{VERSION}"}}}}"#
    ))
}

fn assert_monitor_warning_reported(output: &std::process::Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("! LPM Firewall monitor: 0 would-block, 1 warned; command continues because monitor mode is active."),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("  › {PACKAGE}@{VERSION} - ")),
        "{stderr}"
    );
}

#[tokio::test]
async fn monitor_install_downloads_without_waiting_for_the_verdict() {
    let registry = TimedRegistry::start("monitor").await;
    let project = consumer_project();
    write_npm_firewall_global_config(&project, "monitor");

    let output = registry.install(&project);

    assert_monitor_warning_reported(&output);
    let gap = registry.download_start_after_verdict_request();
    assert!(
        gap < VERDICT_DELAY.as_secs_f64() / 2.0,
        "monitor mode held the download {gap:.2}s for a verdict delayed {VERDICT_DELAY:?}"
    );
}

#[tokio::test]
async fn monitor_lockfile_install_downloads_without_waiting_for_the_verdict() {
    let registry = TimedRegistry::start("monitor").await;
    let project = consumer_project();
    write_npm_firewall_global_config(&project, "off");
    let first = registry.install(&project);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(project.file_exists("lpm.lock"));
    for dir in [
        project.path().join("node_modules"),
        project.store_dir(),
        project.cache_dir(),
    ] {
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("remove install state");
        }
    }
    write_npm_firewall_global_config(&project, "monitor");
    registry.reset_arrivals();

    let output = registry.install(&project);

    assert_monitor_warning_reported(&output);
    let gap = registry.download_start_after_verdict_request();
    assert!(
        gap < VERDICT_DELAY.as_secs_f64() / 2.0,
        "monitor mode held the download {gap:.2}s for a verdict delayed {VERDICT_DELAY:?}"
    );
}

#[tokio::test]
async fn enforce_install_holds_downloads_until_the_verdict_arrives() {
    let registry = TimedRegistry::start("enforce").await;
    let project = consumer_project();
    write_npm_firewall_global_config(&project, "enforce");

    let output = registry.install(&project);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let gap = registry.download_start_after_verdict_request();
    assert!(
        gap >= VERDICT_DELAY.as_secs_f64() * 0.95,
        "enforce mode started the download {gap:.2}s after requesting a verdict delayed {VERDICT_DELAY:?}"
    );
}

#[tokio::test]
async fn monitor_workspace_install_downloads_without_waiting_for_the_verdict() {
    let registry = TimedRegistry::start("monitor").await;
    let project = TempProject::empty(&format!(
        r#"{{"name":"monitor-workspace","version":"1.0.0","private":true,"workspaces":["packages/*"],"dependencies":{{"{PACKAGE}":"{VERSION}"}}}}"#
    ));
    project.write_file(
        "packages/member/package.json",
        r#"{"name":"@fixture/member","version":"1.0.0","private":true}"#,
    );
    write_npm_firewall_global_config(&project, "monitor");

    let output = registry.install_with(&project, &["--recursive"]);

    assert_monitor_warning_reported(&output);
    let gap = registry.download_start_after_verdict_request();
    assert!(
        gap < VERDICT_DELAY.as_secs_f64() / 2.0,
        "monitor mode held the workspace download {gap:.2}s for a verdict delayed {VERDICT_DELAY:?}"
    );
}

#[tokio::test]
async fn monitor_download_does_not_wait_for_the_verdict() {
    let registry = TimedRegistry::start("monitor").await;
    let project = TempProject::empty(r#"{"name":"consumer","version":"1.0.0"}"#);
    write_npm_firewall_global_config(&project, "monitor");
    write_lpm_proxy_npmrc(&project, &registry.mock.url());

    let output = lpm_with_registry(&project, &registry.mock.url())
        .args([
            "--color",
            "never",
            "download",
            PACKAGE,
            "--version",
            VERSION,
        ])
        .args(["--output", "downloaded"])
        .output()
        .expect("run lpm download");

    assert_monitor_warning_reported(&output);
    assert!(project.file_exists("downloaded/package.json"));
    let gap = registry.download_start_after_verdict_request();
    assert!(
        gap < VERDICT_DELAY.as_secs_f64() / 2.0,
        "monitor mode held the download {gap:.2}s for a verdict delayed {VERDICT_DELAY:?}"
    );
}
