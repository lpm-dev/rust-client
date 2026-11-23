//! Tests of the request gate in `support`: what each way of breaking a
//! bounded pool makes it say, with an in-process client in place of lpm.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::request_gate::RequestGate;
use tokio::sync::Semaphore;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const LIMIT: usize = 3;
const TOTAL: usize = 6;

/// How long a test that must see a pool go over its limit watches for the
/// extra request at each step: twenty quiet periods, so only a runner that
/// stalls that long hides it, and well inside the clients' read timeouts.
const WATCH: Duration = Duration::from_secs(5);

/// How a test client schedules its requests.
#[derive(Clone, Copy)]
enum Pool {
    /// At most `n` at once, starting another as each ends.
    Bounded(usize),
    /// `LIMIT` at once, and one more from the first answer on.
    GrowsOnRefill,
    /// `LIMIT` at a time, each batch only once the one before has ended.
    Waves,
    /// `LIMIT` at once, and one more request this long after the first
    /// answer, while the others are still held.
    LateExtra(Duration),
}

/// Start a client that sends `TOTAL` requests to `url` as `pool` says, and
/// gives up on a request after `read_timeout`.
fn client(url: &str, pool: Pool, read_timeout: Duration) -> tokio::task::JoinHandle<()> {
    let url = url.to_owned();
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .no_proxy()
            .read_timeout(read_timeout)
            .build()
            .expect("client");
        let get = |index: usize| {
            let client = client.clone();
            let url = format!("{url}/item/{index}");
            async move {
                let _ = client
                    .get(url)
                    .send()
                    .await
                    .and_then(|response| response.error_for_status());
            }
        };
        match pool {
            Pool::Bounded(_) | Pool::GrowsOnRefill | Pool::LateExtra(_) => {
                let initial = match pool {
                    Pool::Bounded(n) => n,
                    _ => LIMIT,
                };
                let mut late_extra = match pool {
                    Pool::LateExtra(delay) => Some((delay, get(TOTAL))),
                    _ => None,
                };
                let permits = Arc::new(Semaphore::new(initial));
                let grow = matches!(pool, Pool::GrowsOnRefill);
                let mut tasks = Vec::with_capacity(TOTAL);
                for index in 0..TOTAL {
                    let permit = Arc::clone(&permits).acquire_owned().await.expect("permit");
                    let request = get(index);
                    let permits = Arc::clone(&permits);
                    let extra = if index == 0 { late_extra.take() } else { None };
                    tasks.push(tokio::spawn(async move {
                        request.await;
                        if grow && index == 0 {
                            permits.add_permits(1);
                        }
                        if let Some((delay, extra)) = extra {
                            tokio::spawn(async move {
                                tokio::time::sleep(delay).await;
                                extra.await;
                            });
                        }
                        drop(permit);
                    }));
                }
                for task in tasks {
                    let _ = task.await;
                }
            }
            Pool::Waves => {
                for wave in (0..TOTAL).collect::<Vec<_>>().chunks(LIMIT) {
                    futures_util::future::join_all(wave.iter().map(|index| get(*index))).await;
                }
            }
        }
    })
}

async fn gate() -> (MockServer, RequestGate) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;
    let gate = RequestGate::start(&server.uri(), |request| {
        request.uri.path().starts_with("/item/")
    });
    (server, gate)
}

#[tokio::test]
async fn a_pool_that_keeps_its_limit_and_refills_each_freed_slot_passes() {
    let (_server, mut gate) = gate().await;
    let client = client(gate.url(), Pool::Bounded(LIMIT), Duration::from_secs(60));
    gate.hold_a_bounded_pool(LIMIT, TOTAL).await;
    client.await.expect("client");
    gate.assert_held(TOTAL);
}

#[tokio::test]
#[should_panic(expected = "more than 3 requests were in flight")]
async fn a_pool_that_runs_more_than_its_limit_from_the_start_fails() {
    let (_server, mut gate) = gate().await;
    let _client = client(
        gate.url(),
        Pool::Bounded(LIMIT + 1),
        Duration::from_secs(60),
    );
    gate.hold_a_bounded_pool_watching(LIMIT, TOTAL, WATCH).await;
}

#[tokio::test]
#[should_panic(expected = "more than 3 requests were in flight")]
async fn a_pool_that_goes_past_its_limit_only_when_it_refills_fails() {
    let (_server, mut gate) = gate().await;
    let _client = client(gate.url(), Pool::GrowsOnRefill, Duration::from_secs(60));
    gate.hold_a_bounded_pool_watching(LIMIT, TOTAL, WATCH).await;
}

#[tokio::test]
#[should_panic(expected = "more than 3 requests were in flight")]
async fn a_pool_whose_extra_request_starts_seconds_after_a_refill_fails() {
    let (_server, mut gate) = gate().await;
    let _client = client(
        gate.url(),
        Pool::LateExtra(Duration::from_secs(2)),
        Duration::from_secs(60),
    );
    gate.hold_a_bounded_pool_watching(LIMIT, TOTAL, WATCH).await;
}

#[tokio::test]
#[should_panic(expected = "more than 3 requests were in flight: 4 at once")]
async fn a_gate_that_held_more_than_the_limit_at_once_says_the_limit_was_passed() {
    let (_server, mut gate) = gate().await;
    let _client = client(
        gate.url(),
        Pool::Bounded(LIMIT + 1),
        Duration::from_secs(60),
    );
    let mut held = Vec::with_capacity(LIMIT + 1);
    for _ in 0..=LIMIT {
        held.push(gate.next().await);
    }
    held.into_iter()
        .for_each(support::request_gate::HeldRequest::release);
    gate.assert_peak(LIMIT).await;
}

#[tokio::test]
#[should_panic(expected = "after its own read timeout")]
async fn a_pool_that_waits_for_a_whole_wave_before_it_refills_fails() {
    let (_server, mut gate) = gate().await;
    let _client = client(gate.url(), Pool::Waves, Duration::from_secs(2));
    gate.hold_a_bounded_pool(LIMIT, TOTAL).await;
}

#[tokio::test]
#[should_panic(expected = "after its own read timeout")]
async fn a_pool_that_runs_fewer_than_its_limit_fails() {
    let (_server, mut gate) = gate().await;
    let _client = client(gate.url(), Pool::Bounded(LIMIT - 1), Duration::from_secs(2));
    gate.hold_a_bounded_pool(LIMIT, TOTAL).await;
}

#[cfg(unix)]
#[tokio::test]
#[should_panic(expected = "stderr: the command's own error")]
async fn a_command_that_exits_while_its_requests_are_awaited_shows_its_output() {
    let (_server, mut gate) = gate().await;
    let mut command = std::process::Command::new("sh");
    command.args(["-c", "echo \"the command's own error\" >&2; exit 3"]);
    support::request_gate::run_while(command, async {
        gate.next().await;
    })
    .await;
}

/// Run `command` with a step that fails once `ready` exists, and what
/// `run_while` panicked with.
#[cfg(unix)]
async fn failing_step(command: std::process::Command, ready: Option<&std::path::Path>) -> String {
    use futures_util::FutureExt as _;
    let failed = std::panic::AssertUnwindSafe(support::request_gate::run_while(command, async {
        if let Some(ready) = ready {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        panic!("the drive's own reason");
    }))
    .catch_unwind()
    .await
    .expect_err("the step failed");
    failed.downcast_ref::<String>().cloned().expect("a message")
}

#[cfg(unix)]
#[tokio::test]
async fn a_failed_step_says_why_and_stops_the_command() {
    let folder = tempfile::tempdir().expect("folder");
    let finished = folder.path().join("finished");
    let mut command = std::process::Command::new("sh");
    command
        .args(["-c", "sleep 2 && touch \"$0\""])
        .arg(&finished);
    let started = std::time::Instant::now();

    let message = failing_step(command, None).await;

    assert!(
        message.contains("the test failed: the drive's own reason"),
        "{message}"
    );
    // Long enough for the command to have finished, had it not been stopped.
    tokio::time::sleep(Duration::from_secs(3).saturating_sub(started.elapsed())).await;
    assert!(!finished.exists(), "the command ran on");
}

#[cfg(unix)]
#[tokio::test]
async fn a_failed_step_ends_though_something_the_command_started_holds_its_output() {
    let folder = tempfile::tempdir().expect("folder");
    let holding = folder.path().join("holding");
    let mut command = std::process::Command::new("sh");
    command
        .args(["-c", "echo started; sleep 600 & touch \"$0\"; wait"])
        .arg(&holding);

    let message = tokio::time::timeout(
        support::request_gate::WAIT_LIMIT / 2,
        failing_step(command, Some(&holding)),
    )
    .await
    .expect("the failure is said without waiting for the sleep");

    assert!(message.contains("stdout: started"), "{message}");
}
