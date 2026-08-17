use std::time::Duration;

use wait_timeout::ChildExt;

pub(in crate::commands) fn kill_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pid = child.id();
        // Snapshot descendants BEFORE the kill — once the pgrp is
        // SIGKILL'd, surviving orphans get reparented to init (or a
        // subreaper) and their original PPID is lost.
        let descendants = collect_unix_descendants(pid);
        let signed = pid as i32;
        // SAFETY: kill(-pid) sends SIGKILL to the whole process group.
        unsafe {
            libc::kill(-signed, libc::SIGKILL);
        }
        // Then mop up any pgid-detached survivors by individual pid.
        for d in descendants {
            // SAFETY: kill(pid) sends SIGKILL to one process. ESRCH
            // (already gone) is harmless and expected for most
            // entries since the pgrp kill above usually catches them.
            unsafe {
                libc::kill(d as i32, libc::SIGKILL);
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Tell the sandbox crate to terminate the Job Object tree
        // associated with this PID. The tracker holds the Job
        // handle, so without this call the kernel's
        // KILL_ON_JOB_CLOSE policy never fires (the handle isn't
        // closed until parent exit). Belt-and-suspenders:
        // `child.kill()` after, so the root child is reaped even if
        // the PID wasn't tracked (e.g. SandboxMode::Disabled +
        // NoopSandbox routed through here).
        lpm_sandbox::terminate_sandbox_tree(child.id());
        let _ = child.kill();
    }
}

/// Collect every descendant pid of `root` by shelling out to
/// `ps -A -o pid=,ppid=` and walking the PPID chain. Returns an
/// empty Vec on any failure — the caller's pgrp kill is the primary
/// path; descendant kill is defense-in-depth against `setpgid` /
/// `setsid` escapes.
///
/// Output rows are `<pid> <ppid>` per line with trailing whitespace.
/// Both BSD `ps` (macOS) and procps `ps` (Linux) honor `-A -o
/// pid=,ppid=` identically — the `=` suffix on each format spec
/// suppresses the header row, so no parsing of column headers is
/// needed.
#[cfg(unix)]
pub(super) fn collect_unix_descendants(root: u32) -> Vec<u32> {
    use std::io::Read;
    use std::process::Stdio;
    use wait_timeout::ChildExt;

    const PS_OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;
    const PS_TIMEOUT: Duration = Duration::from_millis(500);

    let Some(ps) = ["/bin/ps", "/usr/bin/ps"]
        .into_iter()
        .map(std::path::Path::new)
        .find(|path| path.is_file())
    else {
        return Vec::new();
    };
    let mut child = match std::process::Command::new(ps)
        .args(["-A", "-o", "pid=,ppid="])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        _ => return Vec::new(),
    };
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Vec::new();
    };
    let reader = match std::thread::Builder::new()
        .name("lpm-ps-snapshot".to_string())
        .spawn(move || {
            let mut bytes = Vec::new();
            let _ = stdout
                .by_ref()
                .take(PS_OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes);
            bytes
        }) {
        Ok(reader) => reader,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Vec::new();
        }
    };
    let status = match child.wait_timeout(PS_TIMEOUT) {
        Ok(Some(status)) => status,
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Vec::new();
        }
    };
    let Ok(out) = reader.join() else {
        return Vec::new();
    };
    if !status.success() || out.len() > PS_OUTPUT_LIMIT as usize {
        return Vec::new();
    }
    let text = match std::str::from_utf8(&out) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    collect_descendants_from_ps_output(text, root)
}

/// Pure-logic helper for [`collect_unix_descendants`] — split out so
/// the BFS-and-parser shape is covered by deterministic unit tests
/// without spawning `ps`.
///
/// A `visited` set guards against pathological cycles in the input.
/// Real `ps` output cannot contain a ppid cycle (pids form a tree by
/// definition — every process has exactly one parent), but a
/// malformed fixture, a future regression that produces synthetic
/// rows, or a hostile environment that intercepts `ps` could feed
/// one. Without the guard, a cycle like `100→200→300→200` would
/// infinite-loop the BFS.
#[cfg(unix)]
pub(super) fn collect_descendants_from_ps_output(text: &str, root: u32) -> Vec<u32> {
    use std::collections::HashSet;

    let mut edges = Vec::with_capacity(text.len() / 16);
    for line in text.lines() {
        let mut it = line.split_ascii_whitespace();
        let pid = match it.next().and_then(|s| s.parse::<u32>().ok()) {
            Some(v) => v,
            None => continue,
        };
        let ppid = match it.next().and_then(|s| s.parse::<u32>().ok()) {
            Some(v) => v,
            None => continue,
        };
        edges.push((ppid, pid));
    }
    edges.sort_unstable();

    let first_root_child = edges.partition_point(|(ppid, _)| *ppid < root);
    let after_root_children = edges.partition_point(|(ppid, _)| *ppid <= root);
    if first_root_child == after_root_children {
        return Vec::new();
    }
    let initial_capacity = (after_root_children - first_root_child)
        .saturating_mul(2)
        .max(4);
    let mut visited = HashSet::with_capacity(initial_capacity);
    visited.insert(root);
    let mut descendants = Vec::with_capacity(initial_capacity);
    descendants.push(root);
    let mut cursor = 0;
    while cursor < descendants.len() {
        let parent = descendants[cursor];
        cursor += 1;
        let first = edges.partition_point(|(ppid, _)| *ppid < parent);
        let end = edges.partition_point(|(ppid, _)| *ppid <= parent);
        for (_, child) in &edges[first..end] {
            if visited.insert(*child) {
                descendants.push(*child);
            }
        }
    }
    descendants.remove(0);
    descendants
}

#[cfg(all(test, unix))]
mod kill_tree_tests {
    use super::collect_descendants_from_ps_output;

    #[test]
    fn descendants_bfs_walks_ppid_chain_two_levels() {
        // root=100; 200 is child; 300 is grandchild via 200.
        // 999 is unrelated. Expected output: {200, 300} in some order.
        let ps = "  100   1\n  200 100\n  300 200\n  999   1\n";
        let mut got = collect_descendants_from_ps_output(ps, 100);
        got.sort();
        assert_eq!(got, vec![200, 300]);
    }

    #[test]
    fn descendants_handles_pgid_detached_orphan_by_ppid_chain() {
        // Setpgid escapee: pid 500 detached pgrp but its PPID is
        // still 400 (the lifecycle script root). The BFS must catch
        // it via PPID alone.
        let ps = "  400   1\n  500 400\n  600   1\n";
        let got = collect_descendants_from_ps_output(ps, 400);
        assert_eq!(got, vec![500]);
    }

    #[test]
    fn descendants_returns_empty_on_no_match() {
        let ps = "  10   1\n  20  10\n";
        let got = collect_descendants_from_ps_output(ps, 999);
        assert!(got.is_empty());
    }

    #[test]
    fn descendants_tolerates_malformed_rows() {
        // Garbage row + missing-ppid row + ok row. Parser must
        // discard the malformed lines and still find the orphan.
        let ps = "\ngarbage\n  abc def\n  10\n  20  10\n";
        let got = collect_descendants_from_ps_output(ps, 10);
        assert_eq!(got, vec![20]);
    }

    #[test]
    fn descendants_does_not_include_root_in_a_self_loop() {
        // Pathological self-parent shouldn't infinite-loop or
        // include the root itself.
        let ps = "  77  77\n  88  77\n";
        let got = collect_descendants_from_ps_output(ps, 77);
        assert_eq!(got, vec![88]);
    }

    #[test]
    fn descendants_terminates_on_multi_node_ppid_cycle() {
        // 100 → 200 → 300 → 200 forms a 2-cycle on {200, 300}.
        // Without a visited-set the BFS would re-push 200 then 300
        // forever. With the guard, each node is enqueued once and
        // the walk terminates.
        let ps = "  100   1\n  200 100\n  300 200\n  200 300\n";
        let mut got = collect_descendants_from_ps_output(ps, 100);
        got.sort();
        assert_eq!(got, vec![200, 300]);
    }

    #[test]
    #[ignore = "manual peak-RSS probe at the process-table input cap"]
    fn descendants_peak_rss_at_input_cap() {
        use std::collections::{HashMap, HashSet};
        use std::fmt::Write as _;

        let mode =
            std::env::var("LPM_PROCESS_TREE_BENCH_MODE").unwrap_or_else(|_| "sorted".to_string());
        let shape =
            std::env::var("LPM_PROCESS_TREE_BENCH_SHAPE").unwrap_or_else(|_| "chain".to_string());
        let record_count = std::env::var("LPM_PROCESS_TREE_BENCH_RECORDS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(250_000);
        let mut process_table = String::with_capacity(record_count as usize * 16);
        for pid in 2..record_count.saturating_add(2) {
            let parent = match shape.as_str() {
                "chain" => pid - 1,
                "star" => 1,
                "unrelated" => pid + 1,
                other => panic!("unknown LPM_PROCESS_TREE_BENCH_SHAPE `{other}`"),
            };
            writeln!(&mut process_table, "{pid} {parent}").unwrap();
        }

        let started = std::time::Instant::now();
        let descendants = match mode.as_str() {
            "fixture" => None,
            "sorted" => Some(collect_descendants_from_ps_output(&process_table, 1)),
            "hashmap" => {
                let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
                for line in process_table.lines() {
                    let mut fields = line.split_ascii_whitespace();
                    let Some(child) = fields.next().and_then(|value| value.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    let Some(parent) = fields.next().and_then(|value| value.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    children.entry(parent).or_default().push(child);
                }
                let mut descendants = Vec::new();
                let mut visited = HashSet::new();
                visited.insert(1);
                let mut frontier = vec![1];
                while let Some(parent) = frontier.pop() {
                    if let Some(children) = children.get(&parent) {
                        for child in children {
                            if visited.insert(*child) {
                                descendants.push(*child);
                                frontier.push(*child);
                            }
                        }
                    }
                }
                std::hint::black_box(children);
                Some(descendants)
            }
            other => panic!("unknown LPM_PROCESS_TREE_BENCH_MODE `{other}`"),
        };
        let expected = if shape == "unrelated" {
            0
        } else {
            record_count as usize
        };
        if let Some(descendants) = descendants.as_ref() {
            assert_eq!(descendants.len(), expected);
        }
        eprintln!(
            "process_tree mode={mode} shape={shape} bytes={} records={} descendants={} elapsed_us={}",
            process_table.len(),
            record_count,
            descendants.as_ref().map_or(0, Vec::len),
            started.elapsed().as_micros()
        );
        std::hint::black_box(process_table);
        std::hint::black_box(descendants);
    }
}

/// Wait for a child process with a timeout.
/// On timeout, kills the process group (Unix) or the Job Object
/// tree (Windows) via [`kill_process_tree`]. On normal exit, releases
/// the Windows Job-tracker entry so the kernel can reclaim the Job
/// handle the sandbox stashed for kill-tree parity.
pub(in crate::commands) fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: &Duration,
) -> Result<std::process::ExitStatus, String> {
    let wait_result = child.wait_timeout(*timeout);
    finish_wait_with_cleanup(child, timeout, wait_result)
}

pub(in crate::commands) fn wait_with_timeout_or_cancel(
    mut child: std::process::Child,
    timeout: &Duration,
    cancelled: &std::sync::atomic::AtomicBool,
    cancellation_error: &str,
) -> Result<std::process::ExitStatus, String> {
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    let started = Instant::now();
    loop {
        if cancelled.load(Ordering::Acquire) {
            kill_process_tree(&mut child);
            let _ = child.wait();
            return Err(cancellation_error.to_string());
        }
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            return finish_wait_with_cleanup(child, timeout, Ok(None));
        };
        let wait_result = child.wait_timeout(remaining.min(Duration::from_millis(10)));
        match wait_result {
            Ok(None) => {}
            result => return finish_wait_with_cleanup(child, timeout, result),
        }
    }
}

fn finish_wait_with_cleanup(
    mut child: std::process::Child,
    timeout: &Duration,
    wait_result: std::io::Result<Option<std::process::ExitStatus>>,
) -> Result<std::process::ExitStatus, String> {
    let pid = child.id();

    match wait_result {
        Err(error) => {
            kill_process_tree(&mut child);
            let _ = child.wait();
            Err(format!("wait error: {error}"))
        }
        Ok(Some(status)) => {
            #[cfg(unix)]
            {
                let signed = pid as i32;
                // SAFETY: tracked callers create a process group whose id is
                // the root pid. ESRCH is expected when no descendants remain.
                unsafe {
                    libc::kill(-signed, libc::SIGKILL);
                }
            }
            lpm_sandbox::release_sandbox_tracker(pid);
            Ok(status)
        }
        Ok(None) => {
            kill_process_tree(&mut child);
            let _ = child.wait();
            Err(format!(
                "timeout after {}s — process group killed",
                timeout.as_secs()
            ))
        }
    }
}

#[cfg(all(test, unix))]
mod wait_with_timeout_tests {
    use super::{finish_wait_with_cleanup, wait_with_timeout};
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn wait_with_timeout_returns_success_for_short_lived_child() {
        let child = Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn short-lived child");
        let status = wait_with_timeout(child, &Duration::from_secs(5))
            .expect("short-lived child should exit normally");

        assert!(status.success());
    }

    #[test]
    fn wait_with_timeout_kills_and_reaps_long_lived_child() {
        let mut command = Command::new("sleep");
        command.arg("30").process_group(0);
        let child = command.spawn().expect("spawn long-lived child");
        let pid = child.id();

        let error = wait_with_timeout(child, &Duration::from_millis(10))
            .expect_err("long-lived child should time out");
        assert!(error.starts_with("timeout after "));

        // SAFETY: `pid` came from the child this test spawned. A second
        // non-blocking wait can only report whether that child was reaped.
        let wait_result =
            unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), libc::WNOHANG) };
        let wait_error = std::io::Error::last_os_error();
        assert_eq!(wait_result, -1);
        assert_eq!(wait_error.raw_os_error(), Some(libc::ECHILD));
    }

    #[test]
    fn wait_error_kills_and_reaps_the_tracked_child() {
        let mut command = Command::new("sleep");
        command.arg("30").process_group(0);
        let child = command.spawn().expect("spawn long-lived child");
        let pid = child.id();

        let error = finish_wait_with_cleanup(
            child,
            &Duration::from_secs(5),
            Err(std::io::Error::other("injected wait failure")),
        )
        .expect_err("injected wait failure must be returned");
        assert_eq!(error, "wait error: injected wait failure");

        // SAFETY: `pid` came from the child this test spawned. The cleanup
        // path must already have reaped it.
        let wait_result =
            unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), libc::WNOHANG) };
        let wait_error = std::io::Error::last_os_error();
        assert_eq!(wait_result, -1);
        assert_eq!(wait_error.raw_os_error(), Some(libc::ECHILD));
    }

    #[test]
    #[ignore = "manual wall-clock benchmark; scheduler-sensitive by design"]
    fn wait_with_timeout_manual_benchmark_for_four_short_lived_children() {
        let start = Instant::now();
        for _ in 0..4 {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 0.01"]).process_group(0);
            let child = command.spawn().expect("spawn short-lived child");
            let status = wait_with_timeout(child, &Duration::from_secs(5))
                .expect("short-lived child should exit normally");
            assert!(status.success());
        }

        eprintln!(
            "four serial 10 ms lifecycle children: {:?}",
            start.elapsed()
        );
    }
}
