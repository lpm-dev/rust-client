use std::time::Duration;

use wait_timeout::ChildExt;

pub(super) fn kill_process_tree(child: &mut std::process::Child) {
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
/// `setsid` escapes (M20).
///
/// Output rows are `<pid> <ppid>` per line with trailing whitespace.
/// Both BSD `ps` (macOS) and procps `ps` (Linux) honor `-A -o
/// pid=,ppid=` identically — the `=` suffix on each format spec
/// suppresses the header row, so no parsing of column headers is
/// needed.
#[cfg(unix)]
pub(super) fn collect_unix_descendants(root: u32) -> Vec<u32> {
    let out = match std::process::Command::new("ps")
        .args(["-A", "-o", "pid=,ppid="])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
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
    use std::collections::{HashMap, HashSet};
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
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
        children.entry(ppid).or_default().push(pid);
    }
    let mut out = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();
    visited.insert(root);
    let mut frontier = vec![root];
    while let Some(p) = frontier.pop() {
        if let Some(kids) = children.get(&p) {
            for k in kids {
                if visited.insert(*k) {
                    out.push(*k);
                    frontier.push(*k);
                }
            }
        }
    }
    out
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
}

/// Wait for a child process with a timeout.
/// On timeout, kills the process group (Unix) or the Job Object
/// tree (Windows) via [`kill_process_tree`]. On normal exit, releases
/// the Windows Job-tracker entry so the kernel can reclaim the Job
/// handle the sandbox stashed for kill-tree parity.
pub(super) fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: &Duration,
) -> Result<std::process::ExitStatus, String> {
    let pid = child.id();

    match child
        .wait_timeout(*timeout)
        .map_err(|error| format!("wait error: {error}"))?
    {
        Some(status) => {
            lpm_sandbox::release_sandbox_tracker(pid);
            Ok(status)
        }
        None => {
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
    use super::wait_with_timeout;
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn wait_with_timeout_returns_promptly_for_short_lived_children() {
        let start = Instant::now();
        for _ in 0..4 {
            let child = Command::new("sh")
                .args(["-c", "sleep 0.01"])
                .spawn()
                .expect("spawn short-lived child");
            let status = wait_with_timeout(child, &Duration::from_secs(5))
                .expect("short-lived child should exit normally");
            assert!(status.success());
        }

        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(250),
            "four 10ms children should not inherit a 100ms polling floor: {:?}",
            elapsed
        );
    }
}
