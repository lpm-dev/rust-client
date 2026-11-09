//! macOS process-tree tracking for Seatbelt spawns.
//!
//! A descendant can leave its process group and session with `setsid`, and
//! once its parent exits launchd adopts it, so neither the group nor the
//! parent chain still reaches it. Its Seatbelt profile does: every
//! descendant inherits the profile, and the kernel refuses a sandboxed
//! process a second one. Each spawn's profile therefore carries a
//! [`ProfileMark`], a Mach service name it allows and a sibling name it
//! denies, both built from a random token. No other profile answers that
//! pair the same way, so [`terminate_sandbox_tree`] can find and end every
//! process the spawn started, however it detached.

#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::{LazyLock, Mutex};

/// `SANDBOX_FILTER_GLOBAL_NAME` from `enum sandbox_filter_type`.
const SANDBOX_FILTER_GLOBAL_NAME: c_int = 2;
/// `PROC_RUID_ONLY` from `<sys/proc_info.h>`.
const PROC_RUID_ONLY: u32 = 5;
/// Bounds the sweep against a tree that keeps forking while it is ended.
const MAX_SWEEPS: usize = 64;
const SWEEP_PAUSE: std::time::Duration = std::time::Duration::from_millis(2);

unsafe extern "C" {
    safe static SANDBOX_CHECK_NO_REPORT: c_int;
    fn sandbox_check(pid: libc::pid_t, operation: *const c_char, filter: c_int, ...) -> c_int;
}

/// The per-spawn identity rendered into a Seatbelt profile.
pub(crate) struct ProfileMark {
    allowed: CString,
    denied: CString,
}

impl ProfileMark {
    pub(crate) fn new() -> Self {
        let mut token = [0_u8; 16];
        // SAFETY: arc4random_buf fills exactly `token.len()` bytes and cannot fail.
        unsafe { libc::arc4random_buf(token.as_mut_ptr().cast(), token.len()) };
        let mut denied = String::with_capacity(16 + 2 * token.len());
        denied.push_str("dev.lpm.sandbox.");
        for byte in token {
            denied.push(char::from(HEX[usize::from(byte >> 4)]));
            denied.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        let allowed = format!("{denied}.member");
        Self {
            allowed: CString::new(allowed).expect("hex token has no NUL"),
            denied: CString::new(denied).expect("hex token has no NUL"),
        }
    }

    /// Appends the rules that make a profile carry this mark. They go last,
    /// so no broader rule earlier in the profile can override them.
    pub(crate) fn append_rules(&self, profile: &mut String) {
        for (action, name) in [("allow", &self.allowed), ("deny", &self.denied)] {
            profile.push('(');
            profile.push_str(action);
            profile.push_str(" mach-lookup (global-name \"");
            profile.push_str(name.to_str().expect("hex token is ASCII"));
            profile.push_str("\"))\n");
        }
    }

    /// Whether `pid` is a live process running under a profile with this
    /// mark. Unsandboxed processes allow both names, other profiles deny
    /// both or allow both, and exited processes deny both.
    fn is_on(&self, pid: libc::pid_t) -> bool {
        lookup_denied(pid, &self.allowed) == Some(false)
            && lookup_denied(pid, &self.denied) == Some(true)
    }

    /// Sends SIGKILL to every process carrying this mark until a sweep finds
    /// none left. Returns how many marked processes were still found when
    /// the sweep limit ran out.
    fn end_marked_processes(&self) -> usize {
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        let mut pids = Vec::new();
        let mut remaining = 0;
        for sweep in 0..MAX_SWEEPS {
            if sweep > 0 {
                std::thread::sleep(SWEEP_PAUSE);
            }
            list_processes_of_real_user(uid, &mut pids);
            remaining = 0;
            for &pid in &pids {
                if pid > 1 && self.is_on(pid) {
                    remaining += 1;
                    // SAFETY: SIGKILL to one process this spawn started; ESRCH
                    // after it exits on its own is harmless.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
            }
            if remaining == 0 {
                return 0;
            }
        }
        remaining
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// `Some(true)` when `pid`'s profile denies looking up the Mach service
/// `name`, `Some(false)` when it allows it, `None` when the check failed.
fn lookup_denied(pid: libc::pid_t, name: &CStr) -> Option<bool> {
    // SAFETY: both strings are NUL-terminated and outlive the call; the
    // global-name filter takes exactly one `const char *` variadic argument.
    let result = unsafe {
        sandbox_check(
            pid,
            c"mach-lookup".as_ptr(),
            SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT,
            name.as_ptr(),
        )
    };
    match result {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// Fills `pids` with the processes whose real user is `uid`: the only
/// processes this one may signal, which includes every process a spawn
/// started, even one running a set-user-ID program.
fn list_processes_of_real_user(uid: libc::uid_t, pids: &mut Vec<libc::pid_t>) {
    pids.clear();
    loop {
        // SAFETY: a null buffer asks only for the size needed.
        let needed = unsafe { libc::proc_listpids(PROC_RUID_ONLY, uid, std::ptr::null_mut(), 0) };
        let Ok(needed) = usize::try_from(needed) else {
            return;
        };
        let capacity = needed / size_of::<libc::pid_t>() + 64;
        pids.reserve(capacity.saturating_sub(pids.capacity()));
        let bytes =
            c_int::try_from(pids.capacity() * size_of::<libc::pid_t>()).unwrap_or(c_int::MAX);
        // SAFETY: the buffer holds `bytes` bytes of writable pid_t storage.
        let written =
            unsafe { libc::proc_listpids(PROC_RUID_ONLY, uid, pids.as_mut_ptr().cast(), bytes) };
        let Ok(written) = usize::try_from(written) else {
            return;
        };
        if written < usize::try_from(bytes).unwrap_or(usize::MAX) {
            // SAFETY: the kernel initialized `written` bytes of whole pid_t values.
            unsafe { pids.set_len(written / size_of::<libc::pid_t>()) };
            return;
        }
    }
}

/// Spawned profiles' marks by the root process's PID.
static TRACKED: LazyLock<Mutex<HashMap<u32, ProfileMark>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) fn track(pid: u32, mark: ProfileMark) {
    TRACKED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(pid, mark);
}

/// Ends every process the spawn rooted at `pid` started, wherever it now
/// sits in the process tree, and forgets the spawn.
///
/// Idempotent: a PID that isn't tracked is a no-op.
pub(crate) fn terminate_sandbox_tree(pid: u32) {
    let mark = TRACKED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&pid);
    if let Some(mark) = mark {
        let remaining = mark.end_marked_processes();
        if remaining > 0 {
            tracing::warn!(
                pid,
                remaining,
                "lifecycle processes kept starting while their sandbox was ended"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const BASE_PROFILE: &str = "(version 1)\n(deny default)\n(allow process*)\n\
        (allow file-read*)\n(allow file-write* (literal \"/dev/null\") (subpath \"/private/tmp\") \
        (subpath \"/private/var/folders\"))\n(allow sysctl-read)\n(allow mach-lookup)\n\
        (allow signal (target same-sandbox))\n";

    fn spawn_marked(mark: &ProfileMark, script: &str) -> std::process::Child {
        let mut profile = BASE_PROFILE.to_string();
        mark.append_rules(&mut profile);
        std::process::Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/bin/sh", "-c", script])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("spawn under sandbox-exec")
    }

    fn read_pid(path: &std::path::Path) -> libc::pid_t {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(text) = std::fs::read_to_string(path)
                && let Ok(pid) = text.trim().parse()
            {
                return pid;
            }
            assert!(
                Instant::now() < deadline,
                "{} never appeared",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn is_running(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only checks that the process exists.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    fn wait_until_gone(pid: libc::pid_t) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while is_running(pid) {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    fn daemonize_script(pid_file: &std::path::Path) -> String {
        format!(
            "/usr/bin/perl -MPOSIX -e 'exit 0 if fork; POSIX::setsid(); exit 0 if fork; \
             open(my $f, \">\", \"{}\") or die; print $f $$; close $f; sleep 30'",
            pid_file.display()
        )
    }

    #[test]
    fn marks_from_two_spawns_never_share_a_name() {
        let (first, second) = (ProfileMark::new(), ProfileMark::new());
        assert_ne!(first.denied, second.denied);
        assert_ne!(first.allowed, second.allowed);
    }

    #[test]
    fn ending_a_spawn_kills_a_descendant_that_left_its_session_and_parent() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("daemon.pid");
        let mark = ProfileMark::new();
        let mut root = spawn_marked(&mark, &daemonize_script(&pid_file));
        let root_pid = root.id();
        assert!(root.wait().unwrap().success());
        let daemon = read_pid(&pid_file);
        assert!(
            is_running(daemon),
            "the fixture daemon must outlive its root"
        );

        track(root_pid, mark);
        terminate_sandbox_tree(root_pid);

        assert!(
            wait_until_gone(daemon),
            "a setsid daemon reparented to launchd survived its spawn's end"
        );
    }

    #[test]
    fn ending_a_spawn_leaves_other_spawns_and_unsandboxed_processes_running() {
        let dir = tempfile::tempdir().unwrap();
        let ended_file = dir.path().join("ended.pid");
        let kept_file = dir.path().join("kept.pid");
        let ended_mark = ProfileMark::new();
        let kept_mark = ProfileMark::new();
        let mut ended_root = spawn_marked(&ended_mark, &daemonize_script(&ended_file));
        let mut kept_root = spawn_marked(&kept_mark, &daemonize_script(&kept_file));
        let mut unsandboxed = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let ended_root_pid = ended_root.id();
        assert!(ended_root.wait().unwrap().success());
        assert!(kept_root.wait().unwrap().success());
        let ended = read_pid(&ended_file);
        let kept = read_pid(&kept_file);

        track(ended_root_pid, ended_mark);
        terminate_sandbox_tree(ended_root_pid);

        let ended_gone = wait_until_gone(ended);
        let kept_alive = is_running(kept);
        let unsandboxed_alive = unsandboxed.try_wait().unwrap().is_none();
        // SAFETY: SIGKILL to the fixture daemon this test started.
        unsafe { libc::kill(kept, libc::SIGKILL) };
        let _ = unsandboxed.kill();
        let _ = unsandboxed.wait();

        assert!(ended_gone, "the ended spawn's daemon survived");
        assert!(
            kept_alive,
            "ending one spawn killed another spawn's process"
        );
        assert!(
            unsandboxed_alive,
            "ending a spawn killed an unsandboxed process"
        );
    }

    #[test]
    fn ending_an_untracked_pid_does_nothing() {
        let mut unsandboxed = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        terminate_sandbox_tree(unsandboxed.id());
        let alive = unsandboxed.try_wait().unwrap().is_none();
        let _ = unsandboxed.kill();
        let _ = unsandboxed.wait();
        assert!(alive);
    }
}
