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

    /// Sends `signal` to `pid` while it carries this mark. The PID version
    /// is read before the check that decides the signal, and the signal is
    /// bound to it, so a PID that passes to another process in between is
    /// never signalled: the signal lands only on the process that was
    /// checked.
    fn signal(&self, pid: libc::pid_t, signal: c_int) {
        if SIGNAL_ONE_PROCESS.is_none() {
            // SAFETY: a signal to one process this spawn started; ESRCH after
            // it exits on its own is harmless.
            unsafe { libc::kill(pid, signal) };
        } else if let Some(process) = ProcessIdentity::read(pid)
            && self.is_on(pid)
        {
            process.signal(signal);
        }
    }
}

/// What a sweep needs from the kernel, as a trait so the sweep's logic can
/// run against a modelled process table in tests.
trait ProcessTable {
    /// Fills `pids` with the processes this one may signal.
    fn list(&mut self, pids: &mut Vec<libc::pid_t>);
    fn is_marked(&self, pid: libc::pid_t) -> bool;
    fn is_stopped(&self, pid: libc::pid_t) -> bool;
    /// Sends `signal` to `pid` if it still carries the mark.
    fn signal_marked(&mut self, pid: libc::pid_t, signal: c_int);
    fn pause(&mut self);
}

/// The live process table, seen through one spawn's mark.
struct MarkedProcesses<'a> {
    mark: &'a ProfileMark,
    uid: libc::uid_t,
}

impl ProcessTable for MarkedProcesses<'_> {
    fn list(&mut self, pids: &mut Vec<libc::pid_t>) {
        list_processes_of_real_user(self.uid, pids);
    }

    fn is_marked(&self, pid: libc::pid_t) -> bool {
        pid > 1 && self.mark.is_on(pid)
    }

    fn is_stopped(&self, pid: libc::pid_t) -> bool {
        process_status(pid) == Some(libc::SSTOP)
    }

    fn signal_marked(&mut self, pid: libc::pid_t, signal: c_int) {
        self.mark.signal(pid, signal);
    }

    fn pause(&mut self) {
        std::thread::sleep(SWEEP_PAUSE);
    }
}

/// Ends every marked process. Returns how many were still found when the
/// sweep limit ran out.
///
/// The processes are stopped before any is killed. A stopped process can't
/// fork or signal, and it keeps its process slot: killing outright frees
/// slots that a fork storm at the per-user limit refills from whichever
/// processes the sweep hasn't reached yet, so the count never drops. A
/// marked process another one resumed is stopped again on the next pass.
fn end_marked_processes(table: &mut impl ProcessTable) -> usize {
    let mut pids = Vec::new();
    for sweep in 0..MAX_SWEEPS {
        if sweep > 0 {
            table.pause();
        }
        table.list(&mut pids);
        let (mut marked, mut running) = (0, 0);
        for &pid in &pids {
            if table.is_marked(pid) {
                marked += 1;
                if !table.is_stopped(pid) {
                    running += 1;
                    table.signal_marked(pid, libc::SIGSTOP);
                }
            }
        }
        if marked == 0 {
            return 0;
        }
        if running == 0 {
            break;
        }
    }
    let mut remaining = 0;
    for sweep in 0..MAX_SWEEPS {
        if sweep > 0 {
            table.pause();
        }
        table.list(&mut pids);
        remaining = 0;
        for &pid in &pids {
            if table.is_marked(pid) {
                remaining += 1;
                table.signal_marked(pid, libc::SIGKILL);
            }
        }
        if remaining == 0 {
            return 0;
        }
    }
    remaining
}

/// The scheduler state (`SRUN`, `SSTOP`, ...) of a live process; `None`
/// once it has exited.
fn process_status(pid: libc::pid_t) -> Option<u32> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = size_of::<libc::proc_bsdinfo>() as c_int;
    // SAFETY: the buffer holds `size` writable bytes.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    // SAFETY: a full-size answer initialized the whole struct.
    (written == size).then(|| unsafe { info.assume_init() }.pbi_status)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// `Some(true)` when `pid`'s profile denies looking up the Mach service
/// `name`, `Some(false)` when it allows it, `None` when the check failed.
pub(crate) fn lookup_denied(pid: libc::pid_t, name: &CStr) -> Option<bool> {
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
    fill_pid_list(pids, |buffer, bytes| {
        // SAFETY: a null buffer asks only for the size needed; otherwise the
        // buffer holds `bytes` bytes of writable pid_t storage.
        unsafe { libc::proc_listpids(PROC_RUID_ONLY, uid, buffer.cast(), bytes) }
    });
}

/// Fills `pids` through `list`, which behaves like `proc_listpids`: given a
/// null buffer it reports the bytes needed, otherwise it fills the buffer
/// and reports the bytes written.
fn fill_pid_list(
    pids: &mut Vec<libc::pid_t>,
    mut list: impl FnMut(*mut libc::pid_t, c_int) -> c_int,
) {
    let entry = size_of::<libc::pid_t>();
    for _ in 0..LIST_ATTEMPTS {
        pids.clear();
        let Ok(needed) = usize::try_from(list(std::ptr::null_mut(), 0)) else {
            return;
        };
        pids.reserve(needed / entry + LIST_HEADROOM);
        let bytes = c_int::try_from(pids.capacity() * entry).unwrap_or(c_int::MAX);
        let Ok(written) = usize::try_from(list(pids.as_mut_ptr(), bytes)) else {
            return;
        };
        // SAFETY: `list` initialized `written` bytes of whole pid_t values,
        // at most `bytes`, which the capacity covers.
        unsafe { pids.set_len(written / entry) };
        if written < usize::try_from(bytes).unwrap_or(usize::MAX) {
            return;
        }
    }
}

/// Room for processes that start between sizing a listing and filling it.
const LIST_HEADROOM: usize = 64;
/// A full buffer may have cut the listing short, so it is retried with a
/// larger one; past this many tries the sweep works from the partial list
/// and the next sweep picks up the rest.
const LIST_ATTEMPTS: usize = 8;

/// One process, as opposed to whichever process holds its PID.
#[derive(Clone, Copy, Debug)]
struct ProcessIdentity {
    pid: libc::pid_t,
    version: i32,
}

impl ProcessIdentity {
    /// `None` when the process is gone, or when this macOS can't signal one
    /// process rather than a PID.
    fn read(pid: libc::pid_t) -> Option<Self> {
        SIGNAL_ONE_PROCESS.as_ref()?;
        pid_version(pid).map(|version| Self { pid, version })
    }

    /// Sends `signal` to this process; once its PID belongs to another
    /// process, the kernel refuses with ESRCH.
    fn signal(self, signal: c_int) {
        let Some(signal_with_token) = *SIGNAL_ONE_PROCESS else {
            return;
        };
        let mut token = AuditToken([0; 8]);
        token.0[AUDIT_TOKEN_PID] = self.pid as u32;
        token.0[AUDIT_TOKEN_PID_VERSION] = self.version as u32;
        // SAFETY: the token outlives the call, which only reads it.
        unsafe { signal_with_token(&mut token, signal) };
    }
}

/// `audit_token_t`. The kernel resolves a token to a process by the PID and
/// PID version slots alone.
#[repr(C)]
struct AuditToken([u32; 8]);
const AUDIT_TOKEN_PID: usize = 5;
const AUDIT_TOKEN_PID_VERSION: usize = 7;

type SignalWithAuditToken = unsafe extern "C" fn(*mut AuditToken, c_int) -> c_int;

/// `proc_signal_with_audittoken`, looked up at run time so the binary still
/// loads on a macOS release without it. `None` there, and wherever the
/// kernel doesn't report PID versions.
static SIGNAL_ONE_PROCESS: LazyLock<Option<SignalWithAuditToken>> = LazyLock::new(|| {
    // SAFETY: RTLD_DEFAULT and a NUL-terminated name are all dlsym needs.
    let symbol =
        unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"proc_signal_with_audittoken".as_ptr()) };
    // SAFETY: getpid has no preconditions and cannot fail.
    if symbol.is_null() || pid_version(unsafe { libc::getpid() }).is_none() {
        return None;
    }
    // SAFETY: libproc declares it `int proc_signal_with_audittoken(audit_token_t *, int)`.
    Some(unsafe { std::mem::transmute::<*mut std::ffi::c_void, SignalWithAuditToken>(symbol) })
});

/// `PROC_PIDUNIQIDENTIFIERINFO` from XNU's `<sys/proc_info.h>`; the public
/// SDK header leaves it out.
const PROC_PIDUNIQIDENTIFIERINFO: c_int = 17;

/// `struct proc_uniqidentifierinfo` from XNU's `<sys/proc_info.h>`.
#[repr(C)]
#[derive(Default)]
struct UniqueIdentifierInfo {
    executable_uuid: [u8; 16],
    unique_id: u64,
    parent_unique_id: u64,
    pid_version: i32,
    reserved: [u32; 5],
}

const _: () = assert!(size_of::<UniqueIdentifierInfo>() == 56);

/// The version the kernel gave `pid` when its current process took it.
fn pid_version(pid: libc::pid_t) -> Option<i32> {
    let mut info = UniqueIdentifierInfo::default();
    let size = size_of::<UniqueIdentifierInfo>() as c_int;
    // SAFETY: the buffer holds `size` writable bytes.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDUNIQIDENTIFIERINFO,
            0,
            (&raw mut info).cast(),
            size,
        )
    };
    (written == size && info.pid_version != 0).then_some(info.pid_version)
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
pub(crate) fn terminate_sandbox_tree(pid: u32) -> Result<(), crate::SurvivingProcesses> {
    let mark = TRACKED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&pid);
    let Some(mark) = mark else {
        return Ok(());
    };
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    match end_marked_processes(&mut MarkedProcesses { mark: &mark, uid }) {
        0 => Ok(()),
        count => Err(crate::SurvivingProcesses { count }),
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
        assert_eq!(terminate_sandbox_tree(root_pid), Ok(()));

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
        assert_eq!(terminate_sandbox_tree(ended_root_pid), Ok(()));

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

    /// A process table at the per-user process limit, where every slot a
    /// kill frees is taken at once by a child of a marked process that is
    /// still running: a fork storm.
    struct ForkStorm {
        live: Vec<Modelled>,
        limit: usize,
        next_pid: libc::pid_t,
        listings: usize,
    }

    #[derive(Clone, Copy)]
    struct Modelled {
        pid: libc::pid_t,
        marked: bool,
        stopped: bool,
    }

    impl ForkStorm {
        fn new(marked: usize, unmarked: usize) -> Self {
            let live = (0..marked + unmarked)
                .map(|index| Modelled {
                    pid: 100 + libc::pid_t::try_from(index).unwrap(),
                    marked: index < marked,
                    stopped: false,
                })
                .collect::<Vec<_>>();
            Self {
                limit: live.len(),
                next_pid: 100 + libc::pid_t::try_from(live.len()).unwrap(),
                live,
                listings: 0,
            }
        }

        fn find(&self, pid: libc::pid_t) -> Option<&Modelled> {
            self.live.iter().find(|process| process.pid == pid)
        }

        fn marked_left(&self) -> usize {
            self.live.iter().filter(|process| process.marked).count()
        }
    }

    impl ProcessTable for ForkStorm {
        fn list(&mut self, pids: &mut Vec<libc::pid_t>) {
            self.listings += 1;
            pids.clear();
            pids.extend(self.live.iter().map(|process| process.pid));
        }

        fn is_marked(&self, pid: libc::pid_t) -> bool {
            self.find(pid).is_some_and(|process| process.marked)
        }

        fn is_stopped(&self, pid: libc::pid_t) -> bool {
            self.find(pid).is_some_and(|process| process.stopped)
        }

        fn signal_marked(&mut self, pid: libc::pid_t, signal: c_int) {
            let Some(index) = self
                .live
                .iter()
                .position(|process| process.pid == pid && process.marked)
            else {
                return;
            };
            match signal {
                libc::SIGSTOP => self.live[index].stopped = true,
                libc::SIGKILL => {
                    self.live.remove(index);
                    let forker_running = self
                        .live
                        .iter()
                        .any(|process| process.marked && !process.stopped);
                    if self.live.len() < self.limit && forker_running {
                        self.live.push(Modelled {
                            pid: self.next_pid,
                            marked: true,
                            stopped: false,
                        });
                        self.next_pid += 1;
                    }
                }
                _ => {}
            }
        }

        fn pause(&mut self) {}
    }

    #[test]
    fn a_fork_storm_that_refills_every_slot_a_kill_frees_is_still_ended() {
        let mut storm = ForkStorm::new(20, 5);

        let survivors = end_marked_processes(&mut storm);

        assert_eq!(survivors, 0, "the storm outlasted every sweep");
        assert_eq!(storm.marked_left(), 0);
        assert_eq!(storm.live.len(), 5, "a process without the mark was ended");
    }

    #[test]
    fn a_spawn_that_left_nothing_running_is_checked_with_one_listing() {
        let mut quiet = ForkStorm::new(0, 30);

        assert_eq!(end_marked_processes(&mut quiet), 0);
        assert_eq!(quiet.listings, 1);
    }

    /// Answers like `proc_listpids` for a user running `running`.
    fn list_from(running: &[libc::pid_t], buffer: *mut libc::pid_t, bytes: c_int) -> c_int {
        let entry = size_of::<libc::pid_t>();
        if buffer.is_null() {
            return c_int::try_from(size_of_val(running)).unwrap();
        }
        let written = running.len().min(usize::try_from(bytes).unwrap() / entry);
        // SAFETY: the caller's buffer holds `bytes` bytes, room for `written` pids.
        unsafe { std::ptr::copy_nonoverlapping(running.as_ptr(), buffer, written) };
        c_int::try_from(written * entry).unwrap()
    }

    #[test]
    fn a_listing_that_outgrows_a_reused_buffer_grows_it_and_returns_every_process() {
        let running: Vec<libc::pid_t> = (1000..1300).collect();
        let mut pids = Vec::with_capacity(256);
        let mut calls = 0;

        fill_pid_list(&mut pids, |buffer, bytes| {
            calls += 1;
            assert!(
                calls < 32,
                "the listing kept retrying without growing its buffer"
            );
            list_from(&running, buffer, bytes)
        });

        assert_eq!(pids, running);
    }

    #[test]
    fn a_listing_that_fills_every_buffer_stops_retrying_and_keeps_what_it_read() {
        let mut pids = Vec::new();
        let mut calls = 0;

        fill_pid_list(&mut pids, |buffer, bytes| {
            calls += 1;
            assert!(calls < 64, "the listing never stopped retrying");
            // Processes start faster than the buffer grows, so every
            // listing comes back full.
            let fits = if buffer.is_null() {
                calls * 1000
            } else {
                usize::try_from(bytes).unwrap() / size_of::<libc::pid_t>() + 1
            };
            let running: Vec<libc::pid_t> = (2..).take(fits).collect();
            list_from(&running, buffer, bytes)
        });

        assert!(!pids.is_empty(), "a full listing was thrown away");
    }

    #[test]
    fn a_kill_meant_for_a_pids_earlier_process_spares_the_process_holding_it_now() {
        use std::os::unix::process::ExitStatusExt;

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let current = ProcessIdentity::read(pid).expect("a running child has an identity");
        let earlier = ProcessIdentity {
            version: current.version.wrapping_sub(1),
            ..current
        };

        earlier.signal(libc::SIGKILL);
        std::thread::sleep(Duration::from_millis(100));
        let spared = child.try_wait().unwrap().is_none();
        current.signal(libc::SIGKILL);
        let status = child.wait().unwrap();

        assert!(
            spared,
            "a kill meant for the PID's earlier process reached the current one"
        );
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn ending_an_untracked_pid_does_nothing() {
        let mut unsandboxed = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        assert_eq!(terminate_sandbox_tree(unsandboxed.id()), Ok(()));
        let alive = unsandboxed.try_wait().unwrap().is_none();
        let _ = unsandboxed.kill();
        let _ = unsandboxed.wait();
        assert!(alive);
    }
}
