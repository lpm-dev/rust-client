//! Whether a process still runs as an AppContainer identity.
//!
//! An identity keeps the trees it was granted between runs, and a run's
//! read denial on a secret inside one holds only while the run lasts. A
//! process of the identity that outlasted its run could read the secret
//! once the denial came off, so a run doesn't start, and nothing takes a
//! stopped run's denials off, while one is found.
//!
//! This is the check for when no Job is left to ask. A run's Job counts
//! its processes for certain; a listing of the machine's processes shows
//! only those this user can open, and a process can take that access to
//! itself away. Each process of an identity belongs to a Job, and a Job
//! is ended before this check runs: by whoever takes its run's entries
//! back, or by Windows once nothing holds it. What the check guards
//! against is a process still on its way out.

use super::*;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_APPCONTAINER_INFORMATION, TOKEN_QUERY, TokenAppContainerSid,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::OpenProcessToken;

/// How long a run or a cleanup waits for the identity's last process. One
/// that its Job was told to end is gone within moments.
pub(super) const LAST_PROCESS_WAIT: Duration = Duration::from_secs(5);

/// How often a listing in which a process ended while it was being read
/// is taken again before it is believed.
const LISTINGS_TAKEN_AGAIN: u32 = 3;

/// Returns once no process is found running as `sid`, and fails naming
/// those that still do after `limit`. The caller holds the identity, so
/// no run of it starts one meanwhile.
pub(super) fn wait_until_none_runs_as(sid: PSID, limit: Duration) -> Result<(), AppContainerError> {
    let started = Instant::now();
    let mut taken_again = 0;
    loop {
        let Listing { running, one_ended } = running_as(sid)?;
        let Some((_, first)) = running.first() else {
            // A process that ended between being listed and being looked
            // at may have started one the listing doesn't hold.
            if one_ended && taken_again < LISTINGS_TAKEN_AGAIN {
                taken_again += 1;
                continue;
            }
            return Ok(());
        };
        let in_use = || AppContainerError::IdentityInUse {
            processes: ProcessIds(running.iter().map(|(id, _)| *id).collect()),
        };
        let left = limit.saturating_sub(started.elapsed());
        // Processes that keep replacing each other would otherwise each
        // be found ended, and the next listed, without end.
        if left.is_zero() {
            return Err(in_use());
        }
        let wait_ms = u32::try_from(left.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: the process handle is open for the wait.
        match unsafe { WaitForSingleObject(first.as_raw(), wait_ms) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Err(in_use()),
            wait_result => return Err(AppContainerError::Wait { wait_result }),
        }
    }
}

/// The ids of processes, as an error message lists them.
#[derive(Debug)]
pub struct ProcessIds(Vec<u32>);

impl std::fmt::Display for ProcessIds {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (position, id) in self.0.iter().enumerate() {
            if position > 0 {
                formatter.write_str(", ")?;
            }
            write!(formatter, "{id}")?;
        }
        Ok(())
    }
}

/// What one listing of the machine's processes found.
struct Listing {
    /// The running processes whose token carries the identity.
    running: Vec<(u32, HandleGuard)>,
    /// Whether a listed process had ended by the time it was looked at.
    one_ended: bool,
}

/// What a listed process turned out to be.
enum Listed {
    RunsAs(HandleGuard),
    /// Another identity's, or one this user can't open or read the token
    /// of.
    Other,
    Ended,
}

/// Every running process whose token carries `sid` as its AppContainer,
/// among those this user can open and read the token of.
fn running_as(sid: PSID) -> Result<Listing, AppContainerError> {
    // SAFETY: the call takes no pointers.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        let last_error = unsafe { GetLastError() };
        return Err(AppContainerError::ListProcesses { last_error });
    }
    let snapshot = HandleGuard(snapshot);
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut listing = Listing {
        running: Vec::new(),
        one_ended: false,
    };
    // SAFETY: `entry` is a stack-local whose size field is set.
    let mut listed = unsafe { Process32FirstW(snapshot.as_raw(), &mut entry) } != 0;
    while listed {
        match look_at(entry.th32ProcessID, sid) {
            Listed::RunsAs(handle) => listing.running.push((entry.th32ProcessID, handle)),
            Listed::Other => {}
            Listed::Ended => listing.one_ended = true,
        }
        // SAFETY: as for the first entry.
        listed = unsafe { Process32NextW(snapshot.as_raw(), &mut entry) } != 0;
    }
    // A listing that stopped for any other reason may have left processes
    // out.
    match unsafe { GetLastError() } {
        ERROR_NO_MORE_FILES => Ok(listing),
        last_error => Err(AppContainerError::ListProcesses { last_error }),
    }
}

fn look_at(id: u32, sid: PSID) -> Listed {
    // The idle process is listed under an id no process can be opened by.
    if id == 0 {
        return Listed::Other;
    }
    // SAFETY: OpenProcess takes no pointers.
    let process = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            id,
        )
    };
    if process.is_null() {
        // An id no process has is refused as an invalid parameter.
        return if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            Listed::Ended
        } else {
            Listed::Other
        };
    }
    let process = HandleGuard(process);
    // SAFETY: the handle is open, and a zero timeout only reads its state.
    if unsafe { WaitForSingleObject(process.as_raw(), 0) } == WAIT_OBJECT_0 {
        return Listed::Ended;
    }
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the process handle is open and `token` is a valid out param.
    if unsafe { OpenProcessToken(process.as_raw(), TOKEN_QUERY, &mut token) } == 0 {
        return Listed::Other;
    }
    let token = HandleGuard(token);
    // Room for the structure and the largest SID it can point at, aligned
    // for the pointer it starts with.
    let mut held = [0u64; 16];
    let mut needed = 0u32;
    // SAFETY: `held` is writable for the length passed.
    let read = unsafe {
        GetTokenInformation(
            token.as_raw(),
            TokenAppContainerSid,
            held.as_mut_ptr().cast(),
            std::mem::size_of_val(&held) as u32,
            &mut needed,
        )
    };
    if read == 0 {
        return Listed::Other;
    }
    // SAFETY: the call filled the buffer with this structure, whose SID
    // pointer is null for a process outside any AppContainer and
    // otherwise points into the buffer.
    let found =
        unsafe { (*held.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer };
    // SAFETY: both SIDs are valid for the comparison.
    if !found.is_null() && unsafe { EqualSid(found, sid) } != 0 {
        Listed::RunsAs(process)
    } else {
        Listed::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_nothing_runs_as_is_found_unused_among_the_running_processes() {
        let name = format!("lpm-test-unused-{}", std::process::id());
        let sid = derive_appcontainer_sid(&name).expect("derive a SID");

        wait_until_none_runs_as(sid.0, Duration::ZERO).expect("no process runs as the identity");
    }

    #[test]
    fn process_ids_are_listed_apart() {
        assert_eq!(ProcessIds(vec![1234]).to_string(), "1234");
        assert_eq!(ProcessIds(vec![1234, 5678]).to_string(), "1234, 5678");
    }

    #[test]
    fn a_process_outside_any_app_container_runs_as_no_identity() {
        let name = format!("lpm-test-outside-{}", std::process::id());
        let sid = derive_appcontainer_sid(&name).expect("derive a SID");

        assert!(matches!(look_at(std::process::id(), sid.0), Listed::Other));
    }
}
