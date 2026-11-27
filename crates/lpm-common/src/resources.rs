//! Effective CPU and memory resource limits for sizing pools and budgets.
//!
//! On Linux containers, host RAM and CPU counts can dramatically overstate what
//! the cgroup allows. Reading cgroup v2 (`memory.max`, `memory.high`), cgroup
//! v1 (`memory.limit_in_bytes`, `hierarchical_memory_limit`), and `/proc/meminfo`
//! bounds extraction buffers, download fan-out, blocking threads, and metadata
//! parse workers to the actual container envelope.

#[cfg(any(target_os = "linux", test))]
use std::borrow::Cow;
#[cfg(any(target_os = "linux", test))]
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const MIN_EXTRACT_MEMORY_BUDGET_BYTES: u64 = 64 * MIB;
const MAX_EXTRACT_MEMORY_BUDGET_BYTES: u64 = GIB;
#[cfg(any(target_os = "linux", test))]
const CGROUP_V1_UNLIMITED_THRESHOLD: u64 = 1_u64 << 60;
#[cfg(any(target_os = "linux", test))]
const MAX_CGROUP_WALK_DEPTH: usize = 64;
#[cfg(any(target_os = "linux", test))]
const CGROUP_SCALAR_READ_CAP_BYTES: u64 = 128;
#[cfg(any(target_os = "linux", test))]
const CGROUP_STAT_READ_CAP_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const PROC_READ_CAP_BYTES: u64 = 256 * 1024;

/// Effective logical CPU count available to this process.
///
/// Rust's `std::thread::available_parallelism` already honors Linux CPU
/// affinity and cgroup v1/v2 CPU quotas; this caches the result once per
/// process so hot call sites avoid repeated `/proc` and `/sys` probes.
pub fn effective_cpu_count() -> usize {
    static CPUS: OnceLock<usize> = OnceLock::new();
    *CPUS
        .get_or_init(|| std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get))
}

/// Effective memory limit available to this process in bytes, if detectable.
///
/// On Linux this takes the tightest finite bound across cgroup v2 ancestors,
/// cgroup v1 memory hierarchy limits, and `/proc/meminfo` `MemTotal`. On macOS
/// and Windows it reports total physical memory. Cached once per process.
pub fn effective_memory_limit_bytes() -> Option<u64> {
    static LIMIT: OnceLock<Option<u64>> = OnceLock::new();
    *LIMIT.get_or_init(detect_effective_memory_limit_bytes)
}

/// Global byte budget for concurrent buffered gzip extractions.
pub fn extract_memory_budget_bytes(memory_limit: Option<u64>) -> u64 {
    match memory_limit {
        Some(bytes) if bytes > 0 => (bytes / 4).clamp(
            MIN_EXTRACT_MEMORY_BUDGET_BYTES,
            MAX_EXTRACT_MEMORY_BUDGET_BYTES,
        ),
        _ => MAX_EXTRACT_MEMORY_BUDGET_BYTES,
    }
}

/// Concurrency ceiling for simultaneous large registry packument parses.
pub fn large_metadata_parse_permits(cpus: usize, memory_limit: Option<u64>) -> usize {
    if memory_limit.is_some_and(|bytes| bytes <= 768 * MIB) {
        return 1;
    }
    (cpus / 4).clamp(1, 4)
}

/// Default bounded fetch/extract concurrency permits for the current OS.
pub fn default_fetch_extract_permits(cpus: usize, memory_limit: Option<u64>) -> usize {
    default_fetch_extract_permits_for_os(cpus, memory_limit, cfg!(target_os = "macos"))
}

/// Default bounded fetch/extract concurrency permits parameterized by OS so
/// cross-platform policies remain directly testable.
pub fn default_fetch_extract_permits_for_os(
    cpus: usize,
    memory_limit: Option<u64>,
    is_macos: bool,
) -> usize {
    // APFS metadata serialization caps macOS extract scaling at 4 writers;
    // Linux and Windows scale up to 8 when CPU and RAM allow.
    let base = if is_macos {
        cpus.clamp(1, 4)
    } else {
        cpus.clamp(1, 8)
    };
    if memory_limit.is_some_and(|bytes| bytes <= GIB) {
        base.min(2)
    } else {
        base
    }
}

/// Default concurrent tarball download ceiling.
pub fn default_max_concurrent_downloads(memory_limit: Option<u64>) -> usize {
    match memory_limit {
        Some(bytes) if bytes <= 512 * MIB => 8,
        Some(bytes) if bytes <= GIB => 12,
        _ => 24,
    }
}

/// Default Tokio `max_blocking_threads` cap when `LPM_MAX_BLOCKING_THREADS` is unset.
pub fn default_max_blocking_threads(cpus: usize, memory_limit: Option<u64>) -> usize {
    let base = cpus.saturating_mul(2).saturating_add(4).clamp(6, 32);
    if memory_limit.is_some_and(|bytes| bytes <= GIB) {
        base.min(12)
    } else {
        base
    }
}

/// Process-wide cap on helper threads spawned by parallel tree-metadata walks.
pub fn default_tree_walk_helper_cap(cpus: usize) -> usize {
    cpus.saturating_sub(1).min(3)
}

fn detect_effective_memory_limit_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let cgroup =
            crate::read_text_file_capped(Path::new("/proc/self/cgroup"), PROC_READ_CAP_BYTES)
                .unwrap_or_default();
        let mountinfo =
            crate::read_text_file_capped(Path::new("/proc/self/mountinfo"), PROC_READ_CAP_BYTES)
                .unwrap_or_default();
        let meminfo = crate::read_text_file_capped(Path::new("/proc/meminfo"), PROC_READ_CAP_BYTES)
            .unwrap_or_default();
        detect_linux_memory_limit_in(Path::new("/"), &cgroup, &mountinfo, &meminfo)
    }
    #[cfg(target_os = "macos")]
    {
        detect_macos_memory_bytes()
    }
    #[cfg(windows)]
    {
        detect_windows_memory_bytes()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn detect_macos_memory_bytes() -> Option<u64> {
    let mut memsize: u64 = 0;
    let mut size = std::mem::size_of::<u64>();
    let name = c"hw.memsize";
    // SAFETY: `name` is NUL-terminated and `memsize`/`size` point to valid
    // writable storage matching `size_of::<u64>()`.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut memsize).cast::<libc::c_void>(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && size == std::mem::size_of::<u64>() && memsize > 0).then_some(memsize)
}

#[cfg(windows)]
fn detect_windows_memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    status.dwLength = u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>()).ok()?;
    // SAFETY: `status` is properly initialized with `dwLength` set to its struct size.
    let ok = unsafe { GlobalMemoryStatusEx(&raw mut status) };
    (ok != 0 && status.ullTotalPhys > 0).then_some(status.ullTotalPhys)
}

#[cfg(any(target_os = "linux", test))]
fn unescape_mountinfo_field(raw: &str) -> Cow<'_, str> {
    if !raw.contains('\\') {
        return Cow::Borrowed(raw);
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4].iter().all(|b| matches!(b, b'0'..=b'7'))
        {
            let val =
                ((bytes[i + 1] - b'0') << 6) | ((bytes[i + 2] - b'0') << 3) | (bytes[i + 3] - b'0');
            out.push(val);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_meminfo_total_bytes(content: &str) -> Option<u64> {
    for line in content.lines() {
        let Some(rest) = line.strip_prefix("MemTotal:") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let value = parts.next()?.parse::<u64>().ok()?;
        let unit = parts.next().unwrap_or("kB");
        let bytes = match unit {
            "kB" | "KiB" => value.checked_mul(1024)?,
            "mB" | "MiB" => value.checked_mul(MIB)?,
            "B" => value,
            _ => value.checked_mul(1024)?,
        };
        return (bytes > 0).then_some(bytes);
    }
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_v2_limit_bytes(content: &str) -> Option<u64> {
    let trimmed = content.trim();
    if trimmed.is_empty() || trimmed == "max" {
        return None;
    }
    let bytes = trimmed.parse::<u64>().ok()?;
    (bytes > 0).then_some(bytes)
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_v1_limit_bytes(content: &str) -> Option<u64> {
    let bytes = content.trim().parse::<u64>().ok()?;
    (bytes > 0 && bytes < CGROUP_V1_UNLIMITED_THRESHOLD).then_some(bytes)
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_v1_hierarchical_limit_bytes(stat_content: &str) -> Option<u64> {
    for line in stat_content.lines() {
        let Some(rest) = line.strip_prefix("hierarchical_memory_limit") else {
            continue;
        };
        let value = rest.split_whitespace().next()?;
        return parse_cgroup_v1_limit_bytes(value);
    }
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_cgroup_paths(content: &str) -> (Option<&str>, Option<&str>) {
    let mut v2_path = None;
    let mut v1_memory_path = None;
    for line in content.lines() {
        let mut parts = line.splitn(3, ':');
        let Some(hierarchy_id) = parts.next() else {
            continue;
        };
        let Some(controllers) = parts.next() else {
            continue;
        };
        let Some(path) = parts.next() else {
            continue;
        };
        if hierarchy_id == "0" && controllers.is_empty() && v2_path.is_none() {
            v2_path = Some(path.trim());
        } else if controllers
            .split(',')
            .any(|controller| controller == "memory")
            && v1_memory_path.is_none()
        {
            v1_memory_path = Some(path.trim());
        }
    }
    (v2_path, v1_memory_path)
}

#[cfg(any(target_os = "linux", test))]
struct CgroupMounts {
    v2: Option<(String, String)>,
    v1_memory: Option<(String, String)>,
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_mounts(mountinfo: &str) -> CgroupMounts {
    let mut mounts = CgroupMounts {
        v2: None,
        v1_memory: None,
    };
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields: Vec<&str> = left.split_whitespace().collect();
        let right_fields: Vec<&str> = right.split_whitespace().collect();
        if left_fields.len() < 5 || right_fields.len() < 3 {
            continue;
        }
        let mount_root = unescape_mountinfo_field(left_fields[3]).into_owned();
        let mount_point = unescape_mountinfo_field(left_fields[4]).into_owned();
        let fs_type = right_fields[0];
        let super_opts = right_fields[2];
        if fs_type == "cgroup2" && mounts.v2.is_none() {
            mounts.v2 = Some((mount_root, mount_point));
        } else if fs_type == "cgroup"
            && mounts.v1_memory.is_none()
            && super_opts.split(',').any(|opt| opt == "memory")
        {
            mounts.v1_memory = Some((mount_root, mount_point));
        }
    }
    mounts
}

#[cfg(any(target_os = "linux", test))]
fn join_rooted_path(fs_root: &Path, abs_path: &str) -> PathBuf {
    let rel = abs_path.trim_start_matches('/');
    if rel.is_empty() {
        fs_root.to_path_buf()
    } else {
        fs_root.join(rel)
    }
}

#[cfg(any(target_os = "linux", test))]
fn resolve_cgroup_dir(
    fs_root: &Path,
    mount_root: &str,
    mount_point: &str,
    cgroup_path: &str,
) -> (PathBuf, PathBuf) {
    let mount_dir = join_rooted_path(fs_root, mount_point);
    let norm_root = mount_root.trim_end_matches('/');
    let norm_cgroup = cgroup_path.trim_end_matches('/');
    let relative = if norm_root.is_empty() {
        norm_cgroup.trim_start_matches('/')
    } else if norm_cgroup == norm_root {
        ""
    } else if let Some(rest) = norm_cgroup.strip_prefix(norm_root) {
        if let Some(sub) = rest.strip_prefix('/') {
            sub
        } else {
            norm_cgroup.trim_start_matches('/')
        }
    } else {
        // Inside a cgroup namespace `/proc/self/cgroup` reports `/` relative to
        // the namespace root even though `mountinfo` shows the host mount_root.
        norm_cgroup.trim_start_matches('/')
    };
    let mut target = mount_dir.clone();
    for segment in relative.split('/').filter(|s| !s.is_empty()) {
        if segment == "." || segment == ".." {
            return (mount_dir.clone(), mount_dir);
        }
        target.push(segment);
    }
    (mount_dir, target)
}

#[cfg(any(target_os = "linux", test))]
fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

#[cfg(any(target_os = "linux", test))]
fn walk_cgroup_v2_memory_limit(mount_dir: &Path, cgroup_dir: &Path) -> Option<u64> {
    let mut limit = None;
    let mut current = cgroup_dir.to_path_buf();
    for _ in 0..MAX_CGROUP_WALK_DEPTH {
        if !current.starts_with(mount_dir) {
            break;
        }
        for filename in ["memory.max", "memory.high"] {
            if let Ok(content) =
                crate::read_text_file_capped(&current.join(filename), CGROUP_SCALAR_READ_CAP_BYTES)
            {
                limit = min_opt(limit, parse_cgroup_v2_limit_bytes(&content));
            }
        }
        if current == mount_dir || !current.pop() {
            break;
        }
    }
    limit
}

#[cfg(any(target_os = "linux", test))]
fn walk_cgroup_v1_memory_limit(mount_dir: &Path, cgroup_dir: &Path) -> Option<u64> {
    let mut limit = None;
    if let Ok(stat_content) =
        crate::read_text_file_capped(&cgroup_dir.join("memory.stat"), CGROUP_STAT_READ_CAP_BYTES)
    {
        limit = min_opt(
            limit,
            parse_cgroup_v1_hierarchical_limit_bytes(&stat_content),
        );
    }
    let mut current = cgroup_dir.to_path_buf();
    for _ in 0..MAX_CGROUP_WALK_DEPTH {
        if !current.starts_with(mount_dir) {
            break;
        }
        if let Ok(content) = crate::read_text_file_capped(
            &current.join("memory.limit_in_bytes"),
            CGROUP_SCALAR_READ_CAP_BYTES,
        ) {
            limit = min_opt(limit, parse_cgroup_v1_limit_bytes(&content));
        }
        if current == mount_dir || !current.pop() {
            break;
        }
    }
    limit
}

#[cfg(any(target_os = "linux", test))]
fn detect_linux_memory_limit_in(
    fs_root: &Path,
    cgroup_content: &str,
    mountinfo: &str,
    meminfo: &str,
) -> Option<u64> {
    let mem_total = parse_proc_meminfo_total_bytes(meminfo);
    let (v2_path, v1_memory_path) = parse_proc_cgroup_paths(cgroup_content);
    let mounts = parse_cgroup_mounts(mountinfo);
    let mut limit = mem_total;
    if let (Some(cgroup_path), Some((mount_root, mount_point))) = (v2_path, mounts.v2.as_ref()) {
        let (mount_dir, cgroup_dir) =
            resolve_cgroup_dir(fs_root, mount_root, mount_point, cgroup_path);
        limit = min_opt(limit, walk_cgroup_v2_memory_limit(&mount_dir, &cgroup_dir));
    }
    if let (Some(cgroup_path), Some((mount_root, mount_point))) =
        (v1_memory_path, mounts.v1_memory.as_ref())
    {
        let (mount_dir, cgroup_dir) =
            resolve_cgroup_dir(fs_root, mount_root, mount_point, cgroup_path);
        limit = min_opt(limit, walk_cgroup_v1_memory_limit(&mount_dir, &cgroup_dir));
    }
    limit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_v2_hierarchy_walk_picks_tightest_ancestor_limit() {
        let root = tempfile::tempdir().unwrap();
        let cg_root = root.path().join("sys/fs/cgroup");
        let parent = cg_root.join("kubepods.slice");
        let leaf = parent.join("pod-123");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(cg_root.join("memory.max"), "max\n").unwrap();
        std::fs::write(parent.join("memory.max"), format!("{}\n", 512 * MIB)).unwrap();
        std::fs::write(leaf.join("memory.max"), "max\n").unwrap();
        std::fs::write(leaf.join("memory.high"), format!("{}\n", 384 * MIB)).unwrap();

        let cgroup = "0::/kubepods.slice/pod-123\n";
        let mountinfo = "28 1 0:25 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw\n";
        let meminfo = "MemTotal:       16384000 kB\n";

        let detected = detect_linux_memory_limit_in(root.path(), cgroup, mountinfo, meminfo);
        assert_eq!(detected, Some(384 * MIB));
    }

    #[test]
    fn cgroup_v1_ignores_unlimited_sentinel_and_uses_hierarchical_limit() {
        let root = tempfile::tempdir().unwrap();
        let cg_root = root.path().join("sys/fs/cgroup/memory");
        let leaf = cg_root.join("docker/container-1");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(
            cg_root.join("memory.limit_in_bytes"),
            "9223372036854771712\n",
        )
        .unwrap();
        std::fs::write(leaf.join("memory.limit_in_bytes"), "9223372036854771712\n").unwrap();
        std::fs::write(
            leaf.join("memory.stat"),
            format!(
                "cache 1024\nhierarchical_memory_limit {}\nrss 4096\n",
                768 * MIB
            ),
        )
        .unwrap();

        let cgroup = "4:memory:/docker/container-1\n";
        let mountinfo = "33 25 0:29 / /sys/fs/cgroup/memory rw,nosuid - cgroup cgroup rw,memory\n";
        let meminfo = "MemTotal:       32768000 kB\n";

        let detected = detect_linux_memory_limit_in(root.path(), cgroup, mountinfo, meminfo);
        assert_eq!(detected, Some(768 * MIB));
    }

    #[test]
    fn cgroup_limit_higher_than_meminfo_clamps_to_memtotal() {
        let root = tempfile::tempdir().unwrap();
        let cg_root = root.path().join("sys/fs/cgroup");
        std::fs::create_dir_all(&cg_root).unwrap();
        std::fs::write(cg_root.join("memory.max"), format!("{}\n", 64 * GIB)).unwrap();

        let cgroup = "0::/\n";
        let mountinfo = "28 1 0:25 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";
        let meminfo = "MemTotal:       1048576 kB\n";

        let detected = detect_linux_memory_limit_in(root.path(), cgroup, mountinfo, meminfo);
        assert_eq!(detected, Some(GIB));
    }

    #[test]
    fn cgroup_namespace_mount_root_resolves_namespaced_container_path() {
        let root = tempfile::tempdir().unwrap();
        let cg_root = root.path().join("sys/fs/cgroup");
        let sub = cg_root.join("app");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(cg_root.join("memory.max"), format!("{}\n", 512 * MIB)).unwrap();
        std::fs::write(sub.join("memory.max"), "max\n").unwrap();

        let cgroup = "0::/app\n";
        let mountinfo = "28 1 0:25 /kubepods/pod-1 /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n";
        let meminfo = "MemTotal:       16384000 kB\n";

        let detected = detect_linux_memory_limit_in(root.path(), cgroup, mountinfo, meminfo);
        assert_eq!(detected, Some(512 * MIB));
    }

    #[test]
    fn resource_policies_scale_down_for_small_containers_and_preserve_large_host_defaults() {
        // 1 vCPU, 512 MiB container
        assert_eq!(extract_memory_budget_bytes(Some(512 * MIB)), 128 * MIB);
        assert_eq!(extract_memory_budget_bytes(Some(128 * MIB)), 64 * MIB);
        assert_eq!(large_metadata_parse_permits(1, Some(512 * MIB)), 1);
        assert_eq!(large_metadata_parse_permits(8, Some(512 * MIB)), 1);
        assert_eq!(
            default_fetch_extract_permits_for_os(1, Some(512 * MIB), false),
            1
        );
        assert_eq!(
            default_fetch_extract_permits_for_os(4, Some(512 * MIB), false),
            2
        );
        assert_eq!(default_max_concurrent_downloads(Some(512 * MIB)), 8);
        assert_eq!(default_max_concurrent_downloads(Some(GIB)), 12);
        assert_eq!(default_max_blocking_threads(1, Some(512 * MIB)), 6);
        assert_eq!(default_max_blocking_threads(8, Some(GIB)), 12);
        assert_eq!(default_tree_walk_helper_cap(1), 0);

        // Large host (16 vCPU, 32 GiB)
        assert_eq!(extract_memory_budget_bytes(Some(32 * GIB)), GIB);
        assert_eq!(extract_memory_budget_bytes(None), GIB);
        assert_eq!(large_metadata_parse_permits(16, Some(32 * GIB)), 4);
        assert_eq!(
            default_fetch_extract_permits_for_os(16, Some(32 * GIB), true),
            4
        );
        assert_eq!(
            default_fetch_extract_permits_for_os(16, Some(32 * GIB), false),
            8
        );
        assert_eq!(default_max_concurrent_downloads(Some(32 * GIB)), 24);
        assert_eq!(default_max_blocking_threads(16, Some(32 * GIB)), 32);
        assert_eq!(default_tree_walk_helper_cap(16), 3);
    }

    #[test]
    fn mountinfo_octal_escapes_decode_spaces_and_backslashes() {
        assert_eq!(
            unescape_mountinfo_field("/mnt/my\\040cgroup\\134v2"),
            "/mnt/my cgroup\\v2"
        );
    }
}
