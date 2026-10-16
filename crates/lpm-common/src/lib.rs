//! Core types shared across LPM workspace crates.
//!
//! Hosts the canonical [`PackageName`] parser, [`Integrity`] (SRI) helpers,
//! [`LpmError`] (the unified error type returned by the CLI surface), and the
//! [`LpmRoot`] / locking primitives every install pass touches. I/O helpers in
//! this crate stay small and dependency-light so it remains the workspace floor.

pub mod atomic_write;
pub mod bounded_read;
pub mod browser;
pub mod child_env;
pub mod color;
pub mod command_name;
pub mod error;
pub mod global_fs;
pub mod integrity;
pub mod known_projects;
pub mod local_target;
pub mod lpm_json;
#[cfg(target_os = "macos")]
pub mod macos_acl;
pub mod npmrc;
pub mod package_instance;
pub mod package_name;
#[cfg(unix)]
pub mod path_trust;
pub mod paths;
pub mod peer;
pub mod platform;
pub mod process_output;
pub mod project_glob;
pub mod project_state;
pub mod provenance;
pub mod symlink;
pub mod terminal;
// The 64-bit system call's groups are 32-bit; 32-bit systems have two calls.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod thread_identity;
mod utf8_bom;

#[cfg(unix)]
pub use atomic_write::replace_symlink_atomic;
pub use atomic_write::{
    AtomicWriteOptions, write_file_atomic, write_file_atomic_in_dir_with,
    write_file_atomic_in_dir_with_options, write_file_atomic_with, write_file_atomic_with_options,
};
#[cfg(unix)]
pub use bounded_read::current_uid;
#[cfg(unix)]
pub use bounded_read::permissions_are_owner_only;
pub use bounded_read::{
    BoundedReadError, CONFIG_FILE_SIZE_CAP_BYTES, NPMRC_FILE_SIZE_CAP_BYTES,
    TLS_MATERIAL_AGGREGATE_CAP_BYTES, TLS_MATERIAL_FILE_SIZE_CAP_BYTES, link_count, open_nofollow,
    read_file_capped, read_file_capped_from_open_file, read_file_capped_unlinked,
    read_regular_file_capped_with_metadata, read_stream_capped, read_text_file_capped,
    read_text_file_capped_from_open_file, read_text_file_capped_from_open_file_with_known_size,
    read_text_file_capped_nofollow, read_text_file_capped_with_metadata,
    read_text_regular_file_capped_with_metadata,
};
pub use command_name::{PortableCommandNameError, validate_portable_command_name};
pub use error::{
    ArtifactUnavailableErrorContext, ArtifactUnavailableKind, LpmError, ResolutionErrorContext,
    ResolutionFailureKind, TyposquatErrorContext, TyposquatErrorFinding,
};
pub use global_fs::{GlobalInstallDirectory, GlobalInstallsDirectory, GlobalStateDirectories};
pub use integrity::Integrity;
pub use local_target::{LocalScheme, LocalTarget};
pub use lpm_json::{LpmJsonFileState, LpmJsonMutation, LpmJsonTransactionError, update_lpm_json};
pub use npmrc::{
    NPMRC_DIAGNOSTIC_LIMIT, NPMRC_INTERPOLATED_VALUE_CAP_BYTES, NpmrcIniSetting, NpmrcIniValue,
    NpmrcInterpolationError, decode_npmrc_ini_fragment, interpolate_npmrc_env, npm_config_path,
    npm_config_path_with_home, npm_global_config_path, npm_global_config_path_from_user_config,
    npm_user_config_path, npmrc_can_influence_config_discovery, parse_npmrc_ini_settings,
    push_npmrc_diagnostic,
};
pub use package_instance::{PackageInstanceId, ResolutionNodeId, artifact_binding_id};
pub use package_name::PackageName;
#[cfg(windows)]
pub use paths::absolute_extended_path;
pub use paths::{
    ExclusiveLockHandle, FsKind, GLOBAL_INSTALL_PATH_BUDGET, INSTALL_READY_MARKER, LpmRoot,
    ProjectLockDirectory, ProjectLockKind, SharedLockHandle, SingleFileExclusiveLockHandle,
    SingleFileSharedLockHandle, acquire_exclusive_lock, acquire_single_file_exclusive_lock,
    acquire_single_file_exclusive_lock_from_file,
    acquire_single_file_exclusive_lock_from_file_within, acquire_single_file_shared_lock,
    acquire_single_file_shared_lock_from_file, as_extended_path, check_install_path_budget,
    is_local_fs, open_lock_file_nofollow, parent_install_lock_environment, project_install_lock,
    project_publish_lock, try_acquire_capability_exclusive_lock, try_acquire_exclusive_lock,
    try_acquire_single_file_exclusive_lock_from_file, try_with_exclusive_lock,
    with_capability_exclusive_lock, with_exclusive_lock, with_exclusive_lock_async,
    with_project_exclusive_lock, with_project_exclusive_lock_async, with_project_shared_lock,
    with_project_shared_lock_async, with_shared_lock, with_shared_lock_async,
};
pub use peer::PeerEdge;
pub use project_glob::{rooted_project_glob, validate_project_glob};
pub use project_state::{
    PROJECT_STATE_DIR, ensure_project_state_dir, ensure_project_state_dir_in,
    keep_existing_project_state_ignored, keep_state_dir_ignored_or_warn, project_state_dir,
};
pub use provenance::{ProvenanceSnapshot, ProvenanceStatus, npm_package_purl};
pub use symlink::{
    create_dir_symlink_or_junction, create_symlink, is_symlink_or_junction, remove_path_entry,
    remove_symlink_or_junction_entry,
};
pub use terminal::{sanitize_for_terminal, sanitize_terminal_inline, sanitize_terminal_multiline};
pub use utf8_bom::{strip_utf8_bom_bytes, strip_utf8_bom_str};

/// The LPM scope prefix. All LPM packages live under this scope.
pub const LPM_SCOPE: &str = "@lpm.dev";

/// Default LPM registry URL.
pub const DEFAULT_REGISTRY_URL: &str = "https://lpm.dev";

/// Default npm upstream registry URL.
pub const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";

/// Maximum bytes retained from one task output stream before a truncation marker.
pub const TASK_OUTPUT_CAPTURE_BYTES: usize = 10 * 1024 * 1024;

/// Check whether a skill name is safe for use in filesystem paths.
///
/// Rejects empty strings, names longer than 128 chars, path separators,
/// parent-directory traversal, null bytes, and any non-ASCII-alphanumeric
/// character other than `-`, `_`, and `.`.
pub fn is_safe_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !name.contains('\0')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Sanitise a package short-name for use as a filesystem directory name.
///
/// Replaces path separators and null bytes with `-`. This is used when the
/// full `is_safe_skill_name` check is too strict (package names may contain
/// `.` which is allowed, but we still need to strip traversal characters).
pub fn sanitize_path_component(name: &str) -> String {
    name.replace("..", "_").replace(['/', '\\', '\0'], "-")
}

/// Default cap on small JSON/TOML state files that lpm reads at command
/// start (project-local `.lpm/build-state.json`, `.lpm/overrides-state.json`,
/// `.lpm/patch-state.json`, global `~/.lpm/known-projects.json`, global
/// manifest, L4 verdict cache, etc.).
///
/// Real-world state files are kilobytes; a 16 MB ceiling leaves several
/// orders of magnitude of headroom while preventing a malicious repo or
/// same-user state writer from forcing `read_to_string` + full serde
/// parse on a multi-GB file at every command start.
pub const STATE_FILE_SIZE_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// Read a small state file while enforcing a hard byte cap. Returns
/// `Ok(None)` when the file is missing OR larger
/// than `cap`; returns `Ok(Some(bytes))` for files within budget;
/// returns `Err` for ordinary open, metadata, or read failures.
///
/// Caller treats the `Ok(None)` cap-overflow case the same as "missing
/// state" — these readers all fall back to "no prior state" when the
/// file fails to parse, so the cap is a stricter version of the
/// existing recovery posture. A `tracing::warn` fires on the overflow
/// arm so an operator can see the cap kicked in.
pub fn read_capped_state_file(
    path: &std::path::Path,
    cap: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    match read_file_capped(path, cap) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(BoundedReadError::NotFound { .. }) => Ok(None),
        Err(BoundedReadError::TooLarge { .. }) => {
            tracing::warn!(
                path = %path.display(),
                cap = cap,
                "state file exceeds size cap — treating as missing"
            );
            Ok(None)
        }
        Err(BoundedReadError::Io { source, .. }) => Err(source),
        Err(BoundedReadError::InvalidUtf8 { .. }) => {
            unreachable!("byte reads do not validate UTF-8")
        }
    }
}

/// Resolve the LPM registry URL with scheme + host gating applied to
/// any value read from the `LPM_REGISTRY_URL` environment variable.
///
/// Returns [`DEFAULT_REGISTRY_URL`] when the env var is unset, empty,
/// or rejected by [`lpm_registry_url_is_accepted`]. An accepted
/// override is logged at `warn` level so an operator scanning logs
/// has visibility — the resolved host is the destination for
/// LPM bearer tokens, OIDC exchanges, and vault payloads, so an
/// unexpected redirect is the highest-severity contamination class.
///
/// The gating contract is the same as
/// `release_lookup::resolve_release_url` (H9): HTTPS is accepted
/// for any host (legitimate private mirror / on-prem appliance),
/// HTTP is accepted only when the host is a loopback address
/// (workflow tests against a localhost mock). Plain `http://attacker`
/// values are refused and the lookup falls back to the default with
/// a separate `warn` so the rejection is auditable.
pub fn resolve_lpm_registry_url() -> String {
    let raw = match std::env::var("LPM_REGISTRY_URL")
        .ok()
        .filter(|s| !s.is_empty())
    {
        Some(v) => v,
        None => return DEFAULT_REGISTRY_URL.to_string(),
    };
    let safe_url = safe_url_origin(&raw);
    if lpm_registry_url_is_accepted(&raw) {
        tracing::warn!(
            registry_url = %safe_url,
            "LPM_REGISTRY_URL override honoured — LPM bearer tokens, OIDC tokens, and vault payloads will be sent to this host; confirm it is expected",
        );
        return raw;
    }
    tracing::warn!(
        registry_url = %safe_url,
        default_url = DEFAULT_REGISTRY_URL,
        "rejecting LPM_REGISTRY_URL override: only https:// (any host) or http:// loopback URLs are accepted; falling back to default",
    );
    DEFAULT_REGISTRY_URL.to_string()
}

/// Validate a candidate `LPM_REGISTRY_URL` override value against
/// the H16/H9 scheme-and-host contract.
///
/// Implements a minimal scheme + host parse rather than pulling in
/// the `url` crate so `lpm-common` stays dep-light. The shape we
/// care about is just `scheme://host[:port][/...]` — full RFC 3986
/// validation runs later inside reqwest at request time.
pub fn lpm_registry_url_is_accepted(url: &str) -> bool {
    let (scheme, rest) = match url.split_once("://") {
        Some(pair) => pair,
        None => return false,
    };
    if scheme.is_empty() || rest.is_empty() {
        return false;
    }
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower != "http" && scheme_lower != "https" {
        return false;
    }
    let authority = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = if authority.starts_with('[') {
        match authority.find(']') {
            Some(end) => &authority[..=end],
            None => return false,
        }
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return false;
    }
    if scheme_lower == "https" {
        return true;
    }
    is_loopback_host(host)
}

/// Redacts an exact credential value from untrusted text without allocating
/// when the value is empty or absent.
pub fn redact_exact_secret<'a>(text: &'a str, secret: &str) -> std::borrow::Cow<'a, str> {
    if secret.is_empty() || !text.contains(secret) {
        return std::borrow::Cow::Borrowed(text);
    }
    std::borrow::Cow::Owned(text.replace(secret, "<redacted>"))
}

pub fn safe_url_origin(raw: &str) -> String {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return "remote-url".to_string();
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return "remote-url".to_string();
    }
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit_once('@')
        .map_or_else(
            || rest.split(['/', '?', '#']).next().unwrap_or(""),
            |(_, host)| host,
        );
    if authority.is_empty() {
        return "remote-url".to_string();
    }
    format!("{}://{authority}", scheme.to_ascii_lowercase())
}

/// Loopback host detection covering the shapes that appear in tests
/// and on dev machines: `localhost`, every IPv4 address in
/// `127.0.0.0/8`, the IPv6 loopback `::1`, and the bracketed
/// `[::1]` form that `reqwest::Url::host_str` returns.
pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        return addr.is_loopback();
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && let Ok(addr) = inner.parse::<std::net::IpAddr>()
    {
        return addr.is_loopback();
    }
    false
}

/// The bytes free to this user on the filesystem holding `path`, or its
/// nearest existing ancestor; None where it can't be read.
pub fn filesystem_available_bytes(path: &std::path::Path) -> Option<u64> {
    filesystem_space(path).map(|space| space.available)
}

/// The bytes a write by this user can take on the filesystem holding
/// `path`, or its nearest existing ancestor: what it reports free, less
/// what APFS keeps back from writes (see [`apfs_held_back`]). None where it
/// can't be read.
pub fn filesystem_writable_bytes(path: &std::path::Path) -> Option<u64> {
    filesystem_space(path).map(|space| space.available.saturating_sub(space.held_back))
}

/// What a filesystem reports free to this user, and how much of that it
/// keeps back from writes.
struct FilesystemSpace {
    available: u64,
    held_back: u64,
}

#[cfg(unix)]
fn filesystem_space(path: &std::path::Path) -> Option<FilesystemSpace> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mut probe = path.to_path_buf();
    while !probe.try_exists().ok()? {
        if !probe.pop() {
            return None;
        }
    }
    let path = CString::new(probe.as_os_str().as_bytes()).ok()?;
    // macOS's `statvfs` counts blocks in 32 bits, which can't hold the free
    // blocks of a volume with more than 16 TiB free; its `statfs` counts in
    // 64 bits.
    #[cfg(target_os = "macos")]
    let (available, held_back) = {
        let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `path` is NUL-terminated and `stats` points to writable,
        // properly aligned storage that is read only after a successful call.
        if unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: `statfs` returned success and initialized the output structure.
        let stats = unsafe { stats.assume_init() };
        let block = u128::from(stats.f_bsize);
        let available = u128::from(stats.f_bavail).checked_mul(block)?;
        let apfs = stats
            .f_fstypename
            .iter()
            .take_while(|&&byte| byte != 0)
            .map(|&byte| byte as u8)
            .eq(*b"apfs");
        let held_back = if apfs {
            let size = u128::from(stats.f_blocks).checked_mul(block)?;
            apfs_held_back(u64::try_from(size).unwrap_or(u64::MAX))
        } else {
            0
        };
        (available, held_back)
    };
    // `f_bavail` already leaves out what's reserved for root.
    #[cfg(not(target_os = "macos"))]
    let (available, held_back) = {
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `path` is NUL-terminated and `stats` points to writable,
        // properly aligned storage that is read only after a successful call.
        if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: `statvfs` returned success and initialized the output structure.
        let stats = unsafe { stats.assume_init() };
        (
            u128::from(stats.f_bavail).checked_mul(u128::from(stats.f_frsize))?,
            0,
        )
    };
    Some(FilesystemSpace {
        available: u64::try_from(available).ok()?,
        held_back,
    })
}

#[cfg(not(unix))]
fn filesystem_space(_path: &std::path::Path) -> Option<FilesystemSpace> {
    None
}

/// What APFS reports free on a volume of `size` bytes but refuses writes:
/// a stream of writes to one file stops with about 2% of the volume and
/// 460 KB more still reported free, and never more than 32 MiB and 80 KiB,
/// as measured on volumes of 64 MB to 8 GB. Rounded up by about half a MiB,
/// which also covers the blocks a file's own metadata takes. That's the
/// least a write needs: on a fresh volume, writes flushed as they go, or
/// spread over many files, stopped up to about 16 MB sooner, so a write
/// counted as fitting can still fail, as on a full disk. APFS sometimes
/// keeps back less: one run on macOS 26 let a stream take 0.7 MB more of a
/// 64 MB volume, so a write can also fit in a little more than this counts.
#[cfg(any(target_os = "macos", test))]
fn apfs_held_back(size: u64) -> u64 {
    (size / 50)
        .saturating_add(1024 * 1024)
        .min(33 * 1024 * 1024)
}

/// Format bytes into a human-readable string in binary units, as they're
/// counted (e.g., "1.2 KiB", "3.4 MiB", "5 GiB"), as the LPM.dev Registry
/// labels them. Switches unit at each 1024, so a 900-byte file never reads
/// as "0.9 KiB", and a value whose tenth would read 1024.0 takes the next
/// unit. A whole number only for an exact size, so 5 GiB and a few bytes
/// reads "5.0 GiB". A tenth halfway between two rounds up, as the
/// Registry's does.
pub fn format_bytes(bytes: u64) -> String {
    format_scaled(bytes, 1, UNITS.len() - 1, Rounding::Nearest, false)
}

/// Formats a size past a limit it's shown against: to two decimals, rounded
/// up, so a size a byte past its limit never reads as within it ("500.01
/// MiB" against 500 MiB), as the LPM.dev Registry states such sizes.
pub fn format_bytes_past(bytes: u64) -> String {
    format_scaled(bytes, 2, UNITS.len() - 1, Rounding::Up, false)
}

/// Formats a usage and the limit it's shown against as the LPM.dev
/// Registry's billing page does: to two decimals, in GiB at most with
/// thousands grouped, as limits and prices are stated per GiB. The usage
/// rounds toward the side of the limit it's on, so usage a few bytes past
/// its limit reads as past it, as overage bills it ("5.01 GiB / 5 GiB"),
/// and usage a few bytes short reads as short of it.
pub fn format_quota(used: u64, limit: u64) -> (String, String) {
    let rounding = match used.cmp(&limit) {
        std::cmp::Ordering::Greater => Rounding::Up,
        std::cmp::Ordering::Less => Rounding::Down,
        std::cmp::Ordering::Equal => Rounding::Nearest,
    };
    (
        format_scaled(used, 2, GIB_UNIT, rounding, true),
        format_scaled(limit, 2, GIB_UNIT, Rounding::Nearest, true),
    )
}

/// Formats a usage with no limit to show it against, as `format_quota`
/// shows usage: to two decimals, in GiB at most with thousands grouped.
pub fn format_usage(used: u64) -> String {
    format_scaled(used, 2, GIB_UNIT, Rounding::Nearest, true)
}

const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
const GIB_UNIT: usize = 3;

#[derive(Clone, Copy)]
enum Rounding {
    Nearest,
    Up,
    Down,
}

/// `bytes` in its largest unit up to `max_unit` whose shown value is at
/// least 1, to `decimals` places, rounded as asked in exact integer
/// arithmetic; a whole number for an exact size.
fn format_scaled(
    bytes: u64,
    decimals: u32,
    max_unit: usize,
    rounding: Rounding,
    grouped: bool,
) -> String {
    if bytes < 1024 {
        let shown = if grouped {
            group_thousands(u128::from(bytes))
        } else {
            bytes.to_string()
        };
        return format!("{shown} B");
    }
    let places = 10_u128.pow(decimals);
    let shown = |scale: u128| {
        let numerator = u128::from(bytes) * places;
        match rounding {
            Rounding::Nearest => (numerator + scale / 2) / scale,
            Rounding::Up => numerator.div_ceil(scale),
            Rounding::Down => numerator / scale,
        }
    };
    let mut unit = 1;
    let mut scale = 1024_u128;
    while unit < max_unit && shown(scale) >= 1024 * places {
        unit += 1;
        scale *= 1024;
    }
    let whole = |value: u128| {
        if grouped {
            group_thousands(value)
        } else {
            value.to_string()
        }
    };
    if u128::from(bytes) % scale == 0 {
        return format!("{} {}", whole(u128::from(bytes) / scale), UNITS[unit]);
    }
    let value = shown(scale);
    format!(
        "{}.{:0width$} {}",
        whole(value / places),
        value % places,
        UNITS[unit],
        width = decimals as usize
    )
}

fn group_thousands(value: u128) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_labels_binary_units() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(1_048_576), "1 MiB");
        assert_eq!(format_bytes(2_621_440), "2.5 MiB");
        assert_eq!(format_bytes(5 * 1024 * 1024 * 1024), "5 GiB");
        assert_eq!(format_bytes(5 * 1024 * 1024 * 1024 + 100), "5.0 GiB");
        assert_eq!(format_bytes(1025 * 1024_u64.pow(3)), "1.0 TiB");
        assert_eq!(format_bytes(2 * 1024_u64.pow(4)), "2 TiB");
        assert_eq!(format_bytes(3 * 1024_u64.pow(5)), "3 PiB");
        assert_eq!(format_bytes(u64::MAX), "16384.0 PiB");
        // Whose tenth would read 1024.0 takes the next unit.
        assert_eq!(format_bytes(1_048_525), "1.0 MiB");
        assert_eq!(format_bytes(1_048_524), "1023.9 KiB");
    }

    #[test]
    fn format_bytes_rounds_a_halfway_tenth_up_as_the_registry_does() {
        assert_eq!(format_bytes(1280), "1.3 KiB");
        assert_eq!(format_bytes(1229), "1.2 KiB");
        assert_eq!(
            format_bytes(5 * 1024_u64.pow(3) + 1024_u64.pow(3) / 4),
            "5.3 GiB"
        );
    }

    #[test]
    fn format_quota_reads_usage_on_its_side_of_the_limit() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let quota = |used, limit| {
            let (used, limit) = format_quota(used, limit);
            format!("{used} / {limit}")
        };
        assert_eq!(quota(5 * GIB + 1, 5 * GIB), "5.01 GiB / 5 GiB");
        assert_eq!(
            quota(5 * GIB + 51 * 1024 * 1024, 5 * GIB),
            "5.05 GiB / 5 GiB"
        );
        assert_eq!(quota(5 * GIB - 1, 5 * GIB), "4.99 GiB / 5 GiB");
        assert_eq!(quota(5 * GIB, 5 * GIB), "5 GiB / 5 GiB");
        assert_eq!(
            quota(512 * 1024 * 1024 + 104_858, 5 * GIB),
            "512.10 MiB / 5 GiB"
        );
        assert_eq!(quota(0, 5 * GIB), "0 B / 5 GiB");
    }

    #[test]
    fn format_usage_reads_usage_as_quotas_do_without_a_limit() {
        let gib = 1024_u64.pow(3);
        assert_eq!(format_usage(1253 * gib + gib / 2), "1,253.50 GiB");
        assert_eq!(format_usage(1023), "1,023 B");
        assert_eq!(format_usage(2048), "2 KiB");
        assert_eq!(format_usage(2049), "2.00 KiB");
        // To nearest: 1.0059 KiB reads 1.01, not 1.00.
        assert_eq!(format_usage(1030), "1.01 KiB");
    }

    #[test]
    fn format_quota_states_sizes_in_gib_at_most_with_thousands_grouped() {
        const GIB: u64 = 1024 * 1024 * 1024;
        assert_eq!(
            format_quota(1253 * GIB, 1250 * GIB),
            ("1,253 GiB".into(), "1,250 GiB".into())
        );
        assert_eq!(
            format_quota(1253 * GIB + GIB / 2, 1250 * GIB).0,
            "1,253.50 GiB"
        );
        assert_eq!(format_quota(u64::MAX, u64::MAX).0, "17,179,869,184.00 GiB");
        assert_eq!(format_bytes_past(500 * 1024 * 1024 + 1), "500.01 MiB");
        assert_eq!(format_bytes_past(500 * 1024 * 1024), "500 MiB");
        assert_eq!(format_bytes_past(5 * GIB + 1), "5.01 GiB");
        // As the Registry groups bytes too ("1,000 B").
        assert_eq!(format_quota(1000, 2048), ("1,000 B".into(), "2 KiB".into()));
        assert_eq!(format_bytes(1000), "1000 B");
    }

    /// `df`'s figure for the filesystem holding `path`: its size and the
    /// space free to this user, in bytes.
    #[cfg(unix)]
    fn df(path: &std::path::Path) -> (u64, u64) {
        let output = std::process::Command::new("/bin/df")
            .arg("-Pk")
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout).unwrap();
        let fields: Vec<u64> = output
            .lines()
            .nth(1)
            .unwrap()
            .split_whitespace()
            .skip(1)
            .take(3)
            .map(|field| field.parse().unwrap())
            .collect();
        (fields[0] * 1024, fields[2] * 1024)
    }

    #[cfg(unix)]
    #[test]
    fn reads_the_space_free_to_this_user_as_df_does() {
        let directory = tempfile::tempdir().unwrap();
        let (size, free) = df(directory.path());

        let available = filesystem_available_bytes(directory.path()).unwrap();

        // Other writers move the figure a little between the two reads; the
        // space reserved for root, which this user can't use, is far more.
        assert!(
            available.abs_diff(free) <= size / 200,
            "{available} against df's {free} of {size}"
        );
        let unmade = filesystem_available_bytes(&directory.path().join("not/yet/made")).unwrap();
        assert!(unmade.abs_diff(available) <= size / 200);
    }

    #[test]
    fn apfs_holds_back_at_least_what_measured_volumes_kept_from_writes() {
        // A volume's size, and what it still reported free once a write
        // failed.
        for (size, kept) in [
            (104_816_640, 2_564_096),
            (314_531_840, 6_758_400),
            (524_247_040, 10_952_704),
            (1_073_700_864, 21_946_368),
            (2_147_442_688, 33_636_352),
            (4_085_211_136, 33_636_352),
            (8_380_178_432, 33_636_352),
        ] {
            let held_back = apfs_held_back(size);
            assert!(held_back >= kept, "{size}: {held_back} < {kept}");
            assert!(
                held_back - kept < 1024 * 1024,
                "{size}: {held_back} past {kept}"
            );
        }
        assert_eq!(apfs_held_back(u64::MAX), 33 * 1024 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn on_any_filesystem_but_apfs_nothing_reported_free_counts_as_kept_back() {
        let directory = tempfile::tempdir().unwrap();
        let space = filesystem_space(directory.path()).unwrap();
        if cfg!(target_os = "macos") && space.held_back > 0 {
            return;
        }

        assert_eq!(space.held_back, 0);
        let writable = filesystem_writable_bytes(directory.path()).unwrap();
        let available = filesystem_available_bytes(directory.path()).unwrap();
        let (size, _) = df(directory.path());
        assert!(writable.abs_diff(available) <= size / 200);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn on_apfs_a_stream_of_writes_takes_what_it_counts_writable_but_not_all_reported_free() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("volume.sparseimage");
        let mount_point = directory.path().join("mounted");
        std::fs::create_dir(&mount_point).unwrap();
        let hdiutil = |arguments: &[&std::ffi::OsStr]| {
            let output = std::process::Command::new("/usr/bin/hdiutil")
                .args(arguments)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "hdiutil {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        hdiutil(&[
            "create".as_ref(),
            "-quiet".as_ref(),
            "-size".as_ref(),
            "64m".as_ref(),
            "-fs".as_ref(),
            "APFS".as_ref(),
            "-type".as_ref(),
            "SPARSE".as_ref(),
            "-volname".as_ref(),
            "lpm-common-test".as_ref(),
            image.as_os_str(),
        ]);
        hdiutil(&[
            "attach".as_ref(),
            "-quiet".as_ref(),
            "-nobrowse".as_ref(),
            "-noautoopen".as_ref(),
            "-mountpoint".as_ref(),
            mount_point.as_os_str(),
            image.as_os_str(),
        ]);
        struct Detach<'a>(&'a std::path::Path);
        impl Drop for Detach<'_> {
            fn drop(&mut self) {
                let _ = std::process::Command::new("/usr/bin/hdiutil")
                    .args(["detach", "-force", "-quiet"])
                    .arg(self.0)
                    .status();
            }
        }
        let _detach = Detach(&mount_point);

        let space = filesystem_space(&mount_point).unwrap();
        assert!(space.held_back > 0);
        let writable = filesystem_writable_bytes(&mount_point).unwrap();
        let mut filler = std::fs::File::create(mount_point.join("filler")).unwrap();
        let mut written = 0u64;
        for chunk in [64 * 1024, 4096] {
            let block = vec![0; chunk];
            while filler.write_all(&block).is_ok() {
                written += chunk as u64;
            }
        }

        // How much of its reserve APFS lets a stream take varies by release
        // and run, so how closely the reserve matches is checked against
        // measured volumes in `apfs_holds_back_at_least_what_measured_volumes_kept_from_writes`.
        assert_eq!(writable, space.available - space.held_back);
        assert!(written >= writable, "wrote {written} of {writable}");
        assert!(
            written < space.available,
            "wrote {written}, all of the {} reported free",
            space.available
        );
    }

    // ── read_capped_state_file ────────────────────────────────────────

    /// Files under the cap round-trip transparently.
    #[test]
    fn capped_state_reader_returns_file_under_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, br#"{"ok":true}"#).unwrap();
        let result = read_capped_state_file(&path, 64 * 1024)
            .expect("read must succeed")
            .expect("file under cap must return Some");
        assert_eq!(&result, br#"{"ok":true}"#);
    }

    /// Missing files map to `Ok(None)` — same shape callers used pre-fix
    /// via `read_to_string(..).ok()?`.
    #[test]
    fn capped_state_reader_treats_missing_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let result = read_capped_state_file(&path, 64 * 1024).expect("missing file is not an Err");
        assert!(result.is_none());
    }

    /// L28: files exceeding the cap are treated as missing — no bytes
    /// are buffered and no serde parse runs. A malicious repo state
    /// file can't force a multi-GB `read_to_string` at command start.
    #[test]
    fn capped_state_reader_treats_over_cap_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.json");
        // 1 MB file with a tiny 256-byte cap — clearly oversize.
        std::fs::write(&path, vec![b'x'; 1024 * 1024]).unwrap();
        let result = read_capped_state_file(&path, 256).expect("over-cap is not an Err");
        assert!(
            result.is_none(),
            "file larger than cap must collapse to None"
        );
    }

    // ── is_safe_skill_name ────────────────────────────────────────────

    #[test]
    fn safe_skill_name_valid() {
        assert!(is_safe_skill_name("getting-started"));
        assert!(is_safe_skill_name("my_skill.v2"));
        assert!(is_safe_skill_name("a"));
        assert!(is_safe_skill_name("skill-123"));
    }

    #[test]
    fn safe_skill_name_rejects_traversal() {
        assert!(!is_safe_skill_name("../../etc/foo"));
        assert!(!is_safe_skill_name(".."));
        assert!(!is_safe_skill_name("foo/bar"));
        assert!(!is_safe_skill_name("foo\\bar"));
    }

    #[test]
    fn safe_skill_name_rejects_empty() {
        assert!(!is_safe_skill_name(""));
    }

    #[test]
    fn safe_skill_name_rejects_null_byte() {
        assert!(!is_safe_skill_name("a\0b"));
    }

    #[test]
    fn safe_skill_name_rejects_long() {
        let long = "a".repeat(129);
        assert!(!is_safe_skill_name(&long));
        // 128 is the limit
        let at_limit = "a".repeat(128);
        assert!(is_safe_skill_name(&at_limit));
    }

    #[test]
    fn safe_skill_name_rejects_special_chars() {
        assert!(!is_safe_skill_name("skill name"));
        assert!(!is_safe_skill_name("skill@name"));
        assert!(!is_safe_skill_name("skill#name"));
    }

    // ── sanitize_path_component ───────────────────────────────────────

    #[test]
    fn sanitize_strips_traversal() {
        assert_eq!(sanitize_path_component("../../etc"), "_-_-etc");
        assert_eq!(sanitize_path_component("foo/bar"), "foo-bar");
        assert_eq!(sanitize_path_component("ok.pkg"), "ok.pkg");
    }

    // ── sanitize_for_terminal ─────────────────────────────────────────

    /// M71: OSC 8 hyperlink escape (used to make a registry-supplied
    /// package name a clickable link to an arbitrary file URL) must be
    /// stripped to literal `?`s before the string reaches the terminal.
    #[test]
    fn terminal_sanitizer_strips_osc8_hyperlink() {
        let payload = "\x1b]8;;file:///etc/passwd\x07evil-pkg\x1b]8;;\x07";
        let cleaned = sanitize_for_terminal(payload);
        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
        assert!(cleaned.contains("evil-pkg"));
    }

    /// M71: OSC 52 clipboard-write must not reach the terminal.
    #[test]
    fn terminal_sanitizer_strips_osc52_clipboard() {
        let payload = "react\x1b]52;c;cm0gLXJmIH4=\x07@1.0.0";
        let cleaned = sanitize_for_terminal(payload);
        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
        assert!(cleaned.contains("react"));
        assert!(cleaned.contains("@1.0.0"));
    }

    /// M71: CSI cursor manipulation (e.g., reposition over a prompt)
    /// is neutralised.
    #[test]
    fn terminal_sanitizer_strips_csi_cursor_moves() {
        let payload = "pkg\x1b[2J\x1b[H\x1b[31mfake prompt: \x1b[0m";
        let cleaned = sanitize_for_terminal(payload);
        assert!(!cleaned.contains('\x1b'));
    }

    #[test]
    fn terminal_multiline_sanitizer_preserves_lf_tabs_and_unicode_but_normalizes_crlf() {
        let cleaned = sanitize_terminal_multiline("line 1\nline 2\r\n\tパッケージ-🌀");

        assert_eq!(cleaned, "line 1\nline 2\n\tパッケージ-🌀");
    }

    #[test]
    fn terminal_multiline_sanitizer_neutralizes_lone_carriage_returns_and_escapes() {
        let cleaned = sanitize_terminal_multiline("one\rtwo\n\x1b[31mthree\x1b[0m");

        assert_eq!(cleaned, "one?two\nthree");
    }

    /// M71: DEL (0x7f) and lone BEL are stripped.
    #[test]
    fn terminal_sanitizer_strips_del_and_bel() {
        assert_eq!(sanitize_for_terminal("a\x7fb"), "a?b");
        assert_eq!(sanitize_for_terminal("ring\x07bell"), "ring?bell");
    }

    #[test]
    fn terminal_sanitizer_removes_complete_escape_sequences_without_leaking_payloads() {
        let input = concat!(
            "before",
            "\x1b[31mred\x1b[0m",
            "\x1b]0;forged title\x07after-osc",
            "\x1bP1;2|dcs payload\x1b\\after-dcs",
            "\x1b_apc payload\x1b\\after-apc",
            "\x1b^pm payload\x1b\\after-pm",
            "\x1bXsos payload\x1b\\after-sos",
            "\x1b7after-esc",
        );

        assert_eq!(
            sanitize_for_terminal(input),
            "beforeredafter-oscafter-dcsafter-apcafter-pmafter-sosafter-esc"
        );
    }

    #[test]
    fn terminal_sanitizer_removes_c1_sequences_and_controls() {
        let input = concat!(
            "a\u{009b}31mred\u{009b}0m",
            "\u{009d}0;title\u{009c}b",
            "\u{0090}dcs\u{009c}c",
            "\u{0098}sos\u{009c}d",
            "\u{009e}pm\u{009c}e",
            "\u{009f}apc\u{009c}f",
            "\u{0085}g",
        );

        assert_eq!(sanitize_for_terminal(input), "aredbcdef?g");
    }

    #[test]
    fn terminal_sanitizer_neutralizes_every_raw_c1_control() {
        let mut input = String::new();
        for codepoint in 0x80..=0x9f {
            if !matches!(codepoint, 0x90 | 0x98 | 0x9b | 0x9d..=0x9f) {
                input.push(char::from_u32(codepoint).expect("C1 codepoint is valid"));
            }
        }

        assert_eq!(
            sanitize_terminal_inline(&input),
            "?".repeat(input.chars().count())
        );
    }

    #[test]
    fn terminal_sanitizer_neutralizes_all_inline_whitespace_and_raw_controls() {
        let input = "nul\0tab\tline\nreturn\rbel\x07back\x08delete\x7funit\x1fend";

        assert_eq!(
            sanitize_for_terminal(input),
            "nul?tab?line?return?bel?back?delete?unit?end"
        );
    }

    #[test]
    fn terminal_sanitizer_fails_safe_for_nested_and_unterminated_sequences() {
        let input = concat!(
            "visible",
            "\x1b]52;c;clipboard\x1b[2Jstill-terminal-payload",
        );

        assert_eq!(sanitize_for_terminal(input), "visible");
    }

    #[test]
    fn terminal_sanitizer_is_idempotent_and_preserves_printable_unicode() {
        let input = "パッケージ🌀\x1b[31m café\x1b[0m";
        let once = sanitize_for_terminal(input);

        assert_eq!(sanitize_for_terminal(&once), once);
        assert_eq!(once, "パッケージ🌀 café");
    }

    #[test]
    fn terminal_sanitizer_bounds_output_for_long_hostile_input() {
        let input = "\x1b[31m\x07\x08\r\x7f".repeat(100_000);

        assert!(sanitize_for_terminal(&input).len() <= input.len());
    }

    #[test]
    fn terminal_sanitizer_returns_borrowed_input_when_unchanged() {
        assert!(matches!(
            sanitize_terminal_inline("ordinary Unicode パッケージ 🌀"),
            std::borrow::Cow::Borrowed(_)
        ));
        assert!(matches!(
            sanitize_terminal_multiline("line one\n\tline two"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn terminal_sanitizer_drops_truncated_escape_families() {
        for input in [
            "safe\x1b",
            "safe\x1b[31",
            "safe\x1b]unterminated",
            "safe\x1bPunterminated",
            "safe\x1b_unterminated",
            "safe\x1b^unterminated",
            "safe\x1bXunterminated",
            "safe\u{009b}31",
            "safe\u{009d}unterminated",
            "safe\u{0090}unterminated",
            "safe\u{0098}unterminated",
            "safe\u{009e}unterminated",
            "safe\u{009f}unterminated",
        ] {
            assert_eq!(sanitize_terminal_inline(input), "safe", "input: {input:?}");
        }
    }

    // ── lpm_registry_url_is_accepted (H16) ────────────────────────────

    /// H16: HTTPS URLs are accepted regardless of host — legitimate
    /// private mirrors / on-prem appliances are operator-chosen and
    /// can't be enumerated upfront.
    #[test]
    fn registry_url_gate_accepts_https_any_host() {
        assert!(lpm_registry_url_is_accepted("https://lpm.dev"));
        assert!(lpm_registry_url_is_accepted("https://lpm.example.com"));
        assert!(lpm_registry_url_is_accepted("https://10.0.0.1:8443"));
        assert!(!lpm_registry_url_is_accepted(
            "https://user:pass@registry.internal/some/path"
        ));
    }

    #[test]
    fn safe_url_origin_removes_credentials_and_url_components() {
        assert_eq!(
            safe_url_origin(
                "https://registry-user:registry-password@example.com/private?token=secret#part"
            ),
            "https://example.com"
        );
        assert_eq!(safe_url_origin("not a url"), "remote-url");
    }

    /// H16: plain HTTP is accepted ONLY for loopback hosts — this is
    /// the workflow-test escape hatch (wiremock binds to 127.0.0.1).
    #[test]
    fn registry_url_gate_accepts_http_loopback_only() {
        assert!(lpm_registry_url_is_accepted("http://127.0.0.1:8080"));
        assert!(lpm_registry_url_is_accepted("http://localhost"));
        assert!(lpm_registry_url_is_accepted("http://[::1]:9000"));
        assert!(lpm_registry_url_is_accepted("http://127.5.5.5/api"));
    }

    /// H16: plain HTTP non-loopback is the credential-exfil shape the
    /// finding calls out — it MUST be refused so the resolver falls
    /// back to DEFAULT_REGISTRY_URL.
    #[test]
    fn registry_url_gate_rejects_http_non_loopback() {
        assert!(!lpm_registry_url_is_accepted("http://attacker.example"));
        assert!(!lpm_registry_url_is_accepted("http://lpm.dev"));
        assert!(!lpm_registry_url_is_accepted("http://10.0.0.1"));
        assert!(!lpm_registry_url_is_accepted("http://192.168.1.1"));
    }

    /// H16: unsupported schemes and malformed input both collapse to
    /// "rejected" — we never honour `ftp://` / `file://` / a bare host
    /// string.
    #[test]
    fn registry_url_gate_rejects_unsupported_schemes_and_garbage() {
        assert!(!lpm_registry_url_is_accepted("ftp://registry.npmjs.org"));
        assert!(!lpm_registry_url_is_accepted("file:///etc/passwd"));
        assert!(!lpm_registry_url_is_accepted("javascript:alert(1)"));
        assert!(!lpm_registry_url_is_accepted("lpm.dev"));
        assert!(!lpm_registry_url_is_accepted(""));
        assert!(!lpm_registry_url_is_accepted("https://"));
    }

    /// H16: loopback shapes the helper specifically needs to cover —
    /// `localhost`, every 127.0.0.0/8 address, and the IPv6 loopback
    /// in both bare and bracketed forms.
    #[test]
    fn loopback_host_covers_localhost_and_127_block_and_v6() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LocalHost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.99.42.7"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("8.8.8.8"));
        assert!(!is_loopback_host("registry.npmjs.org"));
        assert!(!is_loopback_host(""));
    }
}
