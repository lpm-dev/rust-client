//! Core types shared across LPM workspace crates.
//!
//! Hosts the canonical [`PackageName`] parser, [`Integrity`] (SRI) helpers,
//! [`LpmError`] (the unified error type returned by the CLI surface), and the
//! [`LpmRoot`] / locking primitives every install pass touches. I/O helpers in
//! this crate stay small and dependency-light so it remains the workspace floor.

pub mod atomic_write;
pub mod color;
pub mod error;
pub mod integrity;
pub mod known_projects;
pub mod package_name;
pub mod paths;
pub mod platform;
pub mod provenance;
pub mod symlink;

pub use atomic_write::write_file_atomic;
pub use error::{LpmError, ResolutionErrorContext, ResolutionFailureKind};
pub use integrity::Integrity;
pub use package_name::PackageName;
pub use paths::{
    ExclusiveLockHandle, FsKind, GLOBAL_INSTALL_PATH_BUDGET, INSTALL_READY_MARKER, LpmRoot,
    SharedLockHandle, as_extended_path, check_install_path_budget, is_local_fs,
    project_install_lock, try_with_exclusive_lock, with_exclusive_lock, with_exclusive_lock_async,
    with_shared_lock, with_shared_lock_async,
};
pub use provenance::{ProvenanceSnapshot, ProvenanceStatus};
pub use symlink::{create_dir_symlink_or_junction, create_symlink};

/// The LPM scope prefix. All LPM packages live under this scope.
pub const LPM_SCOPE: &str = "@lpm.dev";

/// Default LPM registry URL.
pub const DEFAULT_REGISTRY_URL: &str = "https://lpm.dev";

/// Default npm upstream registry URL.
pub const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";

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

/// Read a small state file with a size cap applied before any bytes
/// are buffered. Returns `Ok(None)` when the file is missing OR larger
/// than `cap`; returns `Ok(Some(bytes))` for files within budget;
/// returns `Err` only when the file exists, fits the cap, and the
/// read itself failed (disk error, permissions, etc.).
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
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if meta.len() > cap {
        tracing::warn!(
            path = %path.display(),
            size = meta.len(),
            cap = cap,
            "state file exceeds size cap — treating as missing"
        );
        return Ok(None);
    }
    Ok(Some(std::fs::read(path)?))
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
    if lpm_registry_url_is_accepted(&raw) {
        tracing::warn!(
            registry_url = %raw,
            "LPM_REGISTRY_URL override honoured — LPM bearer tokens, OIDC tokens, and vault payloads will be sent to this host; confirm it is expected",
        );
        return raw;
    }
    tracing::warn!(
        registry_url = %raw,
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
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
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

/// Render a registry- or lockfile-supplied string safely on a TTY.
///
/// Strips the byte ranges that carry terminal semantics — control
/// characters in `0x00-0x08`, `0x0b-0x1f`, `0x7f`, and the ESC / BEL
/// codepoints used to begin CSI / OSC / DCS sequences. A package name
/// like `\x1b]8;;file:///etc/passwd\x07evil-pkg\x1b]8;;\x07` no longer
/// reaches the terminal as a clickable OSC 8 hyperlink; a name
/// containing `\x1b]52;c;<data>\x07` no longer mutates the system
/// clipboard via OSC 52.
///
/// Tab (`\x09`), newline (`\x0a`), and carriage return (`\x0d`) are
/// preserved — install/audit progress lines legitimately contain them.
/// Each replaced character becomes a literal `?` so the operator
/// still sees something rather than silently-vanishing bytes.
pub fn sanitize_for_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        let code = c as u32;
        let safe = matches!(code, 0x09 | 0x0a | 0x0d) || (code >= 0x20 && code != 0x7f);
        if safe {
            out.push(c);
        } else {
            out.push('?');
        }
    }
    out
}

/// Format bytes into a human-readable string (e.g., "1.2 KB", "3.4 MB").
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// M71: tab / newline / carriage return are preserved — progress
    /// lines and multi-line audit output legitimately carry them.
    #[test]
    fn terminal_sanitizer_preserves_whitespace_and_unicode() {
        let cleaned = sanitize_for_terminal("line 1\nline 2\r\n\tindented\tcell");
        assert_eq!(cleaned, "line 1\nline 2\r\n\tindented\tcell");
        // Non-ASCII codepoints (CJK, emoji) pass through.
        let cleaned = sanitize_for_terminal("パッケージ-🌀");
        assert_eq!(cleaned, "パッケージ-🌀");
    }

    /// M71: DEL (0x7f) and lone BEL are stripped.
    #[test]
    fn terminal_sanitizer_strips_del_and_bel() {
        assert_eq!(sanitize_for_terminal("a\x7fb"), "a?b");
        assert_eq!(sanitize_for_terminal("ring\x07bell"), "ring?bell");
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
        assert!(lpm_registry_url_is_accepted(
            "https://user:pass@registry.internal/some/path"
        ));
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
