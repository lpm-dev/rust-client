//! Core types shared across LPM workspace crates.
//!
//! Hosts the canonical [`PackageName`] parser, [`Integrity`] (SRI) helpers,
//! [`LpmError`] (the unified error type returned by the CLI surface), and the
//! [`LpmRoot`] / locking primitives every install pass touches. I/O helpers in
//! this crate stay small and dependency-light so it remains the workspace floor.

pub mod atomic_write;
pub mod bounded_read;
pub mod color;
pub mod error;
pub mod integrity;
pub mod known_projects;
pub mod local_target;
pub mod package_name;
pub mod paths;
pub mod platform;
pub mod provenance;
pub mod symlink;
pub mod terminal;

#[cfg(unix)]
pub use atomic_write::replace_symlink_atomic;
pub use atomic_write::{
    AtomicWriteOptions, write_file_atomic, write_file_atomic_with, write_file_atomic_with_options,
};
pub use bounded_read::{
    BoundedReadError, CONFIG_FILE_SIZE_CAP_BYTES, NPMRC_FILE_SIZE_CAP_BYTES,
    TLS_MATERIAL_FILE_SIZE_CAP_BYTES, read_file_capped, read_text_file_capped,
};
pub use error::{
    ArtifactUnavailableErrorContext, ArtifactUnavailableKind, LpmError, ResolutionErrorContext,
    ResolutionFailureKind, TyposquatErrorContext, TyposquatErrorFinding,
};
pub use integrity::Integrity;
pub use local_target::{LocalScheme, LocalTarget};
pub use package_name::PackageName;
pub use paths::{
    ExclusiveLockHandle, FsKind, GLOBAL_INSTALL_PATH_BUDGET, INSTALL_READY_MARKER, LpmRoot,
    SharedLockHandle, acquire_exclusive_lock, as_extended_path, check_install_path_budget,
    is_local_fs, project_install_lock, try_acquire_exclusive_lock, try_with_exclusive_lock,
    with_exclusive_lock, with_exclusive_lock_async, with_shared_lock, with_shared_lock_async,
};
pub use provenance::{ProvenanceSnapshot, ProvenanceStatus, npm_package_purl};
pub use symlink::{
    create_dir_symlink_or_junction, create_symlink, is_symlink_or_junction, remove_path_entry,
};
pub use terminal::{sanitize_for_terminal, sanitize_terminal_inline, sanitize_terminal_multiline};

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
