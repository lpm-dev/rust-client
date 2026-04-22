//! Seatbelt profile synthesis for the macOS `sandbox-exec` backend.
//!
//! Implements §9.3 of the Phase 46 plan: reads broad (project +
//! toolchain), writes narrow (package store dir + `node_modules` +
//! `.husky` + `.lpm` + known caches + temp), network allowed by
//! default (D3), process-fork + exec allowed so `node-gyp` children
//! work.
//!
//! The profile is synthesized per-package — each invocation of a
//! lifecycle script renders its own profile whose `(subpath "...")`
//! entries are grounded in that package's `package_dir`, the
//! project root, and the host's `$HOME` + `$TMPDIR`. Extra writable
//! subpaths from `package.json > lpm > scripts > sandboxWriteDirs`
//! are appended to the `file-write*` allow list.

#![cfg(target_os = "macos")]

use crate::{SandboxError, SandboxSpec};
use std::path::Path;

/// Render the Enforce-mode Seatbelt profile for the given
/// [`SandboxSpec`]. The returned string is safe to pass to
/// `sandbox-exec -p`.
///
/// Profile layout matches §9.3: deny-by-default, then an explicit
/// `file-read*` allow list, an explicit `file-write*` allow list,
/// unrestricted network, process spawn, and the mach / sysctl
/// primitives node-gyp needs.
pub(crate) fn render_profile(spec: &SandboxSpec) -> Result<String, SandboxError> {
    // Pre-compute every path the profile references so a path-encoding
    // failure short-circuits before we emit a half-rendered profile.
    let package_dir = quoted_path(&spec.package_dir, "package_dir")?;
    let project_dir = quoted_path(&spec.project_dir, "project_dir")?;
    let home_cache = quoted_path(&spec.home_dir.join(".cache"), "home_dir/.cache")?;
    let home_node_gyp = quoted_path(&spec.home_dir.join(".node-gyp"), "home_dir/.node-gyp")?;
    let home_npm = quoted_path(&spec.home_dir.join(".npm"), "home_dir/.npm")?;
    let home_nvm = quoted_path(
        &spec.home_dir.join(".nvm").join("versions"),
        "home_dir/.nvm/versions",
    )?;
    let tmpdir = quoted_path(&spec.tmpdir, "tmpdir")?;

    // node_modules / .husky / .lpm are subpaths of project_dir.
    let project_node_modules = quoted_path(
        &spec.project_dir.join("node_modules"),
        "project_dir/node_modules",
    )?;
    let project_husky = quoted_path(&spec.project_dir.join(".husky"), "project_dir/.husky")?;
    let project_lpm = quoted_path(&spec.project_dir.join(".lpm"), "project_dir/.lpm")?;

    // Extra writable dirs come from package.json > lpm > scripts >
    // sandboxWriteDirs. The loader already resolved them to absolute
    // paths; we re-assert here because a backend-level invariant
    // violation should surface as ProfileRenderFailed, not a sandbox
    // bypass.
    let mut extras = Vec::with_capacity(spec.extra_write_dirs.len());
    for (i, p) in spec.extra_write_dirs.iter().enumerate() {
        if !p.is_absolute() {
            return Err(SandboxError::ProfileRenderFailed {
                reason: format!(
                    "extra_write_dirs[{i}] must be absolute at render time, got {}",
                    p.display()
                ),
            });
        }
        extras.push(quoted_path(p, &format!("extra_write_dirs[{i}]"))?);
    }

    let mut out = String::with_capacity(1024 + 64 * extras.len());
    out.push_str("(version 1)\n");
    out.push_str("(deny default)\n");
    out.push('\n');

    // file-read*: broad, because scripts legitimately read project +
    // toolchain paths. §9.3 lists the project + system baseline;
    // this implementation extends it with the paths every real macOS
    // binary needs to load (dyld shared cache at /System/Volumes +
    // /private/var/db/dyld, /bin + /sbin for shells and coreutils,
    // /private/etc for locale + resolv.conf, /dev tty/random/zero
    // for common libc initialization). Writes stay narrow; only
    // reads are widened past the schematic §9.3 layout.
    out.push_str("(allow file-read*\n");
    // Stat-the-root is required by the dyld loader on macOS; without
    // this entry even `/usr/bin/true` fails to launch under a
    // deny-default profile.
    out.push_str("  (literal \"/\")\n");
    out.push_str(&format!("  (subpath {package_dir})\n"));
    out.push_str(&format!("  (subpath {project_dir})\n"));
    out.push_str("  (subpath \"/usr\")\n");
    out.push_str("  (subpath \"/bin\")\n");
    out.push_str("  (subpath \"/sbin\")\n");
    out.push_str("  (subpath \"/System\")\n");
    out.push_str("  (subpath \"/Library/Developer/CommandLineTools\")\n");
    out.push_str("  (subpath \"/Library/Preferences\")\n");
    out.push_str("  (subpath \"/private/etc\")\n");
    out.push_str("  (subpath \"/private/var/db/dyld\")\n");
    out.push_str("  (subpath \"/private/var/db/timezone\")\n");
    // Broad /dev read covers /dev/fd/*, /dev/stdin/stdout/stderr, and
    // the tty + random devices shells and coreutils commonly touch.
    // /dev has no secrets (raw disks etc. would need additional
    // iokit-open narrowing to expose, and those aren't granted here).
    out.push_str("  (subpath \"/dev\")\n");
    out.push_str(&format!("  (subpath {home_nvm})\n"));
    out.push_str(")\n");
    out.push('\n');

    // file-write*: narrow but covers the greens. Must contain the
    // package's own store dir (Chunk 5's compat corpus tests write
    // markers here), project `node_modules` (prisma generate),
    // `.husky` (husky install), `.lpm` (LPM's own state),
    // `~/.cache` + `~/.node-gyp` + `~/.npm` (tooling caches), and
    // `/tmp` + `$TMPDIR` — plus `/private/var/folders` since macOS's
    // `$TMPDIR` resolves to there and some tools pass the unresolved
    // form. `/dev/null` is writable so `>/dev/null` redirects work.
    out.push_str("(allow file-write*\n");
    out.push_str(&format!("  (subpath {package_dir})\n"));
    out.push_str(&format!("  (subpath {project_node_modules})\n"));
    out.push_str(&format!("  (subpath {project_husky})\n"));
    out.push_str(&format!("  (subpath {project_lpm})\n"));
    out.push_str(&format!("  (subpath {home_cache})\n"));
    out.push_str(&format!("  (subpath {home_node_gyp})\n"));
    out.push_str(&format!("  (subpath {home_npm})\n"));
    out.push_str("  (subpath \"/tmp\")\n");
    out.push_str(&format!("  (subpath {tmpdir})\n"));
    out.push_str("  (subpath \"/private/var/folders\")\n");
    out.push_str("  (literal \"/dev/null\")\n");
    out.push_str("  (literal \"/dev/tty\")\n");
    for e in &extras {
        out.push_str(&format!("  (subpath {e})\n"));
    }
    out.push_str(")\n");
    out.push('\n');

    // D3: network on by default. Paranoid mode is Phase 46.1.
    out.push_str("(allow network*)\n");
    // node-gyp + electron-rebuild fork helper processes + basic
    // process-info introspection the dynamic linker + libSystem
    // call into. `process*` covers fork, exec, info, codesigning-
    // status, and signalling; narrower splits exist but this is the
    // least-surprising default for a script runner where sub-shells
    // are routine.
    out.push_str("(allow process*)\n");
    out.push_str("(allow signal)\n");
    // Mach lookups + sysctl reads the dynamic linker + libSystem
    // need. IOKit usage comes from libsystem (device enumeration
    // during locale init and similar); without it even /usr/bin/true
    // fails to load on recent macOS releases.
    out.push_str("(allow mach-lookup)\n");
    out.push_str("(allow sysctl-read)\n");
    out.push_str("(allow iokit-open)\n");

    Ok(out)
}

/// Escape a path into a quoted Seatbelt string literal. Handles
/// embedded `"` and `\` per the Scheme-like profile syntax
/// `sandbox-exec` parses.
///
/// Returns `"..."` (quotes included) so callers can interpolate the
/// result directly into `(subpath ...)` / `(literal ...)` forms.
fn quoted_path(p: &Path, field: &str) -> Result<String, SandboxError> {
    let s = p
        .to_str()
        .ok_or_else(|| SandboxError::ProfileRenderFailed {
            reason: format!("{field} is not valid UTF-8: {}", p.display()),
        })?;
    Ok(scheme_quote(s))
}

fn scheme_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render the LogOnly-mode Seatbelt profile for the given
/// [`SandboxSpec`]. Permissive fallback + silent Enforce overrides.
///
/// # SBPL last-match-wins semantics
///
/// The profile opens with `(allow (with report) default)` — every
/// operation matches this. The Enforce allow blocks (`file-read*`,
/// `file-write*`, `network*`, `process*`, etc.) come AFTER, so for
/// operations they cover, the LATER rule wins — those are silent
/// allows, identical to Enforce mode. Operations NOT covered by the
/// Enforce rules fall through to the opening `(allow (with report)
/// default)` and get logged via `sandboxd` while still being
/// permitted.
///
/// This is the pattern Apple's own internal profiles
/// (`com.apple.ClassroomKit.ClassroomMCXService.sb`,
/// `DiagnosticsKit.XPCTestService.sb`, etc.) use as the developer-
/// tuning observe-only idiom.
///
/// # User-facing contract
///
/// A clean run under `--sandbox-log` is NOT a safety signal. Every
/// access that would have been denied in [`render_profile`] is
/// merely logged here — the script runs with full host access for
/// any path outside the Enforce allow list. The CLI surface
/// (banner + help text) makes this explicit.
///
/// # Viewing the logs
///
/// Reports flow through the unified log. Users run
/// `log show --last 5m --predicate 'senderImagePath CONTAINS "Sandbox"' | grep -w <pid>`
/// to see what would-have-been-denied operations fired.
pub(crate) fn render_logonly_profile(spec: &SandboxSpec) -> Result<String, SandboxError> {
    // Build the Enforce profile body first — these are the rules
    // that should remain SILENT under LogOnly.
    let enforce_body = render_profile(spec)?;
    // The enforce profile starts with `(version 1)\n(deny default)\n`.
    // Strip those two lines: LogOnly replaces `(deny default)` with
    // the permissive `(allow (with report) default)` fallback.
    let body_after_deny = enforce_body
        .strip_prefix("(version 1)\n(deny default)\n")
        .ok_or_else(|| SandboxError::ProfileRenderFailed {
            reason: "render_profile output did not match expected header — \
                 LogOnly renderer relies on this invariant"
                .to_string(),
        })?;

    let mut out = String::with_capacity(enforce_body.len() + 64);
    out.push_str("(version 1)\n");
    // SBPL last-match-wins: this permissive+report rule is the
    // fallback. Every operation matches, every operation is logged.
    // Enforce rules that follow override to silent allows for their
    // covered paths.
    out.push_str("(allow (with report) default)\n");
    out.push_str(body_after_deny);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec() -> SandboxSpec {
        SandboxSpec {
            package_dir: PathBuf::from("/lpm-store/prisma@5.22.0"),
            project_dir: PathBuf::from("/home/u/proj"),
            package_name: "prisma".into(),
            package_version: "5.22.0".into(),
            store_root: PathBuf::from("/lpm-store"),
            home_dir: PathBuf::from("/home/u"),
            tmpdir: PathBuf::from("/var/folders/xx/T"),
            extra_write_dirs: Vec::new(),
        }
    }

    #[test]
    fn profile_starts_with_deny_default() {
        let p = render_profile(&spec()).unwrap();
        assert!(p.starts_with("(version 1)\n(deny default)\n"));
    }

    #[test]
    fn profile_contains_package_dir_in_both_read_and_write() {
        let p = render_profile(&spec()).unwrap();
        // Appears once in file-read* block, once in file-write* block.
        assert_eq!(
            p.matches("/lpm-store/prisma@5.22.0").count(),
            2,
            "package_dir must appear in both read and write allow lists — got profile:\n{p}"
        );
    }

    #[test]
    fn profile_contains_project_subpaths_for_writable_greens() {
        let p = render_profile(&spec()).unwrap();
        assert!(
            p.contains("/home/u/proj/node_modules"),
            "node_modules must be writable for prisma generate: {p}"
        );
        assert!(
            p.contains("/home/u/proj/.husky"),
            ".husky must be writable for husky install: {p}"
        );
        assert!(
            p.contains("/home/u/proj/.lpm"),
            ".lpm must be writable for LPM state: {p}"
        );
    }

    #[test]
    fn profile_contains_home_cache_paths() {
        let p = render_profile(&spec()).unwrap();
        assert!(p.contains("/home/u/.cache"));
        assert!(p.contains("/home/u/.node-gyp"));
        assert!(p.contains("/home/u/.npm"));
        assert!(p.contains("/home/u/.nvm/versions"));
    }

    #[test]
    fn profile_contains_temp_paths() {
        let p = render_profile(&spec()).unwrap();
        assert!(p.contains("/tmp"));
        assert!(p.contains("/var/folders/xx/T"));
    }

    #[test]
    fn profile_allows_network_by_default() {
        let p = render_profile(&spec()).unwrap();
        assert!(p.contains("(allow network*)"), "D3 — network allowed: {p}");
    }

    #[test]
    fn profile_allows_process_and_signal_primitives() {
        let p = render_profile(&spec()).unwrap();
        assert!(
            p.contains("(allow process*)"),
            "need process fork+exec+info: {p}"
        );
        assert!(p.contains("(allow signal)"));
        assert!(p.contains("(allow mach-lookup)"));
        assert!(p.contains("(allow sysctl-read)"));
        assert!(p.contains("(allow iokit-open)"));
    }

    #[test]
    fn profile_does_not_allow_ssh_aws_or_keychains() {
        let p = render_profile(&spec()).unwrap();
        assert!(!p.contains("/.ssh"), "ssh must never be allowed: {p}");
        assert!(!p.contains("/.aws"), "aws must never be allowed: {p}");
        assert!(
            !p.contains("(subpath \"/Library/Keychains\")"),
            "system keychain must never be allowed: {p}"
        );
        // `~/Library/Keychains/` lives under the user's home dir and
        // is NOT under the `/Library/Preferences` + `/Library/Developer`
        // subpaths we allow — deny-default covers it. Assert the
        // narrower `/Library` top-level allow didn't sneak in.
        assert!(
            !p.contains("(subpath \"/Library\")\n"),
            "broad /Library allow must not be present (only narrow subpaths): {p}"
        );
    }

    #[test]
    fn profile_includes_extra_write_dirs_verbatim() {
        let mut s = spec();
        s.extra_write_dirs = vec![
            PathBuf::from("/home/u/proj/build-output"),
            PathBuf::from("/home/u/.cache/ms-playwright"),
        ];
        let p = render_profile(&s).unwrap();
        assert!(p.contains("/home/u/proj/build-output"));
        assert!(p.contains("/home/u/.cache/ms-playwright"));
    }

    #[test]
    fn profile_rejects_relative_extra_write_dirs_at_render_time() {
        let mut s = spec();
        s.extra_write_dirs = vec![PathBuf::from("relative/path")];
        match render_profile(&s) {
            Err(SandboxError::ProfileRenderFailed { reason }) => {
                assert!(reason.contains("extra_write_dirs[0]"));
                assert!(reason.contains("absolute"));
            }
            other => panic!("expected ProfileRenderFailed, got {other:?}"),
        }
    }

    #[test]
    fn scheme_quote_escapes_quotes_and_backslashes() {
        assert_eq!(scheme_quote(r#"simple"#), r#""simple""#);
        assert_eq!(scheme_quote(r#"has"quote"#), r#""has\"quote""#);
        assert_eq!(scheme_quote(r"has\slash"), r#""has\\slash""#);
        assert_eq!(scheme_quote(r#"both"and\slash"#), r#""both\"and\\slash""#);
    }

    #[test]
    fn scheme_quote_handles_unicode() {
        assert_eq!(scheme_quote("café"), r#""café""#);
    }

    #[test]
    fn profile_forbidden_path_probe_is_denied_under_deny_default() {
        // `cat ~/.ssh/id_rsa` (§11 P5 ship criterion #1): the path is
        // never in the allow list, and the profile begins with
        // (deny default), so Seatbelt blocks the read. This test
        // asserts the profile's structural shape — the integration
        // test under tests/seatbelt_integration.rs actually shells
        // out to sandbox-exec to confirm runtime behavior.
        let p = render_profile(&spec()).unwrap();
        assert!(p.contains("(deny default)"));
        assert!(!p.contains(".ssh"));
    }

    #[test]
    fn logonly_profile_starts_with_permissive_report_fallback() {
        // `(allow (with report) default)` is the FIRST rule so every
        // operation matches as a baseline; Enforce rules later in the
        // profile override to silent allows where they apply. Pin the
        // ordering invariant since the semantic depends on it.
        let p = render_logonly_profile(&spec()).unwrap();
        assert!(
            p.starts_with("(version 1)\n(allow (with report) default)\n"),
            "LogOnly profile must open with the permissive+report fallback: {p}"
        );
    }

    #[test]
    fn logonly_profile_has_no_deny_default() {
        // `(deny default)` would short-circuit the permissive
        // fallback — LogOnly would become Enforce. Ensure the
        // Enforce header is stripped.
        let p = render_logonly_profile(&spec()).unwrap();
        assert!(
            !p.contains("(deny default)"),
            "LogOnly profile must NOT contain (deny default): {p}"
        );
    }

    #[test]
    fn logonly_profile_preserves_enforce_allow_rules() {
        // The Enforce allow lists (file-read*, file-write*, network*,
        // process*, etc.) still appear. Under SBPL last-match-wins
        // semantics, these override the permissive fallback for their
        // covered paths — operations matching Enforce rules are silent
        // allows, identical to Enforce behavior.
        let p = render_logonly_profile(&spec()).unwrap();
        assert!(p.contains("(allow file-read*"));
        assert!(p.contains("(allow file-write*"));
        assert!(p.contains("(allow network*)"));
        assert!(p.contains("(allow process*)"));
        assert!(p.contains("(allow mach-lookup)"));
    }

    #[test]
    fn logonly_profile_package_dir_and_writable_paths_match_enforce() {
        let enforce = render_profile(&spec()).unwrap();
        let logonly = render_logonly_profile(&spec()).unwrap();
        // Same path content — only the header differs.
        assert!(logonly.contains("/lpm-store/prisma@5.22.0"));
        assert!(logonly.contains("/home/u/proj/node_modules"));
        assert!(logonly.contains("/home/u/.cache"));
        // Sanity: everything Enforce lists in its writable block
        // except the header swap is still present.
        let enforce_after_header = enforce
            .strip_prefix("(version 1)\n(deny default)\n")
            .unwrap();
        let logonly_after_header = logonly
            .strip_prefix("(version 1)\n(allow (with report) default)\n")
            .unwrap();
        assert_eq!(enforce_after_header, logonly_after_header);
    }

    #[test]
    fn logonly_profile_propagates_render_errors_from_enforce() {
        // If the Enforce profile can't render (e.g. relative extra
        // write dir), LogOnly must fail with the same error variant —
        // we don't want LogOnly masking a configuration bug that
        // Enforce would have surfaced.
        let mut s = spec();
        s.extra_write_dirs = vec![PathBuf::from("relative/path")];
        match render_logonly_profile(&s) {
            Err(SandboxError::ProfileRenderFailed { reason }) => {
                assert!(reason.contains("extra_write_dirs[0]"));
            }
            other => panic!("expected ProfileRenderFailed, got {other:?}"),
        }
    }
}
