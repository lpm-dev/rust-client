//! Seatbelt profile synthesis for the macOS `sandbox-exec` backend.
//!
//! Reads broad (project + toolchain), writes narrow (package store
//! dir + `node_modules` + `.husky` + `.lpm` + known caches + temp),
//! network allowed by default, process-fork + exec allowed so
//! `node-gyp` children work.
//!
//! The profile is synthesized per-package — each invocation of a
//! lifecycle script renders its own profile whose `(subpath "...")`
//! entries are grounded in that package's `package_dir`, the
//! project root, and the host's `$HOME` + `$TMPDIR`. Extra writable
//! subpaths from `package.json > lpm > scripts > sandboxWriteDirs`
//! are appended to the `file-write*` allow list.

#![cfg(target_os = "macos")]

use crate::secret_paths::{SECRET_FILE_EXTENSIONS, SECRET_LITERAL_PATHS, SECRET_SUBPATH_DIRS};
use crate::{SandboxError, SandboxSpec};
use std::path::{Path, PathBuf};

/// Render the Enforce-mode Seatbelt profile for the given
/// [`SandboxSpec`]. The returned string is safe to pass to
/// `sandbox-exec -p`.
///
/// Profile layout: deny-by-default, then an explicit `file-read*`
/// allow list, an explicit `file-write*` allow list, unrestricted
/// network, process spawn, and the mach / sysctl primitives
/// node-gyp needs.
pub(crate) fn render_profile(
    spec: &SandboxSpec,
    deny_outbound_network: bool,
) -> Result<String, SandboxError> {
    render_profile_with_isolation(spec, deny_outbound_network, false)
}

pub(crate) fn render_profile_with_isolation(
    spec: &SandboxSpec,
    deny_outbound_network: bool,
    build_cache_isolation: bool,
) -> Result<String, SandboxError> {
    // Canonicalize base paths so Seatbelt rules match against the
    // same form the kernel uses at enforcement time. macOS symlinks
    // `/var` -> `/private/var`, `/tmp` -> `/private/tmp`, and
    // `$TMPDIR` resolves under `/private/var/folders/...`. Seatbelt
    // does NOT resolve symlinks inside `(subpath ...)` rules; a rule
    // spelled `/var/folders/x` does not match an enforcement-time
    // request for `/private/var/folders/x`. Confirmed empirically.
    //
    // Canonicalize only the base paths (which must exist on the
    // host) — their subpaths are constructed from the canonical
    // bases below so `.husky`, `.cache`, etc. get the right prefix
    // whether or not those subpaths exist yet.
    let canon_package_dir = canonicalize_or_passthrough(&spec.package_dir, "package_dir")?;
    let canon_project_dir = canonicalize_or_passthrough(&spec.project_dir, "project_dir")?;
    let canon_home_dir = canonicalize_or_passthrough(&spec.home_dir, "home_dir")?;
    let canon_tmpdir = canonicalize_or_passthrough(&spec.tmpdir, "tmpdir")?;

    let package_dir = quoted_path(&canon_package_dir, "package_dir")?;
    let project_dir = quoted_path(&canon_project_dir, "project_dir")?;
    let home_cache = quoted_path(&canon_home_dir.join(".cache"), "home_dir/.cache")?;
    let home_node_gyp = quoted_path(&canon_home_dir.join(".node-gyp"), "home_dir/.node-gyp")?;
    let home_npm = quoted_path(&canon_home_dir.join(".npm"), "home_dir/.npm")?;
    let home_nvm = quoted_path(
        &canon_home_dir.join(".nvm").join("versions"),
        "home_dir/.nvm/versions",
    )?;
    let tmpdir = quoted_path(&canon_tmpdir, "tmpdir")?;

    // node_modules / .husky / .lpm are subpaths of the canonical
    // project_dir.
    let project_node_modules = quoted_path(
        &canon_project_dir.join("node_modules"),
        "project_dir/node_modules",
    )?;
    let project_husky = quoted_path(&canon_project_dir.join(".husky"), "project_dir/.husky")?;
    let project_lpm = quoted_path(&canon_project_dir.join(".lpm"), "project_dir/.lpm")?;

    // Extra writable dirs are already filesystem-resolved effective
    // paths. Rendering that exact spelling preserves the validator's
    // containment decision instead of independently resolving the
    // untrusted manifest spelling again in the backend.
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
        let field = format!("extra_write_dirs[{i}]");
        extras.push(quoted_path(p, &field)?);
    }

    let mut out = String::with_capacity(1024 + 64 * extras.len());
    out.push_str("(version 1)\n");
    out.push_str("(deny default)\n");
    out.push('\n');

    // file-read-metadata broadly. Required for path traversal: a
    // script doing `mkdir -p $PROJECT/.husky` needs to stat each
    // path component from `/` down to `.husky`'s parent. Without
    // broad metadata, the traversal denies on intermediate dirs
    // (`/private`, `/private/var`, etc.) regardless of what file-
    // read* narrows. Apple's own `bsd.sb` uses this pattern for
    // the same reason.
    //
    // Metadata != data: `cat ~/.ssh/id_rsa` still fails because
    // `file-read-data` for that path stays denied. Escape-corpus
    // tests confirm the secret-contents guard holds.
    out.push_str("(allow file-read-metadata)\n");
    out.push('\n');

    // file-read*: broad, because scripts legitimately read project +
    // toolchain paths. The project + system baseline is extended with
    // the paths every real macOS binary needs to load (dyld shared
    // cache at /System/Volumes + /private/var/db/dyld, /bin + /sbin
    // for shells and coreutils, /private/etc for locale + resolv.conf,
    // /dev tty/random/zero for common libc initialization). Writes
    // stay narrow.
    out.push_str("(allow file-read*\n");
    // Stat-the-root is required by the dyld loader on macOS; without
    // this entry even `/usr/bin/true` fails to launch under a
    // deny-default profile.
    out.push_str("  (literal \"/\")\n");
    out.push_str(&format!("  (subpath {package_dir})\n"));
    if build_cache_isolation {
        let dependency_root = quoted_path(
            &package_dependency_root(spec, &canon_package_dir),
            "package dependency root",
        )?;
        out.push_str(&format!("  (subpath {dependency_root})\n"));
        out.push_str(&format!("  (subpath {home_node_gyp})\n"));
    } else {
        out.push_str(&format!("  (subpath {project_dir})\n"));
    }
    out.push_str("  (subpath \"/usr\")\n");
    out.push_str("  (subpath \"/bin\")\n");
    out.push_str("  (subpath \"/sbin\")\n");
    out.push_str("  (subpath \"/System\")\n");
    out.push_str("  (subpath \"/Library/Developer/CommandLineTools\")\n");
    out.push_str("  (subpath \"/Library/Preferences\")\n");
    // Apple Silicon Homebrew binaries resolve from /opt/homebrew/bin
    // into the versioned Cellar and load formula libraries through
    // /opt/homebrew/opt. Homebrew Node also loads the OpenSSL formula's
    // startup configuration. Keep the allowlist to these runtime paths;
    // other Homebrew configuration and state stay denied.
    out.push_str("  (subpath \"/opt/homebrew/bin\")\n");
    out.push_str("  (subpath \"/opt/homebrew/Cellar\")\n");
    out.push_str("  (subpath \"/opt/homebrew/opt\")\n");
    out.push_str("  (subpath \"/opt/homebrew/etc/openssl@3\")\n");
    out.push_str("  (subpath \"/private/etc\")\n");
    out.push_str("  (subpath \"/private/var/db/dyld\")\n");
    out.push_str("  (subpath \"/private/var/db/timezone\")\n");
    // `/private/var/select/sh` is consulted by `/bin/sh` on startup
    // to locate the user's preferred shell binary. Without this
    // read allow, shell scripts emit a spurious "Error opening
    // /private/var/select/sh: Operation not permitted" on stderr.
    // Harmless as a functional matter but alarming for users — deny
    // here produces an actionable test-fixture false negative.
    out.push_str("  (subpath \"/private/var/select\")\n");
    // Broad /dev read covers /dev/fd/*, /dev/stdin/stdout/stderr, and
    // the tty + random devices shells and coreutils commonly touch.
    // /dev has no secrets (raw disks etc. would need additional
    // iokit-open narrowing to expose, and those aren't granted here).
    out.push_str("  (subpath \"/dev\")\n");
    out.push_str(&format!("  (subpath {home_nvm})\n"));
    out.push_str(")\n");
    out.push('\n');

    // Secret-file deny block — overrides the broad project_dir
    // file-read* allow above for well-known secret conventions
    // (`.env`, `.npmrc`, `.aws/`, `*.pem`, etc.). SBPL last-match-
    // wins: a path covered by both the earlier allow and this deny
    // ends up denied. The per-project / per-user
    // `sandboxReadAllow` opt-in emits a follow-up
    // (allow file-read*) block AFTER this deny so specific files
    // can be exempted without disabling the whole list.
    render_secret_denies(&mut out, &canon_project_dir)?;
    render_secret_read_allow_overrides(&mut out, &spec.secret_read_allow)?;
    out.push('\n');

    // file-write*: narrow but covers the greens. Must contain the
    // package's own store dir (the compat corpus tests write markers
    // here), project `node_modules` (prisma generate),
    // `.husky` (husky install), `.lpm` (LPM's own state),
    // `~/.cache` + `~/.node-gyp` + `~/.npm` (tooling caches), and
    // `/tmp` + `$TMPDIR` — plus `/private/var/folders` since macOS's
    // `$TMPDIR` resolves to there and some tools pass the unresolved
    // form. `/dev/null` is writable so `>/dev/null` redirects work.
    out.push_str("(allow file-write*\n");
    out.push_str(&format!("  (subpath {package_dir})\n"));
    if !build_cache_isolation {
        out.push_str(&format!("  (subpath {project_node_modules})\n"));
        out.push_str(&format!("  (subpath {project_husky})\n"));
        out.push_str(&format!("  (subpath {project_lpm})\n"));
        out.push_str(&format!("  (subpath {home_cache})\n"));
        out.push_str(&format!("  (subpath {home_node_gyp})\n"));
        out.push_str(&format!("  (subpath {home_npm})\n"));
        out.push_str("  (subpath \"/tmp\")\n");
    }
    out.push_str(&format!("  (subpath {tmpdir})\n"));
    out.push_str("  (literal \"/dev/null\")\n");
    out.push_str("  (literal \"/dev/tty\")\n");
    if !build_cache_isolation {
        for e in &extras {
            out.push_str(&format!("  (subpath {e})\n"));
        }
    }
    out.push_str(")\n");
    out.push('\n');

    // Network denial is opt-in, not default. The default posture
    // (filesystem + env containment, network allowed) is the baseline;
    // strict mode (`deny_outbound_network = true`) drops the
    // `(allow network*)` line so the profile's `(deny default)`
    // opener covers every socket / bind / connect operation.
    //
    // The strict path has NO loopback exemption — lifecycle scripts
    // that legitimately need network under strict go through
    // `--no-sandbox`, `trustedDependencies`, or by dropping back to
    // `mode = "default"`.
    //
    if !deny_outbound_network {
        out.push_str("(allow network*)\n");
    }

    // node-gyp + electron-rebuild fork helper processes + basic
    // process-info introspection the dynamic linker + libSystem
    // call into. We keep the `process*` wildcard for fork/exec/info
    // but layer narrower denies on top — SBPL is last-match-wins,
    // so any deny rule emitted AFTER the wildcard overrides for
    // the specific operations it names.
    //
    // NB: SBPL does not expose `process-set-pgid` as an operation
    // name (it is not in the Seatbelt grammar; sandbox-exec rejects
    // it with "unbound variable: process-set-pgid"). The matching
    // kill-tree-escape concern is closed in
    // `lpm_sandbox::terminate_sandbox_tree` via descendant-PID
    // enumeration; the SBPL profile only narrows process-exec here.
    out.push_str("(allow process*)\n");
    // Block process-exec to the macOS automation / privilege-escalation
    // surfaces. `osascript` reaches every AppleScript-controllable app
    // through mach-lookup (which we still need to allow for libSystem),
    // `security` is the Keychain CLI, `sudo`/`su` are explicit privilege
    // boundary crossers, `open` launches GUI apps with the user's full
    // session, and `codesign` is a write-capable signing oracle. None
    // of these are legitimate post-install needs; package authors
    // wanting GUI automation should not be reaching for `osascript`
    // from a lifecycle script.
    out.push_str("(deny process-exec\n");
    out.push_str("  (literal \"/usr/bin/osascript\")\n");
    out.push_str("  (literal \"/usr/bin/security\")\n");
    out.push_str("  (literal \"/usr/bin/sudo\")\n");
    out.push_str("  (literal \"/usr/bin/su\")\n");
    out.push_str("  (literal \"/usr/bin/open\")\n");
    out.push_str("  (literal \"/usr/bin/codesign\")\n");
    out.push_str("  (subpath \"/Applications\")\n");
    out.push_str(")\n");
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

fn package_dependency_root(spec: &SandboxSpec, canonical_package_dir: &Path) -> PathBuf {
    let name_depth = spec
        .package_name
        .bytes()
        .filter(|byte| *byte == b'/')
        .count();
    canonical_package_dir
        .ancestors()
        .nth(name_depth + 1)
        .unwrap_or(canonical_package_dir)
        .to_path_buf()
}

/// Emit the `(deny file-read* ...)` block for well-known secret
/// conventions. Driven by the shared catalog in
/// [`crate::secret_paths`]; all entries are rendered project-rooted
/// at the canonicalized `project_dir` so the rule matches the form
/// the kernel sees at enforcement time.
///
/// The regex suffix family is derived from
/// [`SECRET_FILE_EXTENSIONS`] at render time: each extension
/// (`.pem`, `.tfvars.json`, …) becomes an SBPL regex
/// `^<escaped-project-dir>/.*<escaped-extension>$` anchored at the
/// project root and the file-name end. Driving both backends off
/// the same extension list (vs. one regex list + one suffix list)
/// guarantees `seatbelt::render_secret_denies` and
/// `linux_secret_overlay::enumerate_project_secrets` cover
/// identical file sets.
///
/// Path-existence is intentionally NOT checked — Seatbelt rules
/// match on path shape, not on whether the file is currently
/// present. A `.env` that the lifecycle script later creates
/// (writing to a writable parent) and then re-reads is still
/// denied because the path matches the literal rule.
fn render_secret_denies(out: &mut String, canon_project_dir: &Path) -> Result<(), SandboxError> {
    let project_str =
        canon_project_dir
            .to_str()
            .ok_or_else(|| SandboxError::ProfileRenderFailed {
                reason: format!(
                    "canon_project_dir is not valid UTF-8: {}",
                    canon_project_dir.display()
                ),
            })?;
    let project_re_escaped = regex_escape_literal_path(project_str);

    out.push_str("(deny file-read*\n");
    for rel in SECRET_LITERAL_PATHS {
        let abs = canon_project_dir.join(rel);
        let q = quoted_path(&abs, "secret_deny_literal")?;
        out.push_str(&format!("  (literal {q})\n"));
    }
    for rel in SECRET_SUBPATH_DIRS {
        let abs = canon_project_dir.join(rel);
        let q = quoted_path(&abs, "secret_deny_subpath")?;
        out.push_str(&format!("  (subpath {q})\n"));
    }
    for ext in SECRET_FILE_EXTENSIONS {
        // `.tfvars.json` → `\.tfvars\.json` — escape every dot in
        // the extension before stitching into the anchored regex.
        let escaped_ext = ext.replace('.', r"\.");
        let pattern = format!("^{project_re_escaped}/.*{escaped_ext}$");
        out.push_str(&format!("  (regex {})\n", seatbelt_regex_literal(&pattern)));
    }
    out.push_str(")\n");
    Ok(())
}

/// Emit a `(allow file-read* (literal ...))` override block for each
/// entry in [`SandboxSpec::secret_read_allow`]. SBPL last-match-wins
/// means these allows override the deny block immediately above for
/// the named files, without disabling the whole secret-deny list.
///
/// No-op when the allow list is empty (no block emitted). The
/// The loader is responsible for validating that each entry
/// is an absolute project-rooted path and rejecting traversal /
/// out-of-project entries — this renderer just emits whatever it
/// receives.
fn render_secret_read_allow_overrides(
    out: &mut String,
    allow_list: &[PathBuf],
) -> Result<(), SandboxError> {
    if allow_list.is_empty() {
        return Ok(());
    }
    out.push_str("(allow file-read*\n");
    for p in allow_list {
        let q = quoted_path(p, "secret_read_allow_override")?;
        out.push_str(&format!("  (literal {q})\n"));
    }
    out.push_str(")\n");
    Ok(())
}

/// Wrap a regex source string in the SBPL `#"..."` literal form.
/// Apple's SBPL regex literal treats `\` as a literal pass-through
/// character (NOT a Scheme escape), so `\.pem` in the source
/// reaches the regex engine unchanged. Only `"` is escaped by the
/// SBPL parser; we mirror that.
fn seatbelt_regex_literal(r: &str) -> String {
    let mut out = String::with_capacity(r.len() + 4);
    out.push_str("#\"");
    for c in r.chars() {
        match c {
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Escape regex metacharacters in a literal path string so the path
/// can be safely interpolated into a regex source. Used to anchor
/// the per-suffix rules at the canonicalized project_dir prefix
/// without the path's `.`, `(`, etc. being interpreted as regex
/// metas. Unix paths rarely contain these, but project_dirs under
/// `/private/var/folders/<uuid>/...` on macOS do (parens are
/// possible, dots are common).
fn regex_escape_literal_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    for c in path.chars() {
        match c {
            '.' | '(' | ')' | '[' | ']' | '{' | '}' | '+' | '*' | '?' | '|' | '^' | '$' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
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
    scheme_quote_strict(s, field)
}

/// Resolve `path` through symlinks + relative components so the
/// rendered Seatbelt rule matches the form the kernel uses at
/// enforcement time. macOS symlinks `/var` -> `/private/var` and
/// `/tmp` -> `/private/tmp`; rules spelled in the short form do
/// NOT match enforcement-time requests against the long form.
///
/// Behavior:
/// - **Success**: return the canonical path.
/// - **NotFound** (the path doesn't exist on the host — synthetic
///   test spec, or `extra_write_dirs` entry the script will create
///   on first run): passthrough the input unchanged. The kernel's
///   own symlink resolution still applies at enforcement time, so
///   paths with no symlinks in their component chain still match.
///   Paths that *do* traverse a symlink but don't exist lose
///   symlink resolution — that surfaces as a runtime denial the
///   first time a script touches the path, which is the correct
///   "user-visible failure" shape for a misconfigured spec.
/// - **Any other I/O error** (EIO from a flaky NFS mount, EACCES
///   on a parent component, ELOOP, etc.): fail loud as
///   `ProfileRenderFailed`. The earlier `unwrap_or_else(|_| ...)`
///   silently treated these as passthrough, which produced a rule
///   spelled `/var/folders/...` while the kernel enforced against
///   `/private/var/folders/...` — a hidden-state contract break
///   that manifests as legitimate operations being denied.
fn canonicalize_or_passthrough(path: &Path, field: &str) -> Result<PathBuf, SandboxError> {
    match std::fs::canonicalize(path) {
        Ok(p) => Ok(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(e) => Err(SandboxError::ProfileRenderFailed {
            reason: format!(
                "canonicalize {field} ({}) failed: {e} (kind: {:?}) — likely a \
                 transient I/O error (NFS mount glitch, EACCES on a parent, \
                 symlink loop). Refusing to render a profile with an \
                 un-resolved base path; that would silently mis-match \
                 enforcement-time symlink resolution on macOS.",
                path.display(),
                e.kind()
            ),
        }),
    }
}

/// Escape `s` into a quoted SBPL string literal in one pass,
/// failing on any input character that would perturb the SBPL
/// parser before the SBPL escape rules can contain it.
///
/// **Rejected characters (returns `ProfileRenderFailed`):**
/// - C0 controls (`0x00..=0x1F`) including LF, CR, TAB, NUL
/// - DEL (`0x7F`)
/// - C1 controls (`0x80..=0x9F`)
///
/// POSIX disallows NUL in pathnames outright; the other control
/// bytes are *technically permitted* by the filesystem but never
/// appear in legitimate path content, and any one of them in a
/// `sandboxWriteDirs[i]` entry is a strong injection signal. LF
/// in particular was the documented Seatbelt-injection vector —
/// even with `"` and `\` already escaped, a literal newline could
/// terminate the rendered string in parsers that treat LF as a
/// token boundary. We refuse the whole control range uniformly so
/// callers can't bypass via a CR/TAB/NUL variant.
///
/// **Passed through unchanged:** regular punctuation that some
/// sources flag as Scheme-meta (`(`, `)`, `;`, `` ` ``, `'`) — per
/// the SBPL grammar these are valid data inside a `"..."` string
/// literal, and rejecting them would refuse legitimate macOS paths
/// (e.g. `/Users/<n>/work (proj)/`).
///
/// **Escaped:** `"` becomes `\"` and `\` becomes `\\` per the
/// Scheme-like SBPL string literal syntax.
///
/// The error surfaces with a hex code-point hint (`U+XXXX`) so the
/// offending byte itself never reaches log output, and names the
/// field so the caller knows which path was rejected.
fn scheme_quote_strict(s: &str, field: &str) -> Result<String, SandboxError> {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for (idx, c) in s.char_indices() {
        let code = c as u32;
        if code <= 0x1F || code == 0x7F || (0x80..=0x9F).contains(&code) {
            return Err(SandboxError::ProfileRenderFailed {
                reason: format!(
                    "{field} contains a control character at byte {idx} \
                     (U+{code:04X}); paths with embedded control bytes \
                     are refused at profile render time because they \
                     can perturb SBPL string parsing",
                ),
            });
        }
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
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
pub(crate) fn render_logonly_profile(
    spec: &SandboxSpec,
    deny_outbound_network: bool,
) -> Result<String, SandboxError> {
    // Build the Enforce profile body first — these are the rules
    // that should remain SILENT under LogOnly.
    let enforce_body = render_profile(spec, deny_outbound_network)?;
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
            secret_read_allow: Vec::new(),
            extra_write_dirs: Vec::new(),
        }
    }

    #[test]
    fn profile_starts_with_deny_default() {
        let p = render_profile(&spec(), false).unwrap();
        assert!(p.starts_with("(version 1)\n(deny default)\n"));
    }

    #[test]
    fn profile_contains_package_dir_in_both_read_and_write() {
        let p = render_profile(&spec(), false).unwrap();
        // Appears once in file-read* block, once in file-write* block.
        assert_eq!(
            p.matches("/lpm-store/prisma@5.22.0").count(),
            2,
            "package_dir must appear in both read and write allow lists — got profile:\n{p}"
        );
    }

    #[test]
    fn profile_contains_project_subpaths_for_writable_greens() {
        let p = render_profile(&spec(), false).unwrap();
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
        let p = render_profile(&spec(), false).unwrap();
        assert!(p.contains("/home/u/.cache"));
        assert!(p.contains("/home/u/.node-gyp"));
        assert!(p.contains("/home/u/.npm"));
        assert!(p.contains("/home/u/.nvm/versions"));
    }

    #[test]
    fn profile_allows_apple_silicon_homebrew_runtime_dependencies_without_broad_opt_access() {
        let p = render_profile(&spec(), false).unwrap();
        assert!(p.contains("(subpath \"/opt/homebrew/Cellar\")"));
        assert!(p.contains("(subpath \"/opt/homebrew/opt\")"));
        assert!(p.contains("(subpath \"/opt/homebrew/bin\")"));
        assert!(p.contains("(subpath \"/opt/homebrew/etc/openssl@3\")"));
        assert!(!p.contains("(subpath \"/opt/homebrew\")\n"));
        assert!(!p.contains("(subpath \"/opt/homebrew/etc\")\n"));
    }

    #[test]
    fn profile_contains_temp_paths() {
        let p = render_profile(&spec(), false).unwrap();
        assert!(p.contains("/tmp"));
        assert!(p.contains("/var/folders/xx/T"));
    }

    #[test]
    fn profile_allows_network_under_default_mode() {
        // Network denial is opt-in. Default mode
        // (`deny_outbound_network = false`) emits `(allow network*)`
        // and permits outbound network from the lifecycle script. A
        // regression that drops the line under default mode would
        // break sharp / prisma / puppeteer / `@lpm-registry/cli` and
        // every other legitimate install-time downloader.
        let p = render_profile(&spec(), false).unwrap();
        assert!(
            p.contains("(allow network*)"),
            "default mode must emit `(allow network*)` so install-time \
             downloads work: {p}"
        );
    }

    #[test]
    fn profile_denies_network_under_strict_mode() {
        // Strict path: `deny_outbound_network = true` drops the
        // `(allow network*)` line so the opening `(deny default)`
        // covers every socket / bind / connect. No loopback
        // exemption. A regression that re-adds `(allow network*)`
        // when strict is engaged would silently break the strict
        // contract; this test catches it.
        let p = render_profile(&spec(), true).unwrap();
        assert!(
            !p.contains("(allow network"),
            "strict mode (`deny_outbound_network=true`) must NOT \
             contain any `(allow network*)` or narrower \
             `(allow network ...)` form: {p}"
        );
    }

    #[test]
    fn build_cache_profile_omits_project_and_home_cache_writes() {
        let s = spec();
        let profile = render_profile_with_isolation(&s, true, true).unwrap();
        let write_section = profile
            .split("(allow file-write*\n")
            .nth(1)
            .unwrap()
            .split("\n)\n")
            .next()
            .unwrap();

        assert!(write_section.contains("/lpm-store/prisma@5.22.0"));
        assert!(write_section.contains("/var/folders/xx/T"));
        assert!(!write_section.contains(".husky"));
        assert!(!write_section.contains(".node-gyp"));
        assert!(!write_section.contains("node_modules"));
    }

    #[test]
    fn profile_allows_process_and_signal_primitives() {
        let p = render_profile(&spec(), false).unwrap();
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
        let p = render_profile(&spec(), false).unwrap();
        // The secret-deny block legitimately mentions
        // `.ssh` and `.aws` as project-rooted subpaths — those are
        // DENY rules and exactly what we want. The check below
        // scopes the assertion to the ALLOW blocks: any allow
        // rule mentioning `.ssh` / `.aws` / Keychains would be a
        // security regression.
        let allow_section = extract_allow_blocks(&p);
        assert!(
            !allow_section.contains("/.ssh"),
            "ssh must never appear in an allow rule: {p}"
        );
        assert!(
            !allow_section.contains("/.aws"),
            "aws must never appear in an allow rule: {p}"
        );
        assert!(
            !allow_section.contains("(subpath \"/Library/Keychains\")"),
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

    /// Concatenate the bodies of every `(allow ... )` block in the
    /// profile. Used by allow-only path assertions that must NOT
    /// be confused by deny-block mentions of the same path
    /// (the secret deny block legitimately references
    /// `.ssh`, `.aws`, etc. as project-rooted denies).
    fn extract_allow_blocks(profile: &str) -> String {
        let mut out = String::new();
        let mut tail = profile;
        while let Some(idx) = tail.find("(allow ") {
            tail = &tail[idx..];
            // Find the closing `)` at column 0 (the `\n)\n` form
            // used by every multiline allow block) or the end of
            // the single-line rule.
            if let Some(end) = tail.find("\n)\n") {
                out.push_str(&tail[..end + 3]);
                tail = &tail[end + 3..];
            } else if let Some(eol) = tail.find('\n') {
                // Single-line rule like `(allow process*)`.
                out.push_str(&tail[..eol]);
                tail = &tail[eol..];
            } else {
                out.push_str(tail);
                break;
            }
        }
        out
    }

    #[test]
    fn profile_includes_extra_write_dirs_verbatim() {
        let mut s = spec();
        s.extra_write_dirs = vec![
            PathBuf::from("/home/u/proj/build-output"),
            PathBuf::from("/home/u/.cache/ms-playwright"),
        ];
        let p = render_profile(&s, false).unwrap();
        assert!(p.contains("/home/u/proj/build-output"));
        assert!(p.contains("/home/u/.cache/ms-playwright"));
    }

    #[test]
    fn profile_rejects_relative_extra_write_dirs_at_render_time() {
        let mut s = spec();
        s.extra_write_dirs = vec![PathBuf::from("relative/path")];
        match render_profile(&s, false) {
            Err(SandboxError::ProfileRenderFailed { reason }) => {
                assert!(reason.contains("extra_write_dirs[0]"));
                assert!(reason.contains("absolute"));
            }
            other => panic!("expected ProfileRenderFailed, got {other:?}"),
        }
    }

    #[test]
    fn scheme_quote_strict_escapes_quotes_and_backslashes() {
        let q = |s: &str| scheme_quote_strict(s, "test").unwrap();
        assert_eq!(q(r#"simple"#), r#""simple""#);
        assert_eq!(q(r#"has"quote"#), r#""has\"quote""#);
        assert_eq!(q(r"has\slash"), r#""has\\slash""#);
        assert_eq!(q(r#"both"and\slash"#), r#""both\"and\\slash""#);
    }

    #[test]
    fn scheme_quote_strict_handles_unicode() {
        assert_eq!(scheme_quote_strict("café", "test").unwrap(), r#""café""#);
    }

    #[test]
    fn scheme_quote_strict_rejects_embedded_newline() {
        // Headline SBPL-injection vector: a sandboxWriteDirs entry
        // like `/tmp/")(allow file-read* (subpath \"/Users\")(deny default)\n//`
        // carries a literal LF that would otherwise sit inside the
        // rendered string. Strict refusal here makes the render
        // fail loud before sandbox-exec ever sees the bytes.
        let payload = "/tmp/\")(allow file-read* (subpath \"/Users\")\n//";
        let err = scheme_quote_strict(payload, "extra_write_dirs[0]")
            .expect_err("must refuse embedded LF");
        match err {
            SandboxError::ProfileRenderFailed { reason } => {
                assert!(reason.contains("extra_write_dirs[0]"), "got: {reason}");
                assert!(reason.contains("U+000A"), "got: {reason}");
            }
            other => panic!("expected ProfileRenderFailed, got {other:?}"),
        }
    }

    #[test]
    fn scheme_quote_strict_rejects_tab_cr_nul_and_c1_controls() {
        for bad in &["a\tb", "a\rb", "a\0b", "a\u{0085}b", "a\u{009F}b"] {
            scheme_quote_strict(bad, "test").expect_err(&format!("must refuse {bad:?}"));
        }
    }

    #[test]
    fn scheme_quote_strict_passes_through_scheme_punctuation_inside_paths() {
        // Parens / semicolons / apostrophes / backticks are legitimate
        // path content on macOS (e.g. `/Users/x/code (work)/'thing'`).
        // The strict gate must not refuse them — only control bytes.
        let q = scheme_quote_strict("/Users/x/code (work)/'thing'`", "project_dir").expect("ok");
        assert!(q.starts_with('"') && q.ends_with('"'));
        assert!(q.contains("(work)"));
        assert!(q.contains("'thing'"));
        assert!(q.contains('`'));
    }

    #[test]
    fn profile_denies_high_risk_process_exec_targets() {
        let p = render_profile(&spec(), false).unwrap();
        // M22: narrow process-exec denies for AppleScript automation,
        // Keychain CLI, privilege boundaries, GUI app launching, and
        // the signing oracle. The deny clause must follow the
        // `(allow process*)` wildcard so SBPL last-match-wins
        // overrides for these specific binaries.
        let allow_idx = p.find("(allow process*)").expect("allow process* present");
        let deny_idx = p
            .find("(deny process-exec")
            .expect("narrow deny process-exec block present");
        assert!(
            deny_idx > allow_idx,
            "(deny process-exec ...) must come AFTER (allow process*) under last-match-wins: {p}"
        );
        for needed in &[
            "/usr/bin/osascript",
            "/usr/bin/security",
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/open",
            "/usr/bin/codesign",
            "/Applications",
        ] {
            assert!(
                p.contains(needed),
                "expected narrow process-exec deny for {needed}: {p}",
            );
        }
    }

    #[test]
    fn profile_forbidden_path_probe_is_denied_under_deny_default() {
        // `cat ~/.ssh/id_rsa`: the path is never in the allow list,
        // and the profile begins with (deny default), so Seatbelt
        // blocks the read. This test asserts the profile's structural
        // shape — the integration
        // test under tests/seatbelt_integration.rs actually shells
        // out to sandbox-exec to confirm runtime behavior.
        //
        // The secret-deny block additionally names `.ssh`
        // as a project-rooted DENY (defense-in-depth for the
        // `<project>/.ssh` case); the assertion below scopes to the
        // allow section to confirm no ALLOW rule covers `.ssh`.
        let p = render_profile(&spec(), false).unwrap();
        assert!(p.contains("(deny default)"));
        let allow_section = extract_allow_blocks(&p);
        assert!(
            !allow_section.contains(".ssh"),
            "no allow rule may cover .ssh: {p}"
        );
    }

    #[test]
    fn logonly_profile_starts_with_permissive_report_fallback() {
        // `(allow (with report) default)` is the FIRST rule so every
        // operation matches as a baseline; Enforce rules later in the
        // profile override to silent allows where they apply. Pin the
        // ordering invariant since the semantic depends on it.
        let p = render_logonly_profile(&spec(), false).unwrap();
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
        let p = render_logonly_profile(&spec(), false).unwrap();
        assert!(
            !p.contains("(deny default)"),
            "LogOnly profile must NOT contain (deny default): {p}"
        );
    }

    #[test]
    fn logonly_profile_preserves_enforce_allow_rules() {
        // The Enforce allow lists (file-read*, file-write*, process*,
        // mach-lookup, etc.) still appear. Under SBPL last-match-wins
        // semantics, these override the permissive fallback for their
        // covered paths — operations matching Enforce rules are silent
        // allows, identical to Enforce behavior.
        //
        // Under default mode the Enforce profile emits `(allow
        // network*)` (network allowed); the LogOnly profile inherits
        // the same body, so the rule shows up here too. The mirror
        // test below pins the strict-mode case.
        let p = render_logonly_profile(&spec(), false).unwrap();
        assert!(p.contains("(allow file-read*"));
        assert!(p.contains("(allow file-write*"));
        assert!(
            p.contains("(allow network*)"),
            "default mode — LogOnly inherits Enforce body which \
             contains `(allow network*)`: {p}"
        );
        assert!(p.contains("(allow process*)"));
        assert!(p.contains("(allow mach-lookup)"));
    }

    #[test]
    fn logonly_profile_under_strict_mode_omits_network_allow() {
        // Mirror of `profile_denies_network_under_strict_mode` for
        // the LogOnly path. The Enforce body that LogOnly inherits
        // drops `(allow network*)` when `deny_outbound_network =
        // true`. A regression that re-adds it would silently break
        // the strict contract on the diagnostic LogOnly mode.
        let p = render_logonly_profile(&spec(), true).unwrap();
        assert!(
            !p.contains("(allow network"),
            "strict mode LogOnly profile must NOT contain any \
             `(allow network*)` or narrower `(allow network ...)` \
             form: {p}"
        );
    }

    #[test]
    fn logonly_profile_package_dir_and_writable_paths_match_enforce() {
        let enforce = render_profile(&spec(), false).unwrap();
        let logonly = render_logonly_profile(&spec(), false).unwrap();
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
    fn canonicalize_passes_through_nonexistent_paths() {
        // Unit-test specs use synthetic paths (`/lpm-store/prisma@…`,
        // `/home/u/proj`) that don't exist on the host. The canonical
        // form falls back to the original path so render_profile() is
        // testable without staging real dirs. Pin this so a future
        // tightening of `canonicalize_or_passthrough` that fails on
        // NotFound (rather than only on real I/O errors) is caught.
        let p = render_profile(&spec(), false).unwrap();
        assert!(p.contains("/lpm-store/prisma@5.22.0"));
        assert!(p.contains("/home/u/proj"));
    }

    #[test]
    fn canonicalize_resolves_symlink_in_base_path_to_enforcement_form() {
        // Regression for the symlink-resolution contract: the
        // rendered rule must match the form the kernel uses at
        // enforcement time. We stage a real symlink (`link -> target`)
        // inside a tempdir and pass `link` as `spec.tmpdir`; the
        // rendered profile must contain the resolved `target`, NOT
        // the `link` path. This is the same shape as the
        // `/var/folders/…` → `/private/var/folders/…` resolution
        // that the production code path relies on every install.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("real-tmpdir");
        std::fs::create_dir(&target).unwrap();
        let link = tmp.path().join("link-tmpdir");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // Canonicalize the target up front so we compare against the
        // form `std::fs::canonicalize` actually produces (on macOS
        // the tempdir itself lives under `/var/folders/...` which
        // resolves to `/private/var/folders/...`).
        let canonical_target = std::fs::canonicalize(&target).unwrap();

        let mut s = spec();
        s.tmpdir = link.clone();

        let p = render_profile(&s, false).unwrap();
        assert!(
            p.contains(canonical_target.to_str().unwrap()),
            "rendered profile must contain the resolved tmpdir target \
             {canonical_target:?} — kernel enforces against the resolved \
             form, so a rule spelled with the un-resolved symlink path \
             would silently mis-match: {p}"
        );
        assert!(
            !p.contains(link.to_str().unwrap()),
            "rendered profile must NOT contain the un-resolved symlink \
             path {link:?} — it would never match at enforcement time \
             and produces silent denials: {p}"
        );
    }

    #[test]
    fn canonicalize_fails_loud_on_io_error_for_base_path() {
        // A base path whose canonicalize fails with a *non-NotFound*
        // error (EACCES on a parent component, EIO from a flaky NFS
        // mount, ELOOP) must produce a `ProfileRenderFailed` error
        // rather than silently passing through to a wrong-form rule.
        //
        // We stage this with a symlink loop: `loop_a -> loop_b ->
        // loop_a`. `canonicalize` returns `ErrorKind::FilesystemLoop`
        // (or `Other` on older stdlib), which is neither `Ok` nor
        // `NotFound`. The earlier `unwrap_or_else(|_| ...)` would
        // have silently returned the loop path and rendered a
        // profile that the kernel can't match against; this test
        // pins the fail-loud behavior.
        let tmp = tempfile::tempdir().unwrap();
        let loop_a = tmp.path().join("loop_a");
        let loop_b = tmp.path().join("loop_b");
        std::os::unix::fs::symlink(&loop_b, &loop_a).unwrap();
        std::os::unix::fs::symlink(&loop_a, &loop_b).unwrap();

        let mut s = spec();
        s.tmpdir = loop_a;

        match render_profile(&s, false) {
            Err(SandboxError::ProfileRenderFailed { reason }) => {
                assert!(
                    reason.contains("canonicalize tmpdir"),
                    "error must identify the failing field: {reason}"
                );
            }
            other => panic!("expected ProfileRenderFailed on canonicalize loop, got {other:?}"),
        }
    }

    #[test]
    fn logonly_profile_propagates_render_errors_from_enforce() {
        // If the Enforce profile can't render (e.g. relative extra
        // write dir), LogOnly must fail with the same error variant —
        // we don't want LogOnly masking a configuration bug that
        // Enforce would have surfaced.
        let mut s = spec();
        s.extra_write_dirs = vec![PathBuf::from("relative/path")];
        match render_logonly_profile(&s, false) {
            Err(SandboxError::ProfileRenderFailed { reason }) => {
                assert!(reason.contains("extra_write_dirs[0]"));
            }
            other => panic!("expected ProfileRenderFailed, got {other:?}"),
        }
    }

    // ── Secret-file deny block ──────────────────────────────────────

    /// The deny block appears AFTER the broad
    /// `(allow file-read* (subpath project_dir))` rule. SBPL is
    /// last-match-wins; reversing the order would make the deny a
    /// no-op.
    #[test]
    fn secret_deny_block_comes_after_broad_file_read_allow() {
        let p = render_profile(&spec(), false).unwrap();
        let allow_idx = p
            .find("(allow file-read*")
            .expect("must contain file-read* allow");
        let deny_idx = p
            .find("(deny file-read*")
            .expect("must contain file-read* deny");
        assert!(
            deny_idx > allow_idx,
            "deny block must follow the broad allow for last-match-wins to fire:\n{p}"
        );
    }

    /// `.env` is the canonical dotenv file; lifecycle scripts have no
    /// legitimate read need for it.
    #[test]
    fn profile_denies_dotenv_at_project_root() {
        let p = render_profile(&spec(), false).unwrap();
        assert!(
            p.contains(r#"(literal "/home/u/proj/.env")"#),
            "profile must deny project-rooted .env: {p}"
        );
    }

    /// `.env.local`, `.env.production`, etc. are explicitly
    /// enumerated rather than regex-matched for grep-ability and
    /// to avoid over-matching siblings.
    #[test]
    fn profile_denies_env_variant_literals() {
        let p = render_profile(&spec(), false).unwrap();
        for variant in [
            ".env.local",
            ".env.development",
            ".env.development.local",
            ".env.production",
            ".env.production.local",
            ".env.staging",
            ".env.test",
            ".env.test.local",
            ".envrc",
        ] {
            let lit = format!(r#"(literal "/home/u/proj/{variant}")"#);
            assert!(
                p.contains(&lit),
                "profile must deny project-rooted {variant}: {p}"
            );
        }
    }

    /// `.npmrc` is the npm auth-token file; routinely commits or
    /// drops at the project root and is the leak vector M40 closed
    /// at the auth-matching layer.
    #[test]
    fn profile_denies_npmrc() {
        let p = render_profile(&spec(), false).unwrap();
        assert!(p.contains(r#"(literal "/home/u/proj/.npmrc")"#));
    }

    /// `.git/config` carries credential URLs (`https://user:pass@host`).
    #[test]
    fn profile_denies_git_config_and_credentials() {
        let p = render_profile(&spec(), false).unwrap();
        assert!(p.contains(r#"(literal "/home/u/proj/.git/config")"#));
        assert!(p.contains(r#"(literal "/home/u/proj/.git/credentials")"#));
    }

    /// `.netrc` / `_netrc` (Windows form) hold http auth for curl,
    /// git over https, etc.
    #[test]
    fn profile_denies_netrc_forms() {
        let p = render_profile(&spec(), false).unwrap();
        assert!(p.contains(r#"(literal "/home/u/proj/.netrc")"#));
        assert!(p.contains(r#"(literal "/home/u/proj/_netrc")"#));
    }

    /// Conventionally-committed SSH key files. Project-root only —
    /// the canonical location `~/.ssh/id_rsa` is already covered by
    /// the no-blanket-home rule (`.ssh` isn't in any allow subpath).
    #[test]
    fn profile_denies_ssh_keys_at_project_root() {
        let p = render_profile(&spec(), false).unwrap();
        for k in [
            "id_rsa",
            "id_rsa.pub",
            "id_ecdsa",
            "id_ed25519",
            "id_ed25519.pub",
            "id_dsa",
        ] {
            let lit = format!(r#"(literal "/home/u/proj/{k}")"#);
            assert!(p.contains(&lit), "profile must deny {k}: {p}");
        }
    }

    /// `.ssh`, `.aws`, `.kube` etc. are denied as whole subpaths —
    /// `.aws/credentials`, `.kube/config`, every nested file is
    /// unreadable.
    #[test]
    fn profile_denies_credential_subpath_dirs() {
        let p = render_profile(&spec(), false).unwrap();
        for d in [
            ".ssh",
            ".aws",
            ".kube",
            ".gcp",
            ".terraform",
            "secrets",
            "secret",
        ] {
            let sub = format!(r#"(subpath "/home/u/proj/{d}")"#);
            assert!(p.contains(&sub), "profile must deny {d} subpath: {p}");
        }
    }

    /// `*.pem`, `*.key`, `*.pfx`, `*.p12` regex denies at any depth.
    /// The anchored regex must contain both `^/home/u/proj/` (the
    /// escaped project prefix) and the suffix.
    #[test]
    fn profile_denies_pem_and_key_files_via_regex() {
        let p = render_profile(&spec(), false).unwrap();
        for suffix in [r"\.pem", r"\.key", r"\.pfx", r"\.p12"] {
            // Project_dir `/home/u/proj` has no regex metas, so the
            // anchored regex literal is `^/home/u/proj/.*\.pem$` etc.
            let needle = format!(r#"#"^/home/u/proj/.*{suffix}$""#);
            assert!(
                p.contains(&needle),
                "profile must contain regex {needle}: {p}"
            );
        }
    }

    /// `*.tfstate` and `*.tfvars` regex denies — terraform state
    /// routinely contains plaintext secrets.
    #[test]
    fn profile_denies_terraform_state_and_vars_via_regex() {
        let p = render_profile(&spec(), false).unwrap();
        assert!(p.contains(r#"#"^/home/u/proj/.*\.tfstate$""#));
        assert!(p.contains(r#"#"^/home/u/proj/.*\.tfvars$""#));
        assert!(p.contains(r#"#"^/home/u/proj/.*\.tfvars\.json$""#));
    }

    /// Source files are NOT denied — the deny list targets secret
    /// conventions only. A `src/index.ts` or `lib/foo.js` stays
    /// readable.
    #[test]
    fn profile_does_not_deny_source_files() {
        let p = render_profile(&spec(), false).unwrap();
        assert!(
            !p.contains(r#"(literal "/home/u/proj/src/index.ts")"#),
            "source files must not appear in the deny block: {p}"
        );
        // `src/`, `lib/`, `app/`, etc. are never in any deny rule.
        for dir in ["src", "lib", "app", "pages", "components", "tests"] {
            let sub = format!(r#"(subpath "/home/u/proj/{dir}")"#);
            assert!(
                !p.contains(&sub) || !is_under_deny_block(&p, &sub),
                "{dir} subpath must not appear inside the deny block: {p}"
            );
        }
    }

    /// Helper: is the given needle inside the `(deny file-read* ... )`
    /// block? Splits on the deny opener and the next `)` at column 0.
    fn is_under_deny_block(profile: &str, needle: &str) -> bool {
        let Some(start) = profile.find("(deny file-read*") else {
            return false;
        };
        let tail = &profile[start..];
        // The deny block ends at the first `)\n` line (the rules
        // inside are 2-space-indented; the closing `)` is column 0).
        let end = tail.find("\n)\n").unwrap_or(tail.len());
        tail[..end].contains(needle)
    }

    /// LogOnly profile inherits the secret-deny block from the
    /// Enforce body. Last-match-wins still applies — the deny
    /// overrides the permissive-with-report fallback for the named
    /// secret paths.
    #[test]
    fn logonly_profile_inherits_secret_deny_block() {
        let p = render_logonly_profile(&spec(), false).unwrap();
        assert!(p.contains("(deny file-read*"));
        assert!(p.contains(r#"(literal "/home/u/proj/.env")"#));
        assert!(p.contains(r#"(subpath "/home/u/proj/.aws")"#));
        assert!(p.contains(r#"#"^/home/u/proj/.*\.pem$""#));
    }

    /// Strict mode (deny_outbound_network=true) does NOT change the
    /// secret-deny block — the denies fire regardless of strict.
    #[test]
    fn secret_deny_block_unchanged_under_strict_mode() {
        let default = render_profile(&spec(), false).unwrap();
        let strict = render_profile(&spec(), true).unwrap();
        // The (deny file-read* ... ) block has identical body in
        // both. Diff is only the network rule.
        let extract_deny = |s: &str| {
            let start = s.find("(deny file-read*").unwrap();
            let tail = &s[start..];
            let end = tail.find("\n)\n").unwrap();
            tail[..end + 3].to_string()
        };
        assert_eq!(extract_deny(&default), extract_deny(&strict));
    }

    /// wiring contract: when `secret_read_allow` is non-empty,
    /// an additional `(allow file-read* ...)` block is emitted AFTER
    /// the deny block. Last-match-wins means the named files become
    /// readable again while the rest of the deny list still applies.
    #[test]
    fn secret_read_allow_emits_allow_override_after_deny() {
        let mut s = spec();
        s.secret_read_allow = vec![PathBuf::from("/home/u/proj/.env")];
        let p = render_profile(&s, false).unwrap();
        let deny_idx = p.find("(deny file-read*").unwrap();
        // The override block opens with `(allow file-read*` AFTER the
        // first such block (the broad project_dir allow). Find the
        // SECOND `(allow file-read*` and assert it's after deny.
        let first_allow = p.find("(allow file-read*").unwrap();
        let second_allow_offset = p[first_allow + 1..]
            .find("(allow file-read*")
            .expect("must have override allow when secret_read_allow non-empty");
        let second_allow = first_allow + 1 + second_allow_offset;
        assert!(
            second_allow > deny_idx,
            "override allow must come after the deny:\n{p}"
        );
        // The override block names the exempted literal.
        let override_block = &p[second_allow..];
        assert!(
            override_block.contains(r#"(literal "/home/u/proj/.env")"#),
            "override block must name the allowed file:\n{p}"
        );
    }

    /// Empty `secret_read_allow` — no override block emitted (
    /// default state).
    #[test]
    fn empty_secret_read_allow_emits_no_override_block() {
        let p = render_profile(&spec(), false).unwrap();
        // Exactly ONE `(allow file-read*` (the broad project_dir
        // allow) and ZERO follow-up overrides.
        let count = p.matches("(allow file-read*").count();
        assert_eq!(count, 1, "no override block expected:\n{p}");
    }

    /// Regex escape: project_dirs under
    /// `/private/var/folders/<uuid>/T/...` (the macOS tempdir form
    /// LogOnly tests stage) contain `.` characters that must be
    /// escaped to `\.` in the regex source, or the dot becomes a
    /// wildcard.
    #[test]
    fn regex_escape_literal_path_escapes_dots_and_parens() {
        assert_eq!(
            regex_escape_literal_path("/private/var/folders/xx.tmp/T"),
            r"/private/var/folders/xx\.tmp/T"
        );
        assert_eq!(
            regex_escape_literal_path("/path/with (paren)/dir"),
            r"/path/with \(paren\)/dir"
        );
        assert_eq!(
            regex_escape_literal_path("/safe/normal/path"),
            "/safe/normal/path"
        );
    }

    /// SBPL regex literal: `\` passes through (not a Scheme escape),
    /// `"` is escaped to `\"`. Mirror of Apple bsd.sb convention.
    #[test]
    fn seatbelt_regex_literal_escapes_only_quotes() {
        assert_eq!(
            seatbelt_regex_literal(r"^/home/u/proj/.*\.pem$"),
            r##"#"^/home/u/proj/.*\.pem$""##
        );
        assert_eq!(
            seatbelt_regex_literal(r#"contains "quote""#),
            r#"#"contains \"quote\"""#
        );
    }

    /// Sanity: the deny block is well-formed Scheme — opens with
    /// `(deny file-read*`, closes with `)`, no orphaned tokens.
    #[test]
    fn secret_deny_block_is_well_formed() {
        let p = render_profile(&spec(), false).unwrap();
        let start = p.find("(deny file-read*").unwrap();
        let tail = &p[start..];
        let end = tail.find("\n)\n").unwrap();
        let block = &tail[..end + 3];
        // Balanced parens within the block.
        let opens = block.matches('(').count();
        let closes = block.matches(')').count();
        assert_eq!(opens, closes, "unbalanced parens in deny block:\n{block}");
    }
}
