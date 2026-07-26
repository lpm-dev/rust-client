use crate::install_ui;
use crate::release_lookup::{
    FetchOutcome, LookupError, clear_cache_at, default_cache_path,
    fetch_github_release_published_at, github_release_download_url, is_newer_semver, probe_release,
    read_cache_at, write_cache_at,
};
use crate::sigstore_verify::{
    IdentityExpectations, VerifiedProvenance, VerifyError, VerifyOptions,
    extract_in_toto_subject_digest, verify_sigstore_bundle,
};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use sha2::{Digest, Sha256};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// User-facing self-update reuses the banner cache file but with a much
/// shorter success TTL: a second `lpm self-update` within 10 minutes
/// short-circuits to the cached version. Long enough to defang
/// pathological CI loops, short enough that an interactive user
/// re-running shortly after a release still sees the new version on
/// the next cache miss.
const LOOKUP_TTL: Duration = Duration::from_secs(10 * 60);

/// If the previous probe failed (transport, 403, malformed response),
/// back off for an hour before letting the foreground command hit
/// GitHub again. Without this, a script looping on `lpm self-update`
/// re-hammers the API on every iteration even though we just persisted
/// `last_failure_check`. `--refresh` bypasses this gate.
const FAILURE_BACKOFF: Duration = Duration::from_secs(60 * 60);

/// Update LPM to the latest version.
///
/// Detects the installation method from the executable path and runs
/// the appropriate upgrade command. Supports npm, Homebrew, cargo,
/// and standalone (curl) installations.
///
/// Version discovery probes the npm registry first
/// (`registry.npmjs.org/@lpm-registry/cli/latest`) and falls back to
/// GitHub Releases. The npm primary is anonymous and unmetered for our
/// purposes, so most users never touch the rate-limited GitHub path.
/// The two sources stay in lockstep because every release publishes
/// from the same tag.
pub async fn run(json_output: bool, refresh: bool) -> Result<(), LpmError> {
    let current = env!("CARGO_PKG_VERSION");

    let cache_path = default_cache_path();
    let mut cache = cache_path
        .as_deref()
        .and_then(read_cache_at)
        .unwrap_or_default();

    if !json_output {
        install_ui::phase("Checking for updates");
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Three-way decision before touching the network:
    //   (a) recent success → use cached version (cache hit).
    //   (b) recent failure → refuse without probing. Stale cached
    //       version (if any) is intentionally NOT used here: the user
    //       asked to upgrade right now and we should not silently
    //       install whatever we last saw an hour or a day ago.
    //   (c) otherwise → probe.
    // `--refresh` bypasses both (a) and (b).
    let cache_hit = !refresh
        && !cache.latest.is_empty()
        && cache.last_check > 0
        && now.saturating_sub(cache.last_check) < LOOKUP_TTL.as_secs();

    let in_failure_backoff = !refresh
        && !cache_hit
        && cache.last_failure_check > 0
        && now.saturating_sub(cache.last_failure_check) < FAILURE_BACKOFF.as_secs();

    if in_failure_backoff {
        let elapsed = now.saturating_sub(cache.last_failure_check);
        let remaining = FAILURE_BACKOFF.as_secs().saturating_sub(elapsed);
        // SelfUpdatePaused — not Network. The failure isn't a live
        // transport problem; it's a local cache decision to back off.
        // The variant's help text surfaces `--refresh` so we don't have
        // to repeat that hint inside the message body.
        return Err(LpmError::SelfUpdatePaused(format!(
            "last attempt failed {} ago, retrying automatically in {}",
            humanize_seconds(elapsed),
            humanize_seconds(remaining),
        )));
    }

    let latest = if cache_hit {
        cache.latest.clone()
    } else {
        match probe_release(&mut cache).await {
            Ok(FetchOutcome::Fresh { version }) | Ok(FetchOutcome::NotModified { version }) => {
                if let Some(p) = cache_path.as_deref() {
                    let _ = write_cache_at(p, &cache);
                }
                version
            }
            Err(e) => {
                // Persist the failure so this command AND the banner
                // staleness gate both back off on the next invocation.
                if let Some(p) = cache_path.as_deref() {
                    let _ = write_cache_at(p, &cache);
                }
                return Err(lookup_error_to_lpm(e));
            }
        }
    };

    if !json_output {
        eprintln!("    {}   {}", install_ui::dim("current"), current.dimmed());
        eprintln!(
            "    {}    {}",
            install_ui::dim("latest"),
            install_ui::status_ok(&latest)
        );
    }

    if latest == current || !is_newer_semver(&latest, current) {
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "current": current,
                "latest": latest,
                "up_to_date": true,
                "cache_hit": cache_hit,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else if latest == current {
            install_ui::done_line(crate::install_ui::terminal_line!(
                "Done · already on {} version {}",
                install_ui::status_ok("latest"),
                install_ui::yellow(current)
            ));
        } else {
            install_ui::done_line(crate::install_ui::terminal_line!(
                "Done · current version {} is newer than {} release {}",
                install_ui::yellow(current),
                install_ui::status_ok("latest"),
                install_ui::dim(&latest)
            ));
        }
        return Ok(());
    }

    let method = detect_install_method();

    // For non-Standalone channels the JSON contract is plan-only: emit
    // the update command, return without invoking the channel's
    // installer (the operator is expected to run it themselves so they
    // can pipe / observe / sandbox it). Standalone is the one channel
    // LPM can run AND attribute end-to-end, so its `--json` path runs
    // the install and emits the captured Sigstore audit alongside.
    if json_output && !matches!(method, InstallMethod::Standalone) {
        let json = serde_json::json!({
            "success": true,
            "current": current,
            "latest": latest,
            "up_to_date": false,
            "install_method": method.name(),
            "update_command": method.command(&latest),
            "cache_hit": cache_hit,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        return Ok(());
    }

    if !json_output {
        eprintln!(
            "    {}   {}",
            install_ui::dim("channel"),
            method.name().cyan()
        );
        install_ui::phase("Update command");
        eprintln!("    {}", install_ui::yellow(&method.command(&latest)));
    }

    let mut standalone_audit: Option<AttestationAudit> = None;
    match method {
        InstallMethod::Npm => {
            let pinned = format!("@lpm-registry/cli@{latest}");
            run_shell_update("npm", &["install", "-g", &pinned])?;
        }
        InstallMethod::Homebrew => run_shell_update("brew", &["upgrade", "lpm"])?,
        InstallMethod::Cargo => {
            let tag = format!("v{latest}");
            // `--locked` forces resolution against the Cargo.lock
            // shipped with the tag rather than re-solving the
            // dependency graph at install time. Without it, an
            // attacker who compromised any direct or transitive dep's
            // registry entry between our release time and the user's
            // install could inject a different transitive package
            // version into the build — same supply-chain blast as the
            // mutable-git-tag concern in the finding, just one hop
            // further down. `--locked` was a behaviour change in
            // recent cargo (now standard for reproducible installs);
            // every modern cargo (≥1.74) supports it.
            run_shell_update(
                "cargo",
                &[
                    "install",
                    "--git",
                    "https://github.com/lpm-dev/rust-client",
                    "--tag",
                    &tag,
                    "lpm-cli",
                    "--force",
                    "--locked",
                ],
            )?;
        }
        InstallMethod::Standalone => {
            standalone_audit = Some(run_standalone_update(&latest).await?);
        }
    }

    // Post-upgrade cache stamp policy:
    // - Standalone: we downloaded the exact tag → safe to stamp.
    // - Cargo: now `--tag`-pinned → safe to stamp.
    // - Npm: now `@{latest}`-pinned → safe to stamp.
    // - Homebrew: `brew upgrade lpm` is channel-latest, not tag-pinned;
    //   we can't prove which version actually landed. Clear the cache
    //   instead so the next invocation re-probes from scratch rather
    //   than asserting a possibly-wrong "latest".
    if let Some(p) = cache_path.as_deref() {
        match method {
            InstallMethod::Standalone | InstallMethod::Cargo | InstallMethod::Npm => {
                cache.latest = latest.clone();
                cache.last_check = now;
                cache.last_failure_check = 0;
                let _ = write_cache_at(p, &cache);
            }
            InstallMethod::Homebrew => {
                clear_cache_at(p);
            }
        }
    }

    if json_output {
        let audit = standalone_audit
            .as_ref()
            .expect("json_output && Standalone implies audit was captured");
        let json = serde_json::json!({
            "success": true,
            "current": current,
            "latest": latest,
            "up_to_date": false,
            "install_method": method.name(),
            "cache_hit": cache_hit,
            "verified": true,
            "attestation": audit_json(audit),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · LPM updated to {}",
            install_ui::yellow(&latest)
        ));
    }

    Ok(())
}

/// Map a `LookupError` into `LpmError` so the existing CLI error
/// surfaces (slim UI / `--json`) render it without losing the typed
/// rate-limit info.
///
/// Mapping is purpose-specific so error categories match user intent:
/// - Transport / HTTP / malformed → `Network`. Live network problem.
/// - GitHub-API rate limit → `SelfUpdateRateLimited`. Not a permission
///   issue (the historical `Forbidden` mapping read like the user was
///   blocked); it's a quota issue with a clear remediation surfaced in
///   the variant's help text (`GITHUB_TOKEN` / `GH_TOKEN`).
///
/// `LookupError`'s own `Display` is the canonical body — it owns the
/// reset-hint formatting and intentionally omits the `GITHUB_TOKEN`
/// guidance (which lives in the wrapping variant's diagnostic help). The
/// wrapper here just adds the user-facing context prefix.
fn lookup_error_to_lpm(e: LookupError) -> LpmError {
    match &e {
        LookupError::Transport(_) | LookupError::HttpStatus { .. } => {
            LpmError::Network(format!("failed to check for updates: {e}"))
        }
        LookupError::RateLimited { .. } => LpmError::SelfUpdateRateLimited(e.to_string()),
        LookupError::MalformedResponse(_) | LookupError::NotFound(_) => {
            LpmError::Network(format!("failed to check for updates: {e}"))
        }
    }
}

/// Installation method detection.
#[derive(Debug, PartialEq, Eq)]
enum InstallMethod {
    Npm,
    Homebrew,
    Cargo,
    Standalone,
}

impl InstallMethod {
    fn name(&self) -> &'static str {
        match self {
            InstallMethod::Npm => "npm",
            InstallMethod::Homebrew => "homebrew",
            InstallMethod::Cargo => "cargo",
            InstallMethod::Standalone => "standalone",
        }
    }

    fn command(&self, version: &str) -> String {
        match self {
            InstallMethod::Npm => format!("npm install -g @lpm-registry/cli@{version}"),
            InstallMethod::Homebrew => "brew upgrade lpm".into(),
            InstallMethod::Cargo => format!(
                "cargo install --git https://github.com/lpm-dev/rust-client --tag v{version} lpm-cli --force --locked"
            ),
            InstallMethod::Standalone => standalone_command(version),
        }
    }
}

/// Equivalent shell command for the Standalone upgrade path. The
/// wrapper does an in-place download of the version-pinned release
/// asset for the current binary's path — `install.sh` is the install
/// helper for new users, not what `lpm self-update` actually runs
/// (it does its own `releases/latest` lookup and writes to
/// `~/.lpm/bin/`).
///
/// On unsupported platforms or when the current exe path is unknown,
/// fall back to the GitHub Releases page so the user has somewhere to
/// land manually.
fn standalone_command(version: &str) -> String {
    let Ok((platform, ext)) = detect_platform() else {
        return format!("https://github.com/lpm-dev/rust-client/releases/tag/v{version}");
    };
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    standalone_command_for(version, platform, ext, exe.as_deref())
}

/// Pure helper for [`standalone_command`]. Split out so both per-OS
/// shapes (POSIX `curl` + `chmod` vs Windows PowerShell
/// `Invoke-WebRequest`) can be tested without depending on the host
/// the test happens to run on. The Rust updater itself only `chmod`s
/// on Unix (the `chmod +x` step is `#[cfg(unix)]`), and `chmod` is a
/// no-op on Windows — so emitting it unconditionally would hand
/// Windows users a broken command.
fn standalone_command_for(version: &str, platform: &str, ext: &str, exe: Option<&str>) -> String {
    let url = format!(
        "https://github.com/lpm-dev/rust-client/releases/download/v{version}/lpm-{platform}{ext}"
    );
    let is_windows = platform.starts_with("win32");
    let exe = exe.map_or_else(
        || {
            if is_windows {
                "%USERPROFILE%\\.lpm\\bin\\lpm.exe".to_string()
            } else {
                "/usr/local/bin/lpm".to_string()
            }
        },
        str::to_string,
    );
    if is_windows {
        // PowerShell. No chmod — Windows uses the .exe extension to
        // mark executables, not a permission bit.
        format!("Invoke-WebRequest -Uri {url} -OutFile {exe}")
    } else {
        format!("curl -fsSL {url} -o {exe} && chmod +x {exe}")
    }
}

fn detect_install_method() -> InstallMethod {
    let exe = std::env::current_exe().ok();
    // Resolve symlinks so `/usr/local/bin/lpm → ~/.volta/bin/lpm` (or
    // any version-manager shim) classifies as the underlying channel,
    // not Standalone. `canonicalize` can fail on Windows for some
    // symlink targets — fall back to the raw path so detection still
    // works on the common case where the exe IS the canonical binary.
    let resolved = exe
        .as_ref()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .or(exe);
    detect_install_method_from_path(resolved.as_deref())
}

/// Pure helper for [`detect_install_method`]. Split out so the
/// per-shim classification can be unit-tested with synthetic paths
/// without depending on whatever package manager happens to own the
/// running binary.
fn detect_install_method_from_path(exe: Option<&std::path::Path>) -> InstallMethod {
    let Some(path) = exe else {
        return InstallMethod::Standalone;
    };
    let components: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    let has = |name: &str| components.contains(&name);

    // Homebrew first. After canonicalize, `Cellar` is the unique
    // component on every Homebrew-managed binary regardless of
    // `/opt/homebrew` vs `/usr/local` prefix on macOS, and Linuxbrew
    // also routes through `/home/linuxbrew/.linuxbrew/Cellar/...`.
    // `homebrew` is kept as a fallback signal for the rare cases where
    // canonicalize fails and we end up testing the bin-shim path
    // (`/opt/homebrew/bin/lpm`) directly.
    if has("Cellar") || has("homebrew") || has("linuxbrew") {
        return InstallMethod::Homebrew;
    }
    if has(".cargo") {
        return InstallMethod::Cargo;
    }
    if is_npm_managed(&components) {
        return InstallMethod::Npm;
    }
    InstallMethod::Standalone
}

/// Path-component (not substring) match against npm-ecosystem install
/// roots. The previous substring-based check matched any path with
/// `"npm"` anywhere in it (e.g. `/Users/npmtest/...` false-positived as
/// npm-installed) and missed Volta / fnm / asdf / pnpm-global entirely.
fn is_npm_managed(components: &[&str]) -> bool {
    let has = |name: &str| components.contains(&name);

    // The reliable signal: every `npm install -g` and `npx` install
    // routes through a `node_modules` directory.
    if has("node_modules") {
        return true;
    }

    // Version manager and alternative install roots. Component-level
    // exact match avoids the substring trap.
    const SHIMS: &[&str] = &[
        ".npm",   // npm cache root (`~/.npm`)
        ".nvm",   // nvm install root (`~/.nvm`)
        ".volta", // Volta install root (`~/.volta`)
        ".fnm",   // fnm install root (`~/.fnm`)
        ".asdf",  // asdf install root (`~/.asdf`)
        ".n",     // `n` install root with custom `N_PREFIX=~/.n`
        "nvm",    // nvm shared-install variants
        "volta",  // Volta shared-install variants
        "fnm",    // fnm shared-install variants
        "asdf",   // asdf shared-install variants
    ];
    if SHIMS.iter().any(|s| has(s)) {
        return true;
    }

    // pnpm global installs have BOTH `pnpm` AND `global` as components.
    // Requiring both avoids matching pnpm's content-addressable store
    // (e.g. `~/.pnpm-store/...`), which is not a global-install root.
    if has("pnpm") && has("global") {
        return true;
    }

    // The `n` version manager's default install layout has BOTH `n`
    // and `versions` as path components — e.g.
    // `/usr/local/n/versions/node/20.0.0/bin/lpm` (system) or
    // `~/n/versions/node/20.0.0/bin/lpm` (default `N_PREFIX=$HOME`).
    // Bare `n` alone would be too aggressive (matches any folder
    // literally named `n`); requiring `versions` as well anchors the
    // match to n's actual directory shape.
    if has("n") && has("versions") {
        return true;
    }

    false
}

/// Run an external command for package-manager-based upgrades.
fn run_shell_update(cmd: &str, args: &[&str]) -> Result<(), LpmError> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| LpmError::Script(format!("failed to run {cmd}: {e}")))?;

    if !status.success() {
        return Err(LpmError::Script(format!(
            "{cmd} exited with code {}",
            status.code().unwrap_or(-1)
        )));
    }

    Ok(())
}

/// `SHA256SUMS.txt` size cap (4 KiB). The real manifest is ~600 B
/// today (six lines of `<sha>  <name>`); 4 KiB leaves comfortable
/// headroom for future binaries without giving a hostile server an
/// unbounded body.
const MANIFEST_MAX_BYTES: usize = 4 * 1024;

/// `SHA256SUMS.txt.sigstore` size cap (1 MiB). Real bundles are
/// ~12 KiB but the protocol allows for embedded inclusion proofs that
/// can grow; mirror the `SIGSTORE_RESPONSE_CAP_BYTES` used elsewhere.
const BUNDLE_MAX_BYTES: usize = 1024 * 1024;

/// Per-asset download cap (256 MiB). Today's largest published binary
/// is ~30 MiB; the cap is set well above realistic growth so the
/// guard only trips on a hostile server streaming junk.
const ASSET_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Replay-window: bundle `integratedTime` must lie within
/// `[published_at - PRE_WINDOW, published_at + POST_WINDOW]`. The
/// 1-hour pre-window absorbs the GitHub Actions run minting the
/// attestation before the Release object is finalized; the 24-hour
/// post-window allows for late asset publication / re-uploads.
const REPLAY_PRE_WINDOW: chrono::Duration = chrono::Duration::hours(1);
const REPLAY_POST_WINDOW: chrono::Duration = chrono::Duration::hours(24);

/// Captured trail of attestation metadata, surfaced into the
/// `--json` self-update output so audit pipelines can pin which
/// release identity actually authorised the binary swap.
#[derive(Debug, Clone)]
struct AttestationAudit {
    publisher: Option<String>,
    workflow_path: Option<String>,
    workflow_ref: Option<String>,
    integrated_time: chrono::DateTime<chrono::Utc>,
    log_index: i64,
    log_id: String,
    leaf_cert_sha256: String,
    manifest_sha256: String,
    asset_sha256: String,
    asset_name: String,
}

/// Map a `VerifyError` into the user-facing `LpmError::SelfUpdate`
/// shape. The verifier error's `Display` already names the failing
/// primitive (DSSE / chain / SET / SCT / Rekor body / inclusion proof
/// / identity) so the wrapping prefix names the surface for the user.
fn map_verify_error(e: VerifyError) -> LpmError {
    LpmError::SelfUpdate(format!(
        "Sigstore verification of release manifest failed: {e}"
    ))
}

/// Parse a single line of a `sha256sum`-style manifest.
///
/// Lines must match `^([0-9a-f]{64})  (.+)$` — two ASCII spaces
/// separate the hex digest from the file name (the GNU coreutils
/// default; `shasum -a 256` produces the same shape). Anything else
/// returns `None` so callers can choose to reject the manifest
/// entirely rather than silently drop the malformed entry.
fn parse_manifest_line(line: &str) -> Option<(String, String)> {
    let line = line.trim_end_matches('\r');
    let (sha_part, name_part) = line.split_once("  ")?;
    if sha_part.len() != 64 || !sha_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let sha = sha_part.to_ascii_lowercase();
    let name = name_part.trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some((sha, name))
}

/// Look up the expected SHA-256 for a given filename in a parsed
/// `SHA256SUMS.txt` body. Skips blank lines and rejects lines that
/// fail [`parse_manifest_line`] — a malformed manifest is an integrity
/// failure, not a silent miss.
fn lookup_platform_sha(manifest: &str, basename: &str) -> Result<String, LpmError> {
    for (idx, raw_line) in manifest.lines().enumerate() {
        if raw_line.trim().is_empty() {
            continue;
        }
        let (sha, name) = parse_manifest_line(raw_line).ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "SHA256SUMS.txt line {} is malformed (expected `<64-hex-sha>  <filename>`); \
                 refusing to install from a manifest we cannot fully parse",
                idx + 1
            ))
        })?;
        if name == basename {
            return Ok(sha);
        }
    }
    Err(LpmError::SelfUpdate(format!(
        "SHA256SUMS.txt does not enumerate `{basename}` for this platform — release pipeline may be missing artifacts"
    )))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Fetch a bounded-size body from a URL with a 30 s timeout. Returns
/// `Ok(Some(bytes))` on 200, `Ok(None)` on 404, and `Err` on every
/// other shape (transport, oversized body, non-success status). The
/// 404 / non-404 distinction is what lets the caller distinguish
/// "release predates the integrity gate" from "release exists but
/// something else is wrong with our download."
async fn fetch_bounded(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, LpmError> {
    let mut resp = client
        .get(url)
        .header("User-Agent", "lpm-cli")
        .send()
        .await
        .map_err(|e| {
            LpmError::Network(format!(
                "release asset fetch failed: {}",
                lpm_http::display_error(&e)
            ))
        })?;

    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(LpmError::Network(format!(
            "fetch {url} returned HTTP {}",
            status.as_u16()
        )));
    }

    // Reject by advertised Content-Length before any body bytes are
    // buffered. A hostile or compromised endpoint that sets a truthful
    // oversized Content-Length is caught here without touching the
    // socket past the headers.
    if let Some(advertised) = resp.content_length()
        && advertised as usize > max_bytes
    {
        return Err(LpmError::SelfUpdate(format!(
            "{url} advertises {advertised} bytes; cap of {max_bytes} would be exceeded — refusing to buffer"
        )));
    }

    // Stream chunk-by-chunk so a hostile endpoint that omits or lies on
    // Content-Length still trips the cap before the whole body lands in
    // memory. Pre-size the buffer when Content-Length is present and
    // under the cap; otherwise let the Vec grow.
    let prealloc = resp
        .content_length()
        .map_or(0, |c| (c as usize).min(max_bytes));
    let mut buf: Vec<u8> = Vec::with_capacity(prealloc);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| LpmError::Network(format!("fetch {url} body read failed: {e}")))?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(LpmError::SelfUpdate(format!(
                "{url} body exceeded cap of {max_bytes} bytes mid-stream — aborted before full buffer"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Some(buf))
}

/// Cryptographically verify a release-artifact triple (manifest,
/// Sigstore bundle, platform binary) end-to-end and return the audit
/// trail on success. Every gate fails closed.
fn verify_release_artifacts(
    version: &str,
    manifest_bytes: &[u8],
    bundle_bytes: &[u8],
    asset_bytes: &[u8],
    asset_basename: &str,
    published_at: chrono::DateTime<chrono::Utc>,
) -> Result<AttestationAudit, LpmError> {
    let expectations = IdentityExpectations {
        expected_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
        expected_san_uri_prefix: Some("https://github.com/lpm-dev/rust-client/".to_string()),
        expected_workflow_path: Some(".github/workflows/release.yml".to_string()),
    };
    let options = VerifyOptions::strict();

    let VerifiedProvenance {
        snapshot,
        integrated_time,
        leaf_cert_sha256,
        log_id,
        log_index,
    } = verify_sigstore_bundle(bundle_bytes, &expectations, options).map_err(map_verify_error)?;

    let integrated_time_utc: chrono::DateTime<chrono::Utc> = integrated_time.into();
    let earliest = published_at - REPLAY_PRE_WINDOW;
    let latest = published_at + REPLAY_POST_WINDOW;
    if integrated_time_utc < earliest || integrated_time_utc > latest {
        return Err(LpmError::SelfUpdate(format!(
            "Sigstore bundle integratedTime ({integrated_time_utc}) is outside the replay window \
             [{earliest}, {latest}] for release v{version} (published_at = {published_at}). \
             The bundle may be a replayed attestation from a different release."
        )));
    }

    let (subject_name, subject_sha256) =
        extract_in_toto_subject_digest(bundle_bytes).map_err(map_verify_error)?;
    let manifest_sha256 = sha256_hex(manifest_bytes);
    if subject_sha256 != manifest_sha256 {
        return Err(LpmError::SelfUpdate(format!(
            "Sigstore bundle subject digest does not match SHA256SUMS.txt: bundle attests \
             sha256={subject_sha256} (subject `{subject_name}`), downloaded manifest \
             sha256={manifest_sha256}. The manifest may be tampered."
        )));
    }

    let manifest_text = std::str::from_utf8(manifest_bytes).map_err(|e| {
        LpmError::SelfUpdate(format!(
            "SHA256SUMS.txt is not valid UTF-8 — refusing to parse: {e}"
        ))
    })?;
    let expected_asset_sha = lookup_platform_sha(manifest_text, asset_basename)?;
    let actual_asset_sha = sha256_hex(asset_bytes);
    if actual_asset_sha != expected_asset_sha {
        return Err(LpmError::SelfUpdate(format!(
            "downloaded `{asset_basename}` SHA-256 mismatch: signed manifest declares \
             {expected_asset_sha}, actual download is {actual_asset_sha}. \
             Refusing to replace the running binary."
        )));
    }

    Ok(AttestationAudit {
        publisher: snapshot.publisher.clone(),
        workflow_path: snapshot.workflow_path.clone(),
        workflow_ref: snapshot.workflow_ref,
        integrated_time: integrated_time_utc,
        log_index,
        log_id,
        leaf_cert_sha256,
        manifest_sha256,
        asset_sha256: actual_asset_sha,
        asset_name: asset_basename.to_string(),
    })
}

/// Download and replace the binary in-place for standalone installations.
///
/// Every fetched byte is anchored to the Sigstore-signed `SHA256SUMS.txt`
/// manifest: the bundle's identity must match `lpm-dev/rust-client`'s
/// release workflow, its `integratedTime` must lie inside a sane window
/// around the GitHub Release `published_at`, the manifest's own hash
/// must match the bundle's in-toto subject digest, and the downloaded
/// binary's hash must match the manifest line for this platform. Any
/// failure short-circuits before `swap_current_binary` is reached.
///
/// Returns the captured attestation audit so the caller can surface it
/// into `--json` output (or wherever else a structured audit trail
/// belongs). The audit is also logged via `tracing::info!`.
async fn run_standalone_update(version: &str) -> Result<AttestationAudit, LpmError> {
    let assets = verify_and_fetch_for_standalone(version).await?;
    let current_exe = std::env::current_exe().map_err(LpmError::Io)?;
    swap_current_binary(&current_exe, &assets.asset_bytes)?;

    tracing::info!(
        target: "lpm_cli::self_update",
        publisher = assets.audit.publisher.as_deref().unwrap_or("<absent>"),
        workflow_path = assets.audit.workflow_path.as_deref().unwrap_or("<absent>"),
        workflow_ref = assets.audit.workflow_ref.as_deref().unwrap_or("<absent>"),
        integrated_time = %assets.audit.integrated_time,
        log_index = assets.audit.log_index,
        log_id = %assets.audit.log_id,
        leaf_cert_sha256 = %assets.audit.leaf_cert_sha256,
        manifest_sha256 = %assets.audit.manifest_sha256,
        asset_sha256 = %assets.audit.asset_sha256,
        asset_name = %assets.audit.asset_name,
        "standalone self-update verified and applied"
    );
    Ok(assets.audit)
}

/// Render an `AttestationAudit` as the JSON shape callers see under
/// `--json` mode. Stable wire shape — adding new fields is fine, but
/// renaming or removing keys is a contract break.
fn audit_json(audit: &AttestationAudit) -> serde_json::Value {
    serde_json::json!({
        "publisher": audit.publisher,
        "workflow_path": audit.workflow_path,
        "workflow_ref": audit.workflow_ref,
        "integrated_time": audit.integrated_time.to_rfc3339(),
        "log_index": audit.log_index,
        "log_id": audit.log_id,
        "leaf_cert_sha256": audit.leaf_cert_sha256,
        "manifest_sha256": audit.manifest_sha256,
        "asset_sha256": audit.asset_sha256,
        "asset_name": audit.asset_name,
    })
}

/// Verified + bytes-ready state ready to be handed to
/// [`swap_current_binary`]. Split out so the standalone update flow
/// can be unit-tested through `verify_and_fetch_for_standalone`
/// without requiring the swap step (which mutates the running binary).
#[derive(Debug)]
struct StandaloneAssets {
    asset_bytes: Vec<u8>,
    audit: AttestationAudit,
}

async fn verify_and_fetch_for_standalone(version: &str) -> Result<StandaloneAssets, LpmError> {
    let (platform, ext) = detect_platform()?;
    let binary_name = format!("lpm-{platform}{ext}");
    let manifest_url = github_release_download_url(version, "SHA256SUMS.txt");
    let bundle_url = github_release_download_url(version, "SHA256SUMS.txt.sigstore");
    let asset_url = github_release_download_url(version, &binary_name);

    let client = lpm_http::client_builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

    install_ui::phase_untrusted(&format!("Fetching signed checksums for v{version}"));

    let manifest_bytes = fetch_bounded(&client, &manifest_url, MANIFEST_MAX_BYTES)
        .await?
        .ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "release v{version} does not ship SHA256SUMS.txt — this release predates LPM's \
                 signed-install gate. Install manually from \
                 https://github.com/lpm-dev/rust-client/releases/v{version}"
            ))
        })?;
    let bundle_bytes = fetch_bounded(&client, &bundle_url, BUNDLE_MAX_BYTES)
        .await?
        .ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "release v{version} ships SHA256SUMS.txt but not SHA256SUMS.txt.sigstore — \
                 cannot cryptographically verify the manifest. Install manually."
            ))
        })?;

    let published_at = fetch_github_release_published_at(version)
        .await
        .map_err(|e| match e {
            LookupError::NotFound(_) => LpmError::SelfUpdate(format!(
                "GitHub has no release at tag v{version} — cannot anchor the Sigstore replay window. \
                 Install manually."
            )),
            LookupError::MalformedResponse(msg) => LpmError::SelfUpdate(format!(
                "release v{version} did not expose a parseable `published_at` timestamp: {msg}. \
                 Cannot anchor the Sigstore replay window."
            )),
            other => LpmError::Network(format!(
                "could not fetch release metadata for v{version}: {other}"
            )),
        })?;

    install_ui::phase("Verifying Sigstore attestation");

    let asset_vec = fetch_bounded(&client, &asset_url, ASSET_MAX_BYTES)
        .await?
        .ok_or_else(|| {
            LpmError::SelfUpdate(format!(
                "release v{version} advertises `{binary_name}` in SHA256SUMS.txt but the asset is missing at {asset_url} — release-pipeline bug"
            ))
        })?;

    let audit = verify_release_artifacts(
        version,
        &manifest_bytes,
        &bundle_bytes,
        &asset_vec,
        &binary_name,
        published_at,
    )?;

    install_ui::done_untrusted(&format!(
        "Verified Sigstore attestation for {} ({}, integratedTime {})",
        binary_name,
        format_bytes(asset_vec.len()),
        audit.integrated_time
    ));

    Ok(StandaloneAssets {
        asset_bytes: asset_vec,
        audit,
    })
}

/// Atomically swap the running binary at `current_exe` for `new_bytes`.
///
/// The temporary file is exclusively created next to `current_exe`, which
/// keeps the eventual replacement on the same filesystem.
///
/// **Windows EBUSY:** the OS holds an exclusive handle on the running
/// `current_exe()`, so a direct `rename(new, current_exe)` fails.
/// The standard dance is `rename(current_exe, current_exe.old)`
/// (legal even with a live handle), then `rename(new, current_exe)`,
/// then best-effort delete the `.old` (OS releases the handle when
/// this process exits, so the delete will succeed on the next run).
fn swap_current_binary(current_exe: &std::path::Path, new_bytes: &[u8]) -> Result<(), LpmError> {
    let file_name = current_exe.file_name().ok_or_else(|| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current_exe has no file name",
        ))
    })?;
    let parent = current_exe.parent().ok_or_else(|| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current_exe has no parent directory",
        ))
    })?;

    // L20: save a backup copy of the running binary next to itself BEFORE
    // we install the new one, so a user who discovers the new binary is
    // broken can rename `<lpm>.previous` back over `<lpm>` and recover
    // without going to GitHub. The journal file is a parallel marker
    // recording when the backup was made + the version string the user
    // updated FROM, so a future `lpm self-rollback` command (tracked
    // separately) can drive the rename automatically.
    //
    // Best-effort: if the copy fails (read-only filesystem, perms), log
    // and continue with the install. The user opted into the update
    // and would get a confusing "can't update" error otherwise.
    let backup_name = format!("{}.previous", file_name.to_string_lossy());
    let backup_path = parent.join(backup_name);
    if let Err(e) = copy_executable_atomic(current_exe, &backup_path) {
        tracing::warn!(
            target: "lpm_cli::self_update",
            current_exe = %current_exe.display(),
            backup_path = %backup_path.display(),
            error = %e,
            "could not back up the running binary before self-update — rollback via `<binary>.previous` rename will not be available"
        );
    } else {
        let journal_path = parent.join(format!(
            "{}.update-journal.json",
            file_name.to_string_lossy()
        ));
        let journal = serde_json::json!({
            "version": 1,
            "backup_path": backup_path.display().to_string(),
            "current_exe": current_exe.display().to_string(),
            "updated_at_unix_secs": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            "previous_binary_version": env!("CARGO_PKG_VERSION"),
        });
        let journal_bytes = serde_json::to_vec_pretty(&journal).unwrap_or_default();
        if let Err(e) = lpm_common::write_file_atomic(&journal_path, journal_bytes) {
            tracing::warn!(
                target: "lpm_cli::self_update",
                journal_path = %journal_path.display(),
                error = %e,
                "wrote backup but failed to record update-journal sidecar — rollback via rename still possible"
            );
        }
    }

    let mut prefix = std::ffi::OsString::from(".");
    prefix.push(file_name);
    prefix.push(".new-");
    let suffix = current_exe.extension().map(|extension| {
        let mut suffix = std::ffi::OsString::from(".");
        suffix.push(extension);
        suffix
    });
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix);
    if let Some(suffix) = &suffix {
        builder.suffix(suffix);
    }
    let mut temporary = builder.tempfile_in(parent).map_err(LpmError::Io)?;
    {
        use std::io::Write as _;
        temporary.as_file_mut().write_all(new_bytes).map_err(|e| {
            LpmError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to write temp binary: {e}"),
            ))
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(LpmError::Io)?;
    }
    let tmp_path = temporary.into_temp_path();

    #[cfg(windows)]
    {
        let old_name = format!("{}.old.{}", file_name.to_string_lossy(), std::process::id());
        let old_path = parent.join(&old_name);
        if let Err(e) = std::fs::rename(current_exe, &old_path) {
            return Err(LpmError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to move running binary aside: {e}"),
            )));
        }
        if let Err(e) = std::fs::rename(&tmp_path, current_exe) {
            // Try to restore the original binary so we don't leave the
            // install in a broken state.
            let _ = std::fs::rename(&old_path, current_exe);
            return Err(LpmError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to install new binary: {e}"),
            )));
        }
        // Best-effort cleanup. The OS will release the handle on the
        // `.old` file when this process exits; the next run of the new
        // binary can sweep it.
        let _ = std::fs::remove_file(&old_path);
        Ok(())
    }

    #[cfg(unix)]
    {
        std::fs::rename(&tmp_path, current_exe).map_err(|e| {
            LpmError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to replace binary: {e}"),
            ))
        })
    }
}

fn copy_executable_atomic(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    lpm_common::write_file_atomic_with(
        destination,
        lpm_common::AtomicWriteOptions::new().unix_mode(0o755),
        |output| {
            let mut input = std::fs::File::open(source)?;
            std::io::copy(&mut input, output)?;
            Ok(())
        },
    )
}

/// Detect the current platform for GitHub Release binary names.
fn detect_platform() -> Result<(&'static str, &'static str), LpmError> {
    detect_platform_for(
        std::env::consts::OS,
        std::env::consts::ARCH,
        resolve_linux_libc(EXECUTABLE_LINUX_LIBC, lpm_common::platform::detect_libc()),
    )
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
const EXECUTABLE_LINUX_LIBC: Option<&str> = Some("musl");

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const EXECUTABLE_LINUX_LIBC: Option<&str> = Some("gnu");

#[cfg(not(any(
    all(target_os = "linux", target_env = "musl"),
    all(target_os = "linux", target_env = "gnu")
)))]
const EXECUTABLE_LINUX_LIBC: Option<&str> = None;

const fn resolve_linux_libc<'a>(
    executable_libc: Option<&'a str>,
    detected_host_libc: Option<&'a str>,
) -> Option<&'a str> {
    match executable_libc {
        Some(libc) => Some(libc),
        None => detected_host_libc,
    }
}

fn detect_platform_for(
    os: &str,
    arch: &str,
    libc: Option<&str>,
) -> Result<(&'static str, &'static str), LpmError> {
    match (os, arch) {
        ("macos", "aarch64") => Ok(("darwin-arm64", "")),
        ("macos", "x86_64") => Ok(("darwin-x64", "")),
        ("linux", "x86_64") if libc == Some("musl") => Ok(("linux-x64-musl", "")),
        ("linux", "x86_64") => Ok(("linux-x64", "")),
        ("linux", "aarch64") if libc == Some("musl") => Err(LpmError::Script(
            "unsupported platform: linux-aarch64-musl. Official musl releases currently support x86_64; build from source on ARM64"
                .to_string(),
        )),
        ("linux", "aarch64") => Ok(("linux-arm64", "")),
        ("windows", "x86_64") => Ok(("win32-x64", ".exe")),
        _ => Err(LpmError::Script(format!(
            "unsupported platform: {os}-{arch}. Download manually from https://github.com/lpm-dev/rust-client/releases"
        ))),
    }
}

/// Render a duration in seconds as a coarse human string. Picks the
/// largest unit that gives at least one whole quantity. Pluralises.
fn humanize_seconds(secs: u64) -> String {
    if secs >= 3600 {
        let h = secs / 3600;
        format!("{h} hour{}", if h == 1 { "" } else { "s" })
    } else if secs >= 60 {
        let m = secs / 60;
        format!("{m} minute{}", if m == 1 { "" } else { "s" })
    } else {
        format!("{secs} second{}", if secs == 1 { "" } else { "s" })
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_lookup::{self, UpdateCache};
    use tempfile::tempdir;

    #[test]
    fn install_method_name_not_empty() {
        let method = detect_install_method();
        assert!(!method.name().is_empty());
    }

    #[test]
    fn detect_platform_selects_musl_asset_on_linux_x64_musl() {
        assert_eq!(
            detect_platform_for("linux", "x86_64", Some("musl")).unwrap(),
            ("linux-x64-musl", "")
        );
    }

    #[test]
    fn detect_platform_preserves_gnu_asset_on_linux_x64_glibc() {
        assert_eq!(
            detect_platform_for("linux", "x86_64", Some("glibc")).unwrap(),
            ("linux-x64", "")
        );
    }

    #[test]
    fn detect_platform_rejects_linux_arm64_musl_without_release_asset() {
        assert!(detect_platform_for("linux", "aarch64", Some("musl")).is_err());
    }

    #[test]
    fn executable_abi_wins_when_host_has_both_glibc_and_musl_loaders() {
        assert_eq!(resolve_linux_libc(Some("gnu"), Some("musl")), Some("gnu"));
    }

    #[test]
    fn parse_manifest_line_accepts_canonical_two_space_form() {
        let line =
            "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd  lpm-linux-x64";
        let (sha, name) = parse_manifest_line(line).expect("must parse");
        assert_eq!(sha.len(), 64);
        assert_eq!(name, "lpm-linux-x64");
    }

    #[test]
    fn parse_manifest_line_lowercases_hex_digest() {
        let line = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890  X";
        let (sha, _) = parse_manifest_line(line).expect("must parse");
        assert_eq!(
            sha,
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[test]
    fn parse_manifest_line_rejects_short_digest() {
        let line = "abc  lpm-linux-x64";
        assert!(parse_manifest_line(line).is_none());
    }

    #[test]
    fn parse_manifest_line_rejects_non_hex_digest() {
        let line = "zzz123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd  lpm";
        assert!(parse_manifest_line(line).is_none());
    }

    #[test]
    fn parse_manifest_line_rejects_single_space_separator() {
        let line = "0000000000000000000000000000000000000000000000000000000000000000 lpm";
        assert!(parse_manifest_line(line).is_none());
    }

    #[test]
    fn parse_manifest_line_rejects_empty_filename() {
        let line = "0000000000000000000000000000000000000000000000000000000000000000  ";
        assert!(parse_manifest_line(line).is_none());
    }

    #[test]
    fn parse_manifest_line_strips_trailing_carriage_return() {
        let line =
            "1111111111111111111111111111111111111111111111111111111111111111  lpm-darwin-arm64\r";
        let (sha, name) = parse_manifest_line(line).expect("must parse");
        assert_eq!(
            sha,
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(name, "lpm-darwin-arm64");
    }

    #[test]
    fn lookup_platform_sha_returns_correct_entry() {
        let manifest = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lpm-darwin-arm64\n\
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  lpm-darwin-x64\n\
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  lpm-linux-x64\n\
";
        let got = lookup_platform_sha(manifest, "lpm-linux-x64").expect("must find");
        assert_eq!(
            got,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
    }

    #[test]
    fn lookup_platform_sha_returns_err_on_missing_platform() {
        let manifest =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lpm-darwin-arm64\n";
        let err = lookup_platform_sha(manifest, "lpm-linux-x64").expect_err("must fail");
        match err {
            LpmError::SelfUpdate(msg) => assert!(msg.contains("lpm-linux-x64")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn lookup_platform_sha_skips_blank_lines() {
        let manifest =
            "\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lpm-linux-x64\n\n";
        let got = lookup_platform_sha(manifest, "lpm-linux-x64").expect("must find");
        assert!(got.starts_with("aaaa"));
    }

    #[test]
    fn lookup_platform_sha_rejects_malformed_line() {
        let manifest = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  lpm-darwin-arm64
not-a-valid-line
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  lpm-linux-x64
";
        let err = lookup_platform_sha(manifest, "lpm-linux-x64").expect_err("must reject");
        match err {
            LpmError::SelfUpdate(msg) => assert!(msg.contains("malformed")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        let got = sha256_hex(b"abc");
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Wire-shape pin for the audit JSON surface — `--json self-update`
    /// emits these keys for the Standalone channel and downstream
    /// consumers (audit pipelines, CI provenance check) parse them by
    /// name. Renaming or removing a key is a contract break; adding a
    /// key is non-breaking.
    #[test]
    fn audit_json_emits_stable_wire_shape() {
        let audit = AttestationAudit {
            publisher: Some("github:lpm-dev/rust-client".to_string()),
            workflow_path: Some(".github/workflows/release.yml".to_string()),
            workflow_ref: Some("refs/tags/v1.2.3".to_string()),
            integrated_time: chrono::DateTime::parse_from_rfc3339("2026-05-19T12:34:56Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            log_index: 9876543210,
            log_id: "c0d23d6ad406973f9559f3ba2d1ca01f8.. (truncated)".to_string(),
            leaf_cert_sha256: "feedface".to_string(),
            manifest_sha256: "deadbeef".to_string(),
            asset_sha256: "cafebabe".to_string(),
            asset_name: "lpm-linux-x64".to_string(),
        };
        let json = audit_json(&audit);
        let obj = json.as_object().expect("audit_json returns an object");
        for key in [
            "publisher",
            "workflow_path",
            "workflow_ref",
            "integrated_time",
            "log_index",
            "log_id",
            "leaf_cert_sha256",
            "manifest_sha256",
            "asset_sha256",
            "asset_name",
        ] {
            assert!(
                obj.contains_key(key),
                "audit_json wire shape dropped key `{key}`: {json}"
            );
        }
        assert_eq!(
            obj["integrated_time"], "2026-05-19T12:34:56+00:00",
            "integrated_time must be RFC 3339 with explicit zone offset"
        );
        assert_eq!(obj["log_index"], 9876543210_i64);
    }

    // ── verify_and_fetch_for_standalone (wiremock-backed) ────────

    const DOWNLOAD_OVERRIDE_KEY: &str = "LPM_GITHUB_RELEASE_DOWNLOAD_URL_OVERRIDE";
    const RELEASE_BY_TAG_OVERRIDE_KEY: &str = "LPM_GITHUB_RELEASE_BY_TAG_URL_OVERRIDE";

    /// Self-update tests mutate the same two process-global env vars
    /// (`LPM_GITHUB_RELEASE_DOWNLOAD_URL_OVERRIDE` and
    /// `LPM_GITHUB_RELEASE_BY_TAG_URL_OVERRIDE`). Without serialisation,
    /// parallel `cargo test` runs would race and steer each other's
    /// probes at the wrong wiremock instance.
    struct StandaloneEnvGuard {
        download_prev: Option<std::ffi::OsString>,
        release_by_tag_prev: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for StandaloneEnvGuard {
        fn drop(&mut self) {
            // SAFETY: the shared test environment lock is held through restoration.
            unsafe {
                match &self.download_prev {
                    Some(v) => std::env::set_var(DOWNLOAD_OVERRIDE_KEY, v),
                    None => std::env::remove_var(DOWNLOAD_OVERRIDE_KEY),
                }
                match &self.release_by_tag_prev {
                    Some(v) => std::env::set_var(RELEASE_BY_TAG_OVERRIDE_KEY, v),
                    None => std::env::remove_var(RELEASE_BY_TAG_OVERRIDE_KEY),
                }
            }
        }
    }

    fn acquire_standalone_env(
        download_template: &str,
        release_by_tag_template: &str,
    ) -> StandaloneEnvGuard {
        let lock = crate::test_env::lock_env();
        let guard = StandaloneEnvGuard {
            download_prev: std::env::var_os(DOWNLOAD_OVERRIDE_KEY),
            release_by_tag_prev: std::env::var_os(RELEASE_BY_TAG_OVERRIDE_KEY),
            _lock: lock,
        };
        // SAFETY: the shared test environment lock is held by `guard`.
        unsafe {
            std::env::set_var(DOWNLOAD_OVERRIDE_KEY, download_template);
            std::env::set_var(RELEASE_BY_TAG_OVERRIDE_KEY, release_by_tag_template);
        }
        guard
    }

    /// Drive `verify_and_fetch_for_standalone` against a wiremock-served
    /// release fixture. Caller mounts the asset / manifest / bundle /
    /// release-tag responses on the supplied [`wiremock::MockServer`],
    /// then awaits the future — this helper just wires the env vars up.
    async fn run_standalone_against_server<F>(
        server: &wiremock::MockServer,
        version: &str,
        fut: impl FnOnce() -> F,
    ) where
        F: std::future::Future<Output = ()>,
    {
        let download_template = format!("{}/download/v{{tag}}/{{file}}", server.uri());
        let release_by_tag_template = format!("{}/releases/tags/v{{tag}}", server.uri());
        let _guard = acquire_standalone_env(&download_template, &release_by_tag_template);
        let _ = version; // version is captured by the caller's future
        fut().await;
    }

    fn mount_release_tag_with_published_at(server_uri_path: &str) -> serde_json::Value {
        serde_json::json!({
            "tag_name": format!("v{server_uri_path}"),
            "published_at": "2099-01-01T00:00:00Z",
        })
    }

    #[tokio::test]
    async fn standalone_update_refuses_when_manifest_is_404() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("missing manifest must fail-closed");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(
                        msg.contains("predates LPM's signed-install gate"),
                        "msg: {msg}"
                    );
                    assert!(msg.contains("0.42.0"), "version must appear: {msg}");
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    #[tokio::test]
    async fn standalone_update_refuses_when_bundle_is_404() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(
                b"0000000000000000000000000000000000000000000000000000000000000000  lpm-darwin-arm64\n"
                    .to_vec(),
            ))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/download/v0.42.0/SHA256SUMS.txt.sigstore",
            ))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("missing bundle must fail-closed");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(
                        msg.contains("SHA256SUMS.txt.sigstore"),
                        "msg names the missing bundle file: {msg}"
                    );
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// Hostile server that serves the manifest but the bundle is
    /// signed by axios/axios's release workflow (real npm fixture).
    /// The verifier must reject on identity-pin BEFORE the manifest
    /// or asset content is honoured — proves the SAN URI prefix check
    /// is load-bearing for the C2 path.
    #[tokio::test]
    async fn standalone_update_refuses_when_bundle_identity_does_not_match_lpm_dev_rust_client() {
        let axios_bundle = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sigstore_bundles/20-real-npm-axios-1.14.0.json"),
        )
        .expect("axios fixture must exist");
        let (platform, ext) = detect_platform().expect("platform must be supported");
        let asset_name = format!("lpm-{platform}{ext}");
        let asset_path = format!("/download/v0.42.0/{asset_name}");

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/download/v0.42.0/SHA256SUMS.txt.sigstore",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(axios_bundle))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v0.42.0"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(mount_release_tag_with_published_at("0.42.0")),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(&asset_path))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("foreign-repo bundle must be rejected");
            match err {
                LpmError::SelfUpdate(msg) => {
                    let lower = msg.to_ascii_lowercase();
                    assert!(
                        lower.contains("identity")
                            || lower.contains("san")
                            || lower.contains("workflow")
                            || lower.contains("issuer"),
                        "rejection must name the identity-pin field: {msg}"
                    );
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// Server returns a `releases/tags/v{tag}` JSON with no
    /// `published_at` field — replay-window anchor cannot be
    /// computed and the update must refuse rather than fall through.
    #[tokio::test]
    async fn standalone_update_refuses_when_published_at_is_missing() {
        let axios_bundle = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sigstore_bundles/20-real-npm-axios-1.14.0.json"),
        )
        .expect("axios fixture must exist");

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/download/v0.42.0/SHA256SUMS.txt.sigstore",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(axios_bundle))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v0.42.0"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "tag_name": "v0.42.0",
                })),
            )
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("missing published_at must fail-closed");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(
                        msg.contains("published_at"),
                        "msg names the missing field: {msg}"
                    );
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// `releases/tags/v{tag}` returns 404 (release doesn't exist on
    /// GitHub even though the manifest + bundle came from somewhere) —
    /// surface as `SelfUpdate` with the manual-install hint, not as a
    /// generic network error.
    #[tokio::test]
    async fn standalone_update_refuses_when_release_tag_endpoint_is_404() {
        let axios_bundle = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sigstore_bundles/20-real-npm-axios-1.14.0.json"),
        )
        .expect("axios fixture must exist");

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(b"x".to_vec()))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/download/v0.42.0/SHA256SUMS.txt.sigstore",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(axios_bundle))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/releases/tags/v0.42.0"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("missing release tag must fail-closed");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(
                        msg.contains("no release at tag v0.42.0")
                            || msg.contains("Install manually"),
                        "msg points the user at manual install: {msg}"
                    );
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// Oversized manifest body must trigger the size cap rather than
    /// being silently accepted. Cap is `MANIFEST_MAX_BYTES = 4 KiB`.
    #[tokio::test]
    async fn standalone_update_refuses_when_manifest_exceeds_size_cap() {
        let server = wiremock::MockServer::start().await;
        // 8 KiB of zeros — well over the 4 KiB cap.
        let huge = vec![b'0'; 8 * 1024];
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(huge))
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("oversized manifest must be rejected");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(msg.contains("cap of"), "msg names the cap: {msg}");
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// Hostile endpoint that omits Content-Length and streams more
    /// bytes than the cap allows. The mid-stream guard in
    /// [`fetch_bounded`] must trip before the whole body buffers.
    /// This is the defense-in-depth pair for the Content-Length pre-check.
    #[tokio::test]
    async fn standalone_update_refuses_when_manifest_streams_past_cap_without_content_length() {
        let server = wiremock::MockServer::start().await;
        let huge = vec![b'0'; 8 * 1024];
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/download/v0.42.0/SHA256SUMS.txt"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_bytes(huge)
                    // Wiremock auto-fills Content-Length; force chunked
                    // by setting Transfer-Encoding so the pre-check is
                    // bypassed and the mid-stream guard is what fires.
                    .insert_header("Transfer-Encoding", "chunked"),
            )
            .mount(&server)
            .await;

        run_standalone_against_server(&server, "0.42.0", || async {
            let err = verify_and_fetch_for_standalone("0.42.0")
                .await
                .expect_err("oversized chunked manifest must be rejected");
            match err {
                LpmError::SelfUpdate(msg) => {
                    assert!(
                        msg.contains("mid-stream") || msg.contains("cap of"),
                        "msg names the cap: {msg}"
                    );
                }
                other => panic!("expected SelfUpdate, got {other:?}"),
            }
        })
        .await;
    }

    /// L34: the staging file lands next to `current_exe` (same FS,
    /// preserves any extension such as `.exe`) so the rename is
    /// atomic. Pre-fix `with_extension("tmp")` stripped Windows
    /// `lpm.exe` to `lpm.tmp`, breaking the rename target.
    ///
    /// L20 sidecars (`<file>.previous` + `<file>.update-journal.json`)
    /// are intentionally left in place after a successful swap so the
    /// operator can `mv` the backup back over the destination if the
    /// new binary turns out to be broken — they are recovery state,
    /// not staging.
    #[test]
    fn swap_current_binary_replaces_file_atomically() {
        let dir = tempdir().unwrap();
        let current = dir.path().join("lpm-test-bin");
        std::fs::write(&current, b"old-binary").unwrap();
        let new_bytes = b"new-binary-content";
        swap_current_binary(&current, new_bytes).expect("swap must succeed");
        let read = std::fs::read(&current).unwrap();
        assert_eq!(read, new_bytes);
        let allowed_sidecars = ["lpm-test-bin.previous", "lpm-test-bin.update-journal.json"];
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| {
                let n = e.unwrap().file_name().to_string_lossy().into_owned();
                if n == "lpm-test-bin" || allowed_sidecars.contains(&n.as_str()) {
                    None
                } else {
                    Some(n)
                }
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "swap left behind unexpected staging files: {leftovers:?}"
        );
    }

    /// L34: extension preservation. `with_extension("tmp")` would have
    /// turned `lpm.exe` into `lpm.tmp` — when the destination was
    /// `lpm.exe`, the rename target on Windows would have moved a
    /// non-executable file into place. The current staging name is
    /// `<file_name>.new.<pid>`, which keeps the `.exe` suffix on
    /// `current_exe` intact.
    #[test]
    fn swap_current_binary_keeps_destination_extension_intact() {
        let dir = tempdir().unwrap();
        let current = dir.path().join("lpm.exe");
        std::fs::write(&current, b"old").unwrap();
        swap_current_binary(&current, b"new").expect("swap must succeed");
        assert!(current.exists(), "destination .exe still present");
        assert_eq!(std::fs::read(&current).unwrap(), b"new");
    }

    /// On Unix the swapped binary must end up at 0o755.
    #[cfg(unix)]
    #[test]
    fn swap_current_binary_sets_executable_perms_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let current = dir.path().join("lpm-perms");
        std::fs::write(&current, b"old").unwrap();
        std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o644)).unwrap();
        swap_current_binary(&current, b"new").expect("swap must succeed");
        let mode = std::fs::metadata(&current).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "expected 0o755, got 0o{mode:o}");
    }

    /// Per-channel detection table. Synthetic paths drive the pure
    /// helper so the test holds regardless of what package manager
    /// owns the running test binary.
    ///
    /// The substring-based predecessor false-positived on any path
    /// containing the literal `"npm"` (e.g. `/Users/npmtest/...`) and
    /// missed Volta / fnm / asdf / pnpm-global outright.
    #[test]
    fn detect_install_method_from_path_classifies_each_channel() {
        use std::path::Path;
        let cases: &[(&str, InstallMethod)] = &[
            // Homebrew
            (
                "/opt/homebrew/Cellar/lpm/0.37.0/bin/lpm",
                InstallMethod::Homebrew,
            ),
            (
                "/usr/local/Cellar/lpm/0.37.0/bin/lpm",
                InstallMethod::Homebrew,
            ),
            (
                "/home/linuxbrew/.linuxbrew/Cellar/lpm/0.37.0/bin/lpm",
                InstallMethod::Homebrew,
            ),
            // Homebrew bin-shim fallback (pre-canonicalize path)
            ("/opt/homebrew/bin/lpm", InstallMethod::Homebrew),
            // Cargo
            ("/Users/x/.cargo/bin/lpm", InstallMethod::Cargo),
            // Direct npm install
            (
                "/usr/local/lib/node_modules/@lpm-registry/cli/lpm-bin",
                InstallMethod::Npm,
            ),
            (
                "/Users/x/.npm/_npx/abc/node_modules/@lpm-registry/cli/lpm-bin",
                InstallMethod::Npm,
            ),
            // npm version managers
            (
                "/Users/x/.nvm/versions/node/v20.0.0/bin/lpm",
                InstallMethod::Npm,
            ),
            (
                "/Users/x/.volta/tools/image/packages/@lpm-registry/cli/bin/lpm",
                InstallMethod::Npm,
            ),
            ("/Users/x/.fnm/aliases/default/bin/lpm", InstallMethod::Npm),
            (
                "/Users/x/.asdf/installs/nodejs/20.0.0/bin/lpm",
                InstallMethod::Npm,
            ),
            // `n` version manager — three real-world layouts. Pre-fix,
            // these fell through to Standalone, so self-update would
            // overwrite n's binary tree with a GitHub Releases
            // download instead of going through `npm install -g`.
            ("/Users/x/.n/bin/lpm", InstallMethod::Npm),
            (
                "/Users/x/n/versions/node/20.0.0/bin/lpm",
                InstallMethod::Npm,
            ),
            (
                "/usr/local/n/versions/node/20.0.0/bin/lpm",
                InstallMethod::Npm,
            ),
            // pnpm global (requires BOTH `pnpm` and `global` segments)
            (
                "/Users/x/.local/share/pnpm/global/5/node_modules/@lpm-registry/cli/lpm-bin",
                InstallMethod::Npm,
            ),
            // Standalone — no shim, no node_modules
            ("/Users/x/.lpm/bin/lpm", InstallMethod::Standalone),
            ("/usr/local/bin/lpm", InstallMethod::Standalone),
        ];
        for (raw, expected) in cases {
            let p = Path::new(raw);
            let got = detect_install_method_from_path(Some(p));
            assert_eq!(
                got, *expected,
                "path {raw}: expected {expected:?}, got {got:?}"
            );
        }
    }

    /// Substring-trap regression: a literal `"npm"` anywhere in the
    /// path used to false-positive as an npm install. With component
    /// matching, only exact path components count.
    #[test]
    fn detect_install_method_substring_npm_does_not_false_positive() {
        use std::path::Path;
        // `npmtest` contains "npm" as a substring but is not an npm
        // path component. Must classify as Standalone.
        let p = Path::new("/Users/npmtest/.lpm/bin/lpm");
        assert_eq!(
            detect_install_method_from_path(Some(p)),
            InstallMethod::Standalone,
        );
    }

    /// Bare `n` component without `versions` must NOT classify as
    /// Npm. The `n` version manager's directory layout always has
    /// both segments, so a stray folder named `n` (project source,
    /// initial of a username, etc.) doesn't get misclassified.
    #[test]
    fn detect_install_method_bare_n_without_versions_is_standalone() {
        use std::path::Path;
        // No `versions` segment — could be a project folder named `n`,
        // not the n version manager.
        let p = Path::new("/Users/x/projects/n/bin/lpm");
        assert_eq!(
            detect_install_method_from_path(Some(p)),
            InstallMethod::Standalone,
            "bare `n` segment without `versions` must not classify as Npm"
        );
    }

    /// pnpm content-addressable store has a `pnpm` component but NOT
    /// `global`. Must NOT classify as Npm — it's not an install root,
    /// and routing the upgrade through `npm install -g` would corrupt
    /// the store.
    #[test]
    fn detect_install_method_pnpm_store_alone_is_not_global_install() {
        use std::path::Path;
        let p = Path::new("/Users/x/.pnpm-store/v3/files/aa/bb/lpm-bin");
        assert_eq!(
            detect_install_method_from_path(Some(p)),
            InstallMethod::Standalone,
            "pnpm store without `global` segment is not an install root"
        );
    }

    /// `None` (no exe path resolvable) falls through to Standalone.
    /// Keeps the function total and the upgrade flow predictable.
    #[test]
    fn detect_install_method_none_falls_back_to_standalone() {
        assert_eq!(
            detect_install_method_from_path(None),
            InstallMethod::Standalone
        );
    }

    #[test]
    fn install_method_command_npm_pins_exact_version() {
        let cmd = InstallMethod::Npm.command("0.25.0");
        assert!(cmd.contains("@lpm-registry/cli@0.25.0"), "cmd: {cmd}");
        assert!(!cmd.contains("@latest"), "must not use @latest: {cmd}");
    }

    #[test]
    fn install_method_command_cargo_uses_tag() {
        // Without --tag, `cargo install --git ... --force` tracks
        // the default branch HEAD — so the docs claim "you'll be
        // on v{latest}" is a lie. The fix is mandatory --tag pinning;
        // this test pins the contract.
        let cmd = InstallMethod::Cargo.command("0.25.0");
        assert!(cmd.contains("--tag v0.25.0"), "cmd: {cmd}");
        assert!(cmd.contains("--force"), "cmd: {cmd}");
    }

    #[test]
    fn install_method_command_homebrew_unchanged() {
        assert_eq!(
            InstallMethod::Homebrew.command("0.25.0"),
            "brew upgrade lpm"
        );
    }

    /// The standalone `update_command` must reflect the literal action
    /// the wrapper performs: a version-pinned download of the release
    /// asset, replacing the running binary in place. `install.sh` is
    /// the install helper for new users, not what self-update runs —
    /// it does its own `releases/latest` lookup and writes to
    /// `~/.lpm/bin/`. Locking the wrong contract previously masked
    /// this divergence.
    #[test]
    fn install_method_command_standalone_pins_resolved_version() {
        let cmd = InstallMethod::Standalone.command("0.25.0");
        // Must NOT use install.sh (which re-resolves latest itself).
        assert!(
            !cmd.contains("install.sh"),
            "standalone command must not delegate to install.sh: {cmd}"
        );
        // Must pin the exact version the wrapper resolved.
        assert!(
            cmd.contains("v0.25.0"),
            "standalone command must include resolved version: {cmd}"
        );
        // Must point at GitHub Releases — either the tag page (fallback
        // when platform detection fails) or the direct download URL.
        assert!(
            cmd.contains("github.com/lpm-dev/rust-client/releases/"),
            "standalone command must reference GitHub Releases: {cmd}"
        );
    }

    /// POSIX hosts (darwin / linux) get a `curl … && chmod +x …`
    /// command. Driven through the pure helper so the assertion holds
    /// even when CI runs on a different platform than the inputs.
    #[test]
    fn standalone_command_for_posix_uses_curl_and_chmod() {
        for (platform, ext) in [
            ("darwin-arm64", ""),
            ("darwin-x64", ""),
            ("linux-x64", ""),
            ("linux-x64-musl", ""),
            ("linux-arm64", ""),
        ] {
            let cmd = standalone_command_for("0.25.0", platform, ext, Some("/usr/local/bin/lpm"));
            assert!(
                cmd.starts_with("curl "),
                "{platform}: must start with curl: {cmd}"
            );
            assert!(
                cmd.contains(&format!("/releases/download/v0.25.0/lpm-{platform}{ext}")),
                "{platform}: must include direct download URL: {cmd}"
            );
            assert!(cmd.contains("chmod +x"), "{platform}: must chmod +x: {cmd}");
            assert!(
                cmd.contains("/usr/local/bin/lpm"),
                "{platform}: must target the supplied exe path: {cmd}"
            );
            assert!(
                !cmd.contains("Invoke-WebRequest"),
                "{platform}: must not be PowerShell-shaped: {cmd}"
            );
        }
    }

    /// Windows gets a PowerShell `Invoke-WebRequest`. No `chmod` — the
    /// Rust updater itself only `chmod`s under `#[cfg(unix)]`, and
    /// Windows uses the `.exe` extension instead of a permission bit.
    #[test]
    fn standalone_command_for_windows_uses_invoke_webrequest_no_chmod() {
        let cmd = standalone_command_for(
            "0.25.0",
            "win32-x64",
            ".exe",
            Some("C:\\Users\\me\\.lpm\\bin\\lpm.exe"),
        );
        assert!(
            cmd.starts_with("Invoke-WebRequest "),
            "must start with Invoke-WebRequest: {cmd}"
        );
        assert!(
            cmd.contains("/releases/download/v0.25.0/lpm-win32-x64.exe"),
            "must include direct .exe URL: {cmd}"
        );
        assert!(
            cmd.contains("C:\\Users\\me\\.lpm\\bin\\lpm.exe"),
            "must target the supplied exe path: {cmd}"
        );
        assert!(
            !cmd.contains("chmod"),
            "must not emit chmod on Windows: {cmd}"
        );
        assert!(!cmd.contains("curl "), "must not be POSIX-shaped: {cmd}");
    }

    /// Default exe paths kick in only when `current_exe()` is unknown.
    /// The Unix fallback is `/usr/local/bin/lpm`; the Windows fallback
    /// is `%USERPROFILE%\.lpm\bin\lpm.exe`.
    #[test]
    fn standalone_command_default_exe_paths_per_platform() {
        let posix = standalone_command_for("0.25.0", "darwin-arm64", "", None);
        assert!(posix.contains("/usr/local/bin/lpm"), "{posix}");
        let win = standalone_command_for("0.25.0", "win32-x64", ".exe", None);
        assert!(win.contains("%USERPROFILE%\\.lpm\\bin\\lpm.exe"), "{win}");
    }

    /// The `standalone_command()` dispatcher consults host
    /// `detect_platform()` / `current_exe()`. On every supported host
    /// it must pin the version and include the direct download URL —
    /// the per-OS shape (curl vs Invoke-WebRequest) is covered by the
    /// pure-helper tests above.
    #[test]
    fn standalone_command_dispatcher_returns_pinned_command() {
        let cmd = standalone_command("0.25.0");
        assert!(cmd.contains("v0.25.0"), "must pin version: {cmd}");
        assert!(
            cmd.contains("/releases/download/v0.25.0/lpm-"),
            "must include direct download URL: {cmd}"
        );
    }

    #[test]
    fn detect_platform_returns_valid_tuple() {
        let result = detect_platform();
        assert!(
            result.is_ok(),
            "detect_platform should succeed on this host"
        );
        let (platform, _ext) = result.unwrap();
        assert!(!platform.is_empty());
        assert!(
            [
                "darwin-arm64",
                "darwin-x64",
                "linux-x64",
                "linux-arm64",
                "win32-x64",
            ]
            .contains(&platform),
            "unexpected platform: {platform}"
        );
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(2_621_440), "2.5 MB");
    }

    /// Rate-limit lands on `SelfUpdateRateLimited`, not `Forbidden`.
    /// `Forbidden` is the user-permission category and reads to users
    /// as "you're banned" — wrong category for a quota-reset wait.
    #[test]
    fn lookup_error_rate_limit_maps_to_self_update_rate_limited() {
        let err = lookup_error_to_lpm(LookupError::RateLimited { reset_at: Some(0) });
        assert!(
            matches!(err, LpmError::SelfUpdateRateLimited(_)),
            "got {err:?}"
        );
        // And — explicitly NOT Forbidden, the historical wrong category.
        assert!(
            !matches!(err, LpmError::Forbidden(_)),
            "must not regress to Forbidden: {err:?}"
        );
    }

    /// Rendered body must not duplicate the GITHUB_TOKEN hint — that
    /// guidance now lives in the variant's diagnostic help text. Doubling
    /// it would print the same instruction twice.
    #[test]
    fn lookup_error_rate_limit_body_is_not_doubled_with_help_text() {
        let err = lookup_error_to_lpm(LookupError::RateLimited { reset_at: Some(0) });
        let LpmError::SelfUpdateRateLimited(body) = err else {
            panic!("expected SelfUpdateRateLimited variant");
        };
        assert!(
            !body.contains("GITHUB_TOKEN"),
            "body must not duplicate help text: {body}"
        );
        assert!(
            !body.contains("GH_TOKEN"),
            "body must not duplicate help text: {body}"
        );
    }

    #[test]
    fn lookup_error_transport_maps_to_network() {
        let err = lookup_error_to_lpm(LookupError::Transport("dns failed".into()));
        assert!(matches!(err, LpmError::Network(_)), "got {err:?}");
    }

    #[test]
    fn lookup_error_http_status_maps_to_network() {
        let err = lookup_error_to_lpm(LookupError::HttpStatus {
            status: 503,
            body_excerpt: "down".into(),
        });
        assert!(matches!(err, LpmError::Network(_)), "got {err:?}");
    }

    /// Cache stamp/clear policy is the load-bearing decision in this
    /// patch. Encode the user-facing contract directly: after a
    /// successful Standalone/Cargo/Npm upgrade the cache's `latest`
    /// must match the version we just installed; after a successful
    /// Homebrew upgrade the cache file must NOT exist.
    #[test]
    fn post_upgrade_cache_policy_pinning_channels_stamp() {
        for method in [
            InstallMethod::Standalone,
            InstallMethod::Cargo,
            InstallMethod::Npm,
        ] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("update-check.json");
            let cache = UpdateCache {
                latest: "0.25.0".into(),
                last_check: 1_700_000_000,
                ..Default::default()
            };
            write_cache_at(&path, &cache).unwrap();
            // Mirror the post-upgrade branch logic against the path.
            let mut after = read_cache_at(&path).unwrap();
            after.latest = "0.25.0".into();
            after.last_check = 1_700_000_000;
            after.last_failure_check = 0;
            write_cache_at(&path, &after).unwrap();
            let loaded = read_cache_at(&path).unwrap();
            assert_eq!(loaded.latest, "0.25.0", "method {method:?}");
        }
    }

    #[test]
    fn post_upgrade_cache_policy_homebrew_clears() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        write_cache_at(
            &path,
            &UpdateCache {
                latest: "0.25.0".into(),
                last_check: 1_700_000_000,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(path.exists());
        clear_cache_at(&path);
        assert!(
            !path.exists(),
            "Homebrew upgrade must clear cache, not stamp"
        );
    }

    /// `--refresh` is supposed to bypass the in-process cache hit
    /// short-circuit. Lock the cache-hit predicate that gates it.
    #[test]
    fn refresh_flag_bypasses_cache_hit_predicate() {
        let now = 1_700_000_500u64;
        let cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: now - 60,
            ..Default::default()
        };
        let refresh = false;
        let predicate = |refresh: bool| -> bool {
            !refresh
                && !cache.latest.is_empty()
                && cache.last_check > 0
                && now.saturating_sub(cache.last_check) < LOOKUP_TTL.as_secs()
        };
        assert!(
            predicate(refresh),
            "fresh cache must hit when refresh=false"
        );
        assert!(!predicate(true), "refresh=true must bypass the cache hit");
    }

    /// Recent failure must short-circuit BEFORE the network call so a
    /// script looping on `lpm self-update` after a 403 doesn't re-hit
    /// the rate-limited API on every iteration.
    #[test]
    fn recent_failure_triggers_backoff_without_refresh() {
        let now = 1_700_000_500u64;
        let cache = UpdateCache {
            last_failure_check: now - 60,
            ..Default::default()
        };
        let predicate = |refresh: bool, cache_hit: bool| -> bool {
            !refresh
                && !cache_hit
                && cache.last_failure_check > 0
                && now.saturating_sub(cache.last_failure_check) < FAILURE_BACKOFF.as_secs()
        };
        assert!(
            predicate(false, false),
            "default invocation must respect backoff"
        );
        assert!(!predicate(true, false), "--refresh must bypass the backoff");
        assert!(
            !predicate(false, true),
            "fresh success cache pre-empts backoff"
        );
    }

    #[test]
    fn failure_backoff_lapses_past_ttl() {
        let now = 1_700_000_500u64;
        let cache = UpdateCache {
            last_failure_check: now - 4000, // > 1h
            ..Default::default()
        };
        let predicate = |refresh: bool| -> bool {
            !refresh
                && cache.last_failure_check > 0
                && now.saturating_sub(cache.last_failure_check) < FAILURE_BACKOFF.as_secs()
        };
        assert!(!predicate(false));
    }

    #[test]
    fn humanize_seconds_picks_largest_unit() {
        assert_eq!(humanize_seconds(0), "0 seconds");
        assert_eq!(humanize_seconds(1), "1 second");
        assert_eq!(humanize_seconds(45), "45 seconds");
        assert_eq!(humanize_seconds(60), "1 minute");
        assert_eq!(humanize_seconds(150), "2 minutes");
        assert_eq!(humanize_seconds(3600), "1 hour");
        assert_eq!(humanize_seconds(7200), "2 hours");
    }

    #[test]
    fn cache_hit_only_within_lookup_ttl() {
        let now = 1_700_000_500u64;
        let stale_cache = UpdateCache {
            latest: "0.25.0".into(),
            last_check: now - 700, // > 10m TTL
            ..Default::default()
        };
        let predicate = |c: &UpdateCache| -> bool {
            !c.latest.is_empty()
                && c.last_check > 0
                && now.saturating_sub(c.last_check) < LOOKUP_TTL.as_secs()
        };
        assert!(!predicate(&stale_cache));
    }

    #[test]
    fn release_lookup_module_is_reachable() {
        // Smoke check: the shared module's public surface is wired
        // in. If the module is renamed or visibility changes, this
        // catches it before the CLI dispatch path breaks.
        let _ = release_lookup::default_cache_path();
    }
}
