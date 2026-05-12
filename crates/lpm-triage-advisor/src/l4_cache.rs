//! Phase 46b — L4 verdict cache.
//!
//! Persists `{cache-key → (verdict, cached_at)}` mappings so the second
//! and subsequent installs of any amber-classified package on a given
//! machine skip the LLM round-trip entirely.
//!
//! # Cache identity
//!
//! Cache key = SHA-256 over the four axes a cached verdict implicitly
//! depends on:
//!
//! 1. **Script identity** — `(name, version, phase, body)` for every
//!    amber phase the advisor would classify. Same package contents
//!    → same hash, regardless of which workspace called.
//! 2. **Prompt template hash** — rotates on any prompt-template change
//!    via [`crate::prompt_template_hash`]. A calibration bump
//!    auto-invalidates every cached verdict the old template produced.
//! 3. **Provider slug** — `claude-cli`, `codex`, `ollama`. Different
//!    providers produce different verdicts on the same script; their
//!    cache namespaces never collide.
//! 4. **Model version** — captures provider-version drift the slug
//!    doesn't (e.g. `claude-3-5-sonnet-20241022` vs
//!    `claude-3-5-sonnet-20250101`).
//!
//! Any one of these changing produces a different key; the affected
//! entries are skipped on lookup and overwritten on the next classify.
//! No explicit invalidation step is needed.
//!
//! # On-disk layout
//!
//! ```text
//! $LPM_HOME/cache/l4-verdicts.json
//! ```
//!
//! JSON with a top-level `version` (schema) and an `entries` map.
//! Atomic write-then-rename so a crash mid-persist doesn't corrupt
//! the file. Reads are tolerant of an unparseable file (treat as
//! empty cache and overwrite on next persist).
//!
//! # Concurrency
//!
//! The advisor session can fan out per-package classifications with
//! `buffer_unordered`; the cache must be safe to read+write from
//! multiple tasks. Internal state is wrapped in `parking_lot::Mutex`
//! via [`std::sync::Mutex`] equivalents in `std`. Held only across
//! quick lookups/inserts; never across an LLM call.
//!
//! # Disable / opt out
//!
//! Set `LPM_L4_CACHE=0` (or any value besides `1`/`true`/`yes`) to
//! short-circuit the cache to a no-op. Useful for measurement runs
//! where the comparison must include the round-trip cost.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AdvisorVerdict;

/// Schema version for the on-disk cache file. Bump when the layout
/// changes in a backward-incompatible way; older files are then
/// silently discarded on load.
const CACHE_SCHEMA_VERSION: u32 = 1;

/// Default verdict TTL. 30 days. After this, even an exact-key hit is
/// treated as stale and the advisor is re-invoked.
pub const DEFAULT_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Env var that disables the cache entirely when set to a non-truthy
/// value. Lets measurement runs compare cold cost without an
/// already-warm cache speed-loading the second run.
const DISABLE_ENV_VAR: &str = "LPM_L4_CACHE";

/// Env var that overrides the cache file path. Defaults to
/// `$LPM_HOME/cache/l4-verdicts.json` (or `$HOME/.lpm/...` if
/// `LPM_HOME` is unset). Tests use a per-tempdir path.
const PATH_ENV_VAR: &str = "LPM_L4_CACHE_PATH";

/// Env var for the cache file TTL in seconds.
const TTL_ENV_VAR: &str = "LPM_L4_CACHE_TTL_SECS";

/// Cached per-key entry. Verdict + freshness stamp + the (provider,
/// model, prompt) tuple that produced it. The tuple is duplicated
/// here purely for debug introspection — the LOOKUP key already
/// folds those fields into the hash, so a key collision is
/// impossible (per the hash's preimage resistance) and the entry's
/// tuple is informational.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    verdict: VerdictRepr,
    cached_at_unix: u64,
    /// Debug-only — the provider slug that produced this verdict.
    /// Folded into the key, so this is for inspecting the cache file
    /// by hand, not for lookup logic.
    provider_slug: String,
    /// Debug-only — the model version slug. Folded into the key for
    /// the same reason as `provider_slug`.
    model_version: String,
    /// Debug-only — the prompt template hash. Folded into the key.
    prompt_template_hash: String,
}

/// Wire representation of [`AdvisorVerdict`] for the JSON file. We
/// could reuse the upstream enum via `#[serde(rename_all =
/// "kebab-case")]` (which is what [`AdvisorVerdict`] already does),
/// but a local mirror keeps the cache file's schema stable even if
/// the upstream enum gets new variants.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum VerdictRepr {
    Approve,
    Manual,
    Abstain,
}

impl From<AdvisorVerdict> for VerdictRepr {
    fn from(v: AdvisorVerdict) -> Self {
        match v {
            AdvisorVerdict::Approve => VerdictRepr::Approve,
            AdvisorVerdict::Manual => VerdictRepr::Manual,
            AdvisorVerdict::Abstain => VerdictRepr::Abstain,
        }
    }
}

impl From<VerdictRepr> for AdvisorVerdict {
    fn from(v: VerdictRepr) -> Self {
        match v {
            VerdictRepr::Approve => AdvisorVerdict::Approve,
            VerdictRepr::Manual => AdvisorVerdict::Manual,
            VerdictRepr::Abstain => AdvisorVerdict::Abstain,
        }
    }
}

/// On-disk cache layout. Versioned for forward-compat.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheFile {
    version: u32,
    entries: HashMap<String, CacheEntry>,
}

impl Default for CacheFile {
    fn default() -> Self {
        Self {
            version: CACHE_SCHEMA_VERSION,
            entries: HashMap::new(),
        }
    }
}

/// L4 verdict cache. Construct with [`L4Cache::open_default`] for the
/// canonical `$LPM_HOME/cache/l4-verdicts.json` path, or
/// [`L4Cache::open_at`] for a custom path (tests).
///
/// All operations are no-ops when [`L4Cache::is_disabled`] returns
/// true — lookups always miss, inserts are dropped, persist is a
/// no-op. That lets the cache be wired in unconditionally; callers
/// don't have to branch on the env var.
pub struct L4Cache {
    path: PathBuf,
    ttl: Duration,
    disabled: bool,
    inner: Mutex<CacheFile>,
}

impl L4Cache {
    /// Open the cache at the canonical path. Honors `LPM_L4_CACHE_PATH`
    /// (override), `LPM_HOME` (LPM root, defaults to `~/.lpm`),
    /// `LPM_L4_CACHE_TTL_SECS` (override default TTL), and
    /// `LPM_L4_CACHE=0` (disable).
    ///
    /// Errors on path-resolution failure only (e.g. no usable HOME).
    /// File-not-found and parse errors are silent: the cache starts
    /// empty and overwrites the bad file on the next persist.
    pub fn open_default() -> io::Result<Self> {
        let path = resolve_default_path()?;
        let ttl = resolve_ttl();
        let disabled = is_disabled();
        Self::open_at_with(path, ttl, disabled)
    }

    /// Open the cache at an explicit path (test entry point). The
    /// caller controls both the location and the TTL. The disable
    /// flag still honors the env var.
    pub fn open_at(path: PathBuf, ttl: Duration) -> io::Result<Self> {
        Self::open_at_with(path, ttl, is_disabled())
    }

    fn open_at_with(path: PathBuf, ttl: Duration, disabled: bool) -> io::Result<Self> {
        let file = if disabled {
            CacheFile::default()
        } else {
            load_or_default(&path)
        };
        Ok(Self {
            path,
            ttl,
            disabled,
            inner: Mutex::new(file),
        })
    }

    /// Is this cache disabled via env? Wrapped methods are no-ops
    /// when true.
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Return the underlying cache path (informational; useful for
    /// "cache at /Users/.../l4-verdicts.json" log lines).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How many entries the in-memory map currently holds (for
    /// diagnostics and tests).
    pub fn entry_count(&self) -> usize {
        if self.disabled {
            return 0;
        }
        self.inner.lock().unwrap().entries.len()
    }

    /// Look up a cached verdict. Returns `None` on:
    /// - cache disabled (always),
    /// - key not present,
    /// - entry exists but `cached_at + ttl < now`.
    pub fn lookup(&self, key: &str) -> Option<AdvisorVerdict> {
        if self.disabled {
            return None;
        }
        let guard = self.inner.lock().unwrap();
        let entry = guard.entries.get(key)?;
        if is_expired(entry.cached_at_unix, self.ttl) {
            return None;
        }
        Some(entry.verdict.into())
    }

    /// Insert / overwrite a cached verdict. The cached_at stamp is
    /// captured at insert time. No-op if the cache is disabled.
    ///
    /// The `provider_slug`, `model_version`, and `prompt_template_hash`
    /// fields are stored alongside the verdict for debug introspection.
    /// They MUST match the values folded into `key` via
    /// [`build_cache_key`] — passing mismatched values here would
    /// silently break diagnostics (but never lookup correctness, since
    /// lookup keys off the hash alone).
    pub fn insert(
        &self,
        key: String,
        verdict: AdvisorVerdict,
        provider_slug: &str,
        model_version: &str,
        prompt_template_hash: &str,
    ) {
        if self.disabled {
            return;
        }
        let entry = CacheEntry {
            verdict: verdict.into(),
            cached_at_unix: now_unix_seconds(),
            provider_slug: provider_slug.to_string(),
            model_version: model_version.to_string(),
            prompt_template_hash: prompt_template_hash.to_string(),
        };
        self.inner.lock().unwrap().entries.insert(key, entry);
    }

    /// Atomically write the in-memory map to disk. No-op if disabled.
    ///
    /// Writes to `<path>.tmp` then renames over `<path>`, so a crash
    /// mid-write leaves the prior file intact. Creates the parent
    /// directory if missing.
    pub fn persist(&self) -> io::Result<()> {
        if self.disabled {
            return Ok(());
        }
        let snapshot = self.inner.lock().unwrap().clone();
        persist_snapshot(&self.path, &snapshot)
    }
}

fn persist_snapshot(path: &Path, file: &CacheFile) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(file)
        .map_err(|e| io::Error::other(format!("serialize l4 cache: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn load_or_default(path: &Path) -> CacheFile {
    let Ok(bytes) = fs::read(path) else {
        return CacheFile::default();
    };
    match serde_json::from_slice::<CacheFile>(&bytes) {
        Ok(f) if f.version == CACHE_SCHEMA_VERSION => f,
        _ => CacheFile::default(),
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_expired(cached_at_unix: u64, ttl: Duration) -> bool {
    let now = now_unix_seconds();
    now.saturating_sub(cached_at_unix) >= ttl.as_secs()
}

fn is_disabled() -> bool {
    match env::var(DISABLE_ENV_VAR) {
        Ok(v) => !matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => false,
    }
}

fn resolve_ttl() -> Duration {
    if let Ok(v) = env::var(TTL_ENV_VAR)
        && let Ok(secs) = v.parse::<u64>()
    {
        return Duration::from_secs(secs);
    }
    DEFAULT_TTL
}

fn resolve_default_path() -> io::Result<PathBuf> {
    if let Ok(p) = env::var(PATH_ENV_VAR) {
        return Ok(PathBuf::from(p));
    }
    let lpm_home = env::var_os("LPM_HOME").map(PathBuf::from).or_else(|| {
        env::var_os("HOME").map(|h| {
            let mut p = PathBuf::from(h);
            p.push(".lpm");
            p
        })
    });
    let Some(root) = lpm_home else {
        return Err(io::Error::other(
            "cannot resolve LPM_HOME (no LPM_HOME and no HOME env var)",
        ));
    };
    Ok(root.join("cache").join("l4-verdicts.json"))
}

/// Inputs to the cache key for one package's classification. Mirrors
/// the install pipeline's `AmberPackageRequest` shape minus the
/// integrity slot (which doesn't affect the verdict) and plus the
/// advisor identity (which does).
///
/// Phases must be passed in a canonical order; the cache key folds
/// each `(phase, body)` pair into the hash, so re-ordering the
/// caller's loop would otherwise produce two cache entries for the
/// same install. Use the `EXECUTED_INSTALL_PHASES`-aligned ordering
/// (preinstall, install, postinstall) — same order
/// `compute_script_hash` uses.
pub struct CacheKeyInputs<'a> {
    pub package_name: &'a str,
    pub package_version: &'a str,
    /// `(phase, body)` pairs in canonical order. Filter to amber-only
    /// before passing — green/red phases never reach L4 and would
    /// pollute the key.
    pub amber_phases: &'a [(&'a str, &'a str)],
    /// Phase 46b Lever #1 — the package's `repository` URL when
    /// present. The advisor's prompt embeds this and bases its
    /// "fetch IDENTITY" judgment on it; two installs of the same
    /// `(name, version, body)` triple with different repository URLs
    /// can legitimately receive different verdicts, so the cache key
    /// must distinguish them. `None` folds in differently from
    /// `Some("")` so the absent and empty-string cases stay
    /// distinguishable.
    pub repository: Option<&'a str>,
    /// Phase 46b Lever #3 — files the script body delegates to,
    /// each as `(filename, content)` in canonical order. Two
    /// installs with the same body but different referenced-file
    /// content can legitimately produce different verdicts (the
    /// embedded content IS what the model judges), so the cache
    /// key must distinguish them. Empty slice folds in as "no
    /// referenced files," which differs from a slice containing
    /// one empty `(filename, "")` pair.
    pub referenced_scripts: &'a [(&'a str, &'a str)],
    pub prompt_template_hash: &'a str,
    pub provider_slug: &'a str,
    pub model_version: &'a str,
}

/// Build the cache key for one package's classification. Pure: same
/// inputs → same output across machines and runs.
///
/// The hash folds every input axis the verdict depends on:
/// package_name, package_version, each `(phase, body)` pair,
/// prompt_template_hash, provider_slug, model_version.
/// Distinct separators between fields prevent the
/// `name="ab" version="cd"` / `name="abc" version="d"` ambiguity that
/// a naive concatenation would have.
pub fn build_cache_key(inputs: &CacheKeyInputs<'_>) -> String {
    const FIELD_SEP: u8 = 0x00;
    const RECORD_SEP: u8 = 0x1e;
    // Phase 46b Lever #1 — distinct absent / present sentinels for
    // the optional repository field. `Some("github.com/x/y")` and
    // `None` must hash differently. We also distinguish from
    // `Some("")` by emitting the sentinel byte before any payload
    // bytes.
    const REPO_PRESENT: u8 = 0x01;
    const REPO_ABSENT: u8 = 0x02;
    // Phase 46b Lever #3 — sentinel separating the referenced-files
    // section from the rest of the key. Distinct from FIELD_SEP /
    // RECORD_SEP so the section boundary is unambiguous in the
    // hash input stream.
    const REF_SECTION_SEP: u8 = 0x1f;

    let mut h = Sha256::new();
    h.update(inputs.package_name.as_bytes());
    h.update([FIELD_SEP]);
    h.update(inputs.package_version.as_bytes());
    h.update([FIELD_SEP]);
    for (phase, body) in inputs.amber_phases {
        h.update(phase.as_bytes());
        h.update([FIELD_SEP]);
        h.update(body.as_bytes());
        h.update([RECORD_SEP]);
    }
    h.update([FIELD_SEP]);
    match inputs.repository {
        Some(repo) => {
            h.update([REPO_PRESENT]);
            h.update(repo.as_bytes());
        }
        None => {
            h.update([REPO_ABSENT]);
        }
    }
    h.update([REF_SECTION_SEP]);
    for (filename, content) in inputs.referenced_scripts {
        h.update(filename.as_bytes());
        h.update([FIELD_SEP]);
        h.update(content.as_bytes());
        h.update([RECORD_SEP]);
    }
    h.update([FIELD_SEP]);
    h.update(inputs.prompt_template_hash.as_bytes());
    h.update([FIELD_SEP]);
    h.update(inputs.provider_slug.as_bytes());
    h.update([FIELD_SEP]);
    h.update(inputs.model_version.as_bytes());
    format!("sha256-{}", hex_lower(&h.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn key_for(
        name: &str,
        version: &str,
        phases: &[(&str, &str)],
        template_hash: &str,
        provider: &str,
        model: &str,
    ) -> String {
        build_cache_key(&CacheKeyInputs {
            package_name: name,
            package_version: version,
            amber_phases: phases,
            repository: None,
            referenced_scripts: &[],
            prompt_template_hash: template_hash,
            provider_slug: provider,
            model_version: model,
        })
    }

    fn key_for_with_repo(
        name: &str,
        version: &str,
        phases: &[(&str, &str)],
        repository: Option<&str>,
        template_hash: &str,
        provider: &str,
        model: &str,
    ) -> String {
        build_cache_key(&CacheKeyInputs {
            package_name: name,
            package_version: version,
            amber_phases: phases,
            repository,
            referenced_scripts: &[],
            prompt_template_hash: template_hash,
            provider_slug: provider,
            model_version: model,
        })
    }

    fn key_for_with_refs(
        name: &str,
        version: &str,
        phases: &[(&str, &str)],
        referenced_scripts: &[(&str, &str)],
        template_hash: &str,
        provider: &str,
        model: &str,
    ) -> String {
        build_cache_key(&CacheKeyInputs {
            package_name: name,
            package_version: version,
            amber_phases: phases,
            repository: None,
            referenced_scripts,
            prompt_template_hash: template_hash,
            provider_slug: provider,
            model_version: model,
        })
    }

    #[test]
    fn cache_key_is_deterministic() {
        let a = key_for(
            "sharp",
            "0.34.4",
            &[("install", "node install.js")],
            "sha256-aaa",
            "claude-cli",
            "2.1.138",
        );
        let b = key_for(
            "sharp",
            "0.34.4",
            &[("install", "node install.js")],
            "sha256-aaa",
            "claude-cli",
            "2.1.138",
        );
        assert_eq!(a, b);
        assert!(a.starts_with("sha256-"));
    }

    #[test]
    fn cache_key_differs_per_axis() {
        let base = key_for(
            "p",
            "1.0.0",
            &[("install", "node install.js")],
            "sha256-aaa",
            "claude-cli",
            "v1",
        );
        // Different package name → different key.
        assert_ne!(
            base,
            key_for(
                "q",
                "1.0.0",
                &[("install", "node install.js")],
                "sha256-aaa",
                "claude-cli",
                "v1",
            )
        );
        // Different version → different key.
        assert_ne!(
            base,
            key_for(
                "p",
                "1.0.1",
                &[("install", "node install.js")],
                "sha256-aaa",
                "claude-cli",
                "v1",
            )
        );
        // Different phase → different key.
        assert_ne!(
            base,
            key_for(
                "p",
                "1.0.0",
                &[("postinstall", "node install.js")],
                "sha256-aaa",
                "claude-cli",
                "v1",
            )
        );
        // Different body → different key.
        assert_ne!(
            base,
            key_for(
                "p",
                "1.0.0",
                &[("install", "node other.js")],
                "sha256-aaa",
                "claude-cli",
                "v1",
            )
        );
        // Different prompt template hash → different key.
        assert_ne!(
            base,
            key_for(
                "p",
                "1.0.0",
                &[("install", "node install.js")],
                "sha256-bbb",
                "claude-cli",
                "v1",
            )
        );
        // Different provider → different key.
        assert_ne!(
            base,
            key_for(
                "p",
                "1.0.0",
                &[("install", "node install.js")],
                "sha256-aaa",
                "codex",
                "v1",
            )
        );
        // Different model version → different key.
        assert_ne!(
            base,
            key_for(
                "p",
                "1.0.0",
                &[("install", "node install.js")],
                "sha256-aaa",
                "claude-cli",
                "v2",
            )
        );
    }

    #[test]
    fn cache_key_distinguishes_repository_axes() {
        // Phase 46b Lever #1 — `repository` is a verdict input;
        // adding or changing it must produce a different cache key
        // so a re-fetched verdict respects the prompt change.
        let none = key_for_with_repo("p", "1.0.0", &[("install", "x")], None, "h", "p", "m");
        let some_a = key_for_with_repo(
            "p",
            "1.0.0",
            &[("install", "x")],
            Some("github.com/lovell/sharp"),
            "h",
            "p",
            "m",
        );
        let some_b = key_for_with_repo(
            "p",
            "1.0.0",
            &[("install", "x")],
            Some("github.com/another/pkg"),
            "h",
            "p",
            "m",
        );
        let empty = key_for_with_repo("p", "1.0.0", &[("install", "x")], Some(""), "h", "p", "m");
        assert_ne!(none, some_a, "None vs Some(...) must differ");
        assert_ne!(some_a, some_b, "different repo URLs must differ");
        assert_ne!(
            none, empty,
            "None vs Some(\"\") must differ — the sentinel byte separates them"
        );
    }

    #[test]
    fn cache_key_distinguishes_referenced_script_axes() {
        // Phase 46b Lever #3 — referenced scripts are a verdict
        // input; adding files or changing their content must
        // produce a different cache key.
        let empty = key_for_with_refs("p", "1.0.0", &[("install", "x")], &[], "h", "p", "m");
        let with_one = key_for_with_refs(
            "p",
            "1.0.0",
            &[("install", "x")],
            &[("./install.js", "content a")],
            "h",
            "p",
            "m",
        );
        let with_changed = key_for_with_refs(
            "p",
            "1.0.0",
            &[("install", "x")],
            &[("./install.js", "content b")],
            "h",
            "p",
            "m",
        );
        let with_two = key_for_with_refs(
            "p",
            "1.0.0",
            &[("install", "x")],
            &[("./install.js", "content a"), ("./other.js", "")],
            "h",
            "p",
            "m",
        );
        assert_ne!(empty, with_one, "empty vs one file must differ");
        assert_ne!(with_one, with_changed, "changed file content must differ");
        assert_ne!(with_one, with_two, "adding files must differ");
    }

    #[test]
    fn cache_key_disambiguates_field_boundaries() {
        // FIELD_SEP between name+version means `name="ab" version="cd"`
        // and `name="abc" version="d"` must hash differently.
        let a = key_for("ab", "cd", &[], "h", "p", "m");
        let b = key_for("abc", "d", &[], "h", "p", "m");
        assert_ne!(a, b);
    }

    #[test]
    fn cache_key_distinguishes_phase_order() {
        // `[(install, A), (postinstall, B)]` should hash differently
        // from `[(install, B), (postinstall, A)]` — moving a body
        // between phases changes the verdict input.
        let a = key_for(
            "p",
            "1.0.0",
            &[("install", "A"), ("postinstall", "B")],
            "h",
            "p",
            "m",
        );
        let b = key_for(
            "p",
            "1.0.0",
            &[("install", "B"), ("postinstall", "A")],
            "h",
            "p",
            "m",
        );
        assert_ne!(a, b);
    }

    fn fresh_cache() -> (L4Cache, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("l4.json");
        // We bypass the env-var disable check by calling
        // `open_at_with` with `disabled=false` directly. Tests assert
        // on cache contents and shouldn't care about the host env.
        let cache = L4Cache {
            path: path.clone(),
            ttl: DEFAULT_TTL,
            disabled: false,
            inner: Mutex::new(CacheFile::default()),
        };
        (cache, dir)
    }

    #[test]
    fn lookup_misses_on_empty_cache() {
        let (cache, _dir) = fresh_cache();
        let k = key_for(
            "p",
            "1.0.0",
            &[("install", "node install.js")],
            "h",
            "p",
            "m",
        );
        assert!(cache.lookup(&k).is_none());
    }

    #[test]
    fn insert_then_lookup_returns_verdict() {
        let (cache, _dir) = fresh_cache();
        let k = key_for(
            "p",
            "1.0.0",
            &[("install", "node install.js")],
            "h",
            "p",
            "m",
        );
        cache.insert(k.clone(), AdvisorVerdict::Approve, "p", "m", "h");
        assert_eq!(cache.lookup(&k), Some(AdvisorVerdict::Approve));
    }

    #[test]
    fn ttl_expiry_is_a_miss() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("l4.json");
        // 0-second TTL: any cached entry is immediately stale.
        let cache = L4Cache {
            path,
            ttl: Duration::from_secs(0),
            disabled: false,
            inner: Mutex::new(CacheFile::default()),
        };
        let k = key_for(
            "p",
            "1.0.0",
            &[("install", "node install.js")],
            "h",
            "p",
            "m",
        );
        cache.insert(k.clone(), AdvisorVerdict::Approve, "p", "m", "h");
        // TTL = 0 means `now - cached_at >= 0` always, so lookup misses.
        assert!(cache.lookup(&k).is_none());
    }

    #[test]
    fn persist_and_reload_round_trips_verdict() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("l4.json");
        {
            let cache = L4Cache {
                path: path.clone(),
                ttl: DEFAULT_TTL,
                disabled: false,
                inner: Mutex::new(CacheFile::default()),
            };
            let k = key_for(
                "p",
                "1.0.0",
                &[("install", "node install.js")],
                "h",
                "p",
                "m",
            );
            cache.insert(k.clone(), AdvisorVerdict::Manual, "p", "m", "h");
            cache.persist().unwrap();
        }
        // Re-load and confirm the verdict is still there.
        let reloaded = L4Cache {
            path: path.clone(),
            ttl: DEFAULT_TTL,
            disabled: false,
            inner: Mutex::new(load_or_default(&path)),
        };
        let k = key_for(
            "p",
            "1.0.0",
            &[("install", "node install.js")],
            "h",
            "p",
            "m",
        );
        assert_eq!(reloaded.lookup(&k), Some(AdvisorVerdict::Manual));
        assert_eq!(reloaded.entry_count(), 1);
    }

    #[test]
    fn disabled_cache_lookups_miss_and_inserts_drop() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("l4.json");
        let cache = L4Cache {
            path,
            ttl: DEFAULT_TTL,
            disabled: true,
            inner: Mutex::new(CacheFile::default()),
        };
        let k = key_for("p", "1.0.0", &[("install", "x")], "h", "p", "m");
        cache.insert(k.clone(), AdvisorVerdict::Approve, "p", "m", "h");
        assert!(cache.lookup(&k).is_none());
        assert_eq!(cache.entry_count(), 0);
        // Persist on a disabled cache should be a no-op (no file
        // created).
        cache.persist().unwrap();
        assert!(!cache.path().exists());
    }

    #[test]
    fn corrupt_cache_file_is_reset_silently() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("l4.json");
        fs::write(&path, "{not valid json").unwrap();
        let loaded = load_or_default(&path);
        assert_eq!(loaded.version, CACHE_SCHEMA_VERSION);
        assert!(loaded.entries.is_empty());
    }

    #[test]
    fn wrong_schema_version_is_reset_silently() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("l4.json");
        // A valid-JSON file with a future schema version; load should
        // fall back to default rather than mis-parse.
        let bytes = serde_json::to_vec(&serde_json::json!({
            "version": 9999,
            "entries": {},
        }))
        .unwrap();
        fs::write(&path, bytes).unwrap();
        let loaded = load_or_default(&path);
        assert_eq!(loaded.version, CACHE_SCHEMA_VERSION);
        assert!(loaded.entries.is_empty());
    }
}
