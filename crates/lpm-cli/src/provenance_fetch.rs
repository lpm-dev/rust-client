//! Sigstore attestation fetch policy and orchestration for the CLI.
//!
//! Pipeline:
//!
//! 1. Caller resolves an `Option<AttestationRef>` from the registry
//!    metadata response. `None` (or `url = None`) means the registry
//!    explicitly did not ship a Sigstore attestation for this
//!    version — this is the axios-case signal when compared against
//!    an approved version that DID have one.
//! 2. [`fetch_provenance_snapshot`] checks the on-disk cache under
//!    `~/.lpm/cache/metadata/attestations/` (7-day TTL). Cache hits
//!    skip the network round-trip.
//! 3. On cache miss, we GET the attestation URL, verify the Sigstore
//!    bundle, extract the verified provenance snapshot, cache it, and
//!    return a populated [`ProvenanceSnapshot`].
//!
//! **Fetch-failure semantics**:
//! - `Ok(Some(snapshot))` — a definitive answer (either
//!   `present: true` with identity extracted, or `present: false`
//!   meaning the registry has no attestation for this version).
//! - `Ok(None)` — **degraded / unknown** (network error, oversized
//!   body, etc.). The drift rule interprets this as "pass, don't
//!   drift." Never cached, so the next install retries.
//! - `Err(LpmError::ProvenanceVerification(_))` — the registry served
//!   a structurally present bundle that failed cryptographic
//!   verification. The caller surfaces this as a hard security signal.
//! - `Err(_)` — genuinely fatal cache / I/O conditions the caller must
//!   surface.
//!
//! The install-time call site lives in
//! [`crate::commands::install::run_with_options`]'s drift gate,
//! which fires immediately after the cooldown gate on fresh
//! resolution paths.

use crate::provenance_bundle::{
    fetch_bundle_bytes, parse_sigstore_bundle, read_cache, verify_bundle_or_err, write_cache,
};
use lpm_common::LpmError;
use lpm_registry::AttestationRef;
use lpm_workspace::{ProvenanceSnapshot, ProvenanceStatus};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Canonicalized policy for the
/// `--ignore-provenance-drift[-all]` override flags on `lpm install`.
///
/// `--ignore-provenance-drift-all` deliberately supersedes the
/// per-package list, so passing `-all` alongside specific
/// `--ignore-provenance-drift X` is not an error - it just collapses
/// to `IgnoreAll`. This avoids a clap mutual-exclusion rule that
/// would otherwise trip CI scripts that forward both from an
/// orchestrator.
#[derive(Debug, Clone, Default)]
pub enum DriftIgnorePolicy {
    /// No override: enforce drift normally.
    #[default]
    EnforceAll,
    /// Opt out of drift enforcement for these specific package names.
    /// Empty set is not constructible — callers use [`Self::from_cli`]
    /// which rewrites an empty per-package list to `EnforceAll`.
    IgnoreNames(HashSet<String>),
    /// Opt out of drift enforcement for every resolved package.
    IgnoreAll,
}

impl DriftIgnorePolicy {
    /// Build the canonical policy from the two raw clap inputs.
    ///
    /// - `ignore_all = true` → `IgnoreAll` (per-package list ignored).
    /// - `ignore_all = false`, non-empty list → `IgnoreNames`.
    /// - Both empty / unset → `EnforceAll`.
    pub fn from_cli(ignore_names: Vec<String>, ignore_all: bool) -> Self {
        if ignore_all {
            return Self::IgnoreAll;
        }
        if ignore_names.is_empty() {
            return Self::EnforceAll;
        }
        Self::IgnoreNames(ignore_names.into_iter().collect())
    }

    /// Whether this policy suppresses drift enforcement universally.
    /// Used by the install gate to short-circuit the entire per-
    /// package loop without any network cost.
    pub fn ignores_all(&self) -> bool {
        matches!(self, Self::IgnoreAll)
    }

    /// Whether drift enforcement is suppressed for one specific name.
    /// `IgnoreAll` returns `true` for every name; `EnforceAll`
    /// returns `false` for every name; `IgnoreNames` consults the
    /// set.
    pub fn ignores_name(&self, name: &str) -> bool {
        match self {
            Self::EnforceAll => false,
            Self::IgnoreNames(set) => set.contains(name),
            Self::IgnoreAll => true,
        }
    }
}

/// Operator posture for the install-time and approve-time
/// Sigstore-provenance verifier.
///
/// Resolved via the env > config > default precedence chain in
/// [`Self::resolve_from_chain`] (the env var
/// `LPM_PROVENANCE_ENFORCE`, then `[sigstore] verify` in
/// `~/.lpm/config.toml`, then the fail-closed default).
///
/// Honored end-to-end at:
///
/// - **Approval-capture path** ([`crate::commands::approve_scripts::snapshot_for_binding_with_mode`]):
///   under `Warn`, a `VerificationRejected` records the binding
///   with `provenance_at_approval: None` instead of refusing the
///   approval; under `Deny`, the typed error refuses the binding so
///   the prior `provenance_at_approval` stays intact.
/// - **Install-time drift gate** (`commands/install.rs`): under
///   `Warn`, a verifier rejection logs an `output::warn` +
///   `tracing::warn` and degrades the per-package status to
///   `NoDrift` so the install proceeds; under `Deny`, the typed
///   error `?`-propagates and the install fails. The two-axis
///   split with [`SkipPolicy`] keeps the per-package opt-out
///   (`--unverified-provenance`) orthogonal to the global enforce
///   mode — the operator can carve out specific names without
///   flipping the fleet-wide posture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EnforceMode {
    /// Fail-closed: a verifier rejection refuses the approval.
    #[default]
    Deny,
    /// A verifier rejection logs loudly via `output::warn` +
    /// `tracing::warn` but does not block the approval. The trust
    /// binding's `provenance_at_approval` is recorded as `None` —
    /// same effect as a transport-degraded fetch during the
    /// approval window. Subsequent installs treat the package as
    /// "no provenance reference" until re-approved under `Deny`.
    /// Operators who set this MUST monitor the warn log line and
    /// either remediate the registry compromise or re-approve once
    /// the verifier accepts the bundle.
    Warn,
    /// **Operator opt-out, fleet-wide.** Skip the verification path
    /// entirely: don't fetch the bundle, don't parse, don't verify.
    /// The drift gate falls back to whatever identity data the
    /// registry metadata already carries — preserved as an explicit
    /// operator decision, not a default. Equivalent to passing
    /// `--unverified-provenance-all` on every install; persists via
    /// `[sigstore] verify = "off"` in `~/.lpm/config.toml` or via
    /// `LPM_PROVENANCE_ENFORCE=off`.
    ///
    /// **Loud when degraded.** Every install run that resolves to
    /// `Off` emits exactly one `tracing::warn` naming the source
    /// (env / config / default) and the re-enable command; `lpm
    /// doctor` flags the degraded posture so it stays visible
    /// outside install runs; the JSON envelope reports
    /// `verified: "disabled"` per package so machine-readable
    /// consumers can detect the posture-degrade without parsing
    /// log lines.
    Off,
}

impl EnforceMode {
    /// Env-only resolver for callers that don't load `GlobalConfig`.
    /// See [`Self::resolve_from_chain`] for the full env > config
    /// > default precedence (the production entry point).
    ///
    /// Unknown values fall back to `Deny` with a `tracing::warn`
    /// so a typo in the env var doesn't silently weaken the
    /// posture.
    pub fn from_env() -> Self {
        Self::from_env_value(std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref())
    }

    /// Pure parser exposed for unit tests so they don't have to
    /// mutate process-global env state. Production callers should
    /// use [`Self::from_env`].
    pub(crate) fn from_env_value(value: Option<&str>) -> Self {
        Self::parse_str_with_source(value, "LPM_PROVENANCE_ENFORCE env var").unwrap_or(Self::Deny)
    }

    /// Parse the wire-form string against the canonical three-value
    /// set. Returns `None` for unknown values (typo); caller decides
    /// whether to log and fall back (env / config readers) or hard-
    /// error (CLI-flag-style validators).
    ///
    /// `source` is the log context that fires when an unknown value
    /// is rejected — e.g. "LPM_PROVENANCE_ENFORCE env var" or
    /// "[sigstore] verify in ~/.lpm/config.toml" — so the operator
    /// can find where the typo lives.
    fn parse_str_with_source(value: Option<&str>, source: &'static str) -> Option<Self> {
        match value {
            None => None,
            Some("deny") => Some(Self::Deny),
            Some("warn") => Some(Self::Warn),
            Some("off") => Some(Self::Off),
            Some(other) => {
                tracing::warn!(
                    target = "lpm::provenance",
                    value = %other,
                    source = source,
                    "ignoring unknown sigstore verify mode (expected 'deny', 'warn', or 'off'); falling back to default"
                );
                None
            }
        }
    }

    /// Startup gate for the `LPM_PROVENANCE_ENFORCE` env var:
    /// unknown values hard-fail with an explicit `LpmError::Config`
    /// listing the three valid options.
    ///
    /// The internal [`Self::from_env_value`] / [`Self::resolve_from_chain`]
    /// path falls back to `Deny` on unknown values (defense-in-depth
    /// so a code path that bypasses validation cannot weaken posture).
    /// This gate is the operator-visible enforcement: a typo'd env
    /// var produces a clear error at process start naming the bad
    /// value and the valid set, rather than silently downgrading the
    /// security posture the operator intended.
    pub fn validate_env_value(value: Option<&str>) -> Result<(), LpmError> {
        match value {
            None | Some("deny") | Some("warn") | Some("off") => Ok(()),
            // The sigstore wizard at commands/config.rs uses
            // `LpmError::Registry` for the same shape of invalid-value
            // rejection (`lpm config sigstore --set <bad>`); mirror that
            // so operators get a uniform diagnostic surface.
            Some(other) => Err(LpmError::Registry(format!(
                "LPM_PROVENANCE_ENFORCE has unknown value `{other}`; \
                 must be one of: deny | warn | off"
            ))),
        }
    }

    /// Read `LPM_PROVENANCE_ENFORCE` from the process environment and
    /// validate it. Returns `Err(LpmError::Config)` for unknown
    /// values so the caller can short-circuit with a clear message.
    pub fn validate_from_env() -> Result<(), LpmError> {
        Self::validate_env_value(std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref())
    }

    /// Walk the precedence chain: env > config > default. The CLI
    /// flag tier is not threaded here because the flag axis is
    /// `SkipPolicy` (per-package), not enforce-mode — those two
    /// axes are orthogonal by design.
    ///
    /// `config_reader` is a closure that pulls the
    /// `[sigstore].verify` value from `~/.lpm/config.toml`. Passed
    /// in (rather than imported) so this fn stays decoupled from
    /// the `lpm-cli::commands::config` module — the binary-only
    /// tests in this file don't have to pull the entire config
    /// plumbing in.
    ///
    /// Returns the resolved [`EnforceModeSource`] so the caller can
    /// emit a loud-when-degraded log line naming the source.
    pub fn resolve_from_chain(
        env_value: Option<&str>,
        config_reader: impl FnOnce() -> Option<String>,
    ) -> (Self, EnforceModeSource) {
        if let Some(mode) = Self::parse_str_with_source(env_value, "LPM_PROVENANCE_ENFORCE env var")
        {
            return (mode, EnforceModeSource::Env);
        }
        let config_value = config_reader();
        if let Some(mode) = Self::parse_str_with_source(
            config_value.as_deref(),
            "[sigstore] verify in ~/.lpm/config.toml",
        ) {
            return (mode, EnforceModeSource::Config);
        }
        (Self::default(), EnforceModeSource::Default)
    }
}

/// Where the resolved [`EnforceMode`] came from. Used by the loud-
/// when-degraded warn-line emitter to tell operators which knob to
/// flip when they want to re-enable verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforceModeSource {
    Env,
    Config,
    Default,
}

impl EnforceModeSource {
    /// Human-readable suffix for the loud-when-degraded warn line.
    /// Used in the install-run heads-up so operators know where to
    /// flip the knob back without consulting the source code.
    pub fn re_enable_hint(&self) -> &'static str {
        match self {
            Self::Env => "unset LPM_PROVENANCE_ENFORCE or set it to 'deny'",
            Self::Config => "run `lpm config sigstore --set deny`",
            // Defensive: never fires today because the default IS
            // Deny and the loud-line predicate skips Deny. Kept so
            // any future default-flip in a rollout window still has
            // a sensible recovery hint instead of placeholder text.
            Self::Default => "set LPM_PROVENANCE_ENFORCE=deny",
        }
    }
}

/// Per-package opt-out for Sigstore cryptographic verification.
/// Orthogonal to [`EnforceMode`]: a package excluded here is
/// treated as if the verifier was never run, regardless of the
/// mode. The fetch still happens (we need the bytes to extract the
/// SAN identity) but the verifier is skipped and the resulting
/// snapshot lands on the binding as
/// [`lpm_common::ProvenanceStatus::Unverified`] — explicit
/// "operator accepted the identity without crypto" rather than
/// silently degraded.
///
/// The orthogonal split (rather than collapsing skip into a third
/// `EnforceMode::Off` value) is load-bearing for composition: an
/// operator can run `LPM_PROVENANCE_ENFORCE=warn` AND skip a
/// specific package — the env knob still drives the rest of the
/// install (verifier failures warn but don't block) while the
/// skip-listed package produces `Unverified` directly. The wiring
/// composes cleanly only if the two axes are independent.
#[derive(Debug, Clone, Default)]
pub enum SkipPolicy {
    /// Verify every package (default). The verifier runs and its
    /// outcome falls under whatever [`EnforceMode`] is active.
    #[default]
    None,
    /// Skip verification for these specific package names. Empty set
    /// is not constructible — callers use [`Self::from_cli`] which
    /// rewrites an empty per-package list to `None`.
    Names(HashSet<String>),
    /// Skip verification for every resolved package on this
    /// invocation.
    All,
}

impl SkipPolicy {
    /// Build the canonical policy from the two raw clap inputs.
    /// Mirrors [`DriftIgnorePolicy::from_cli`] so the two
    /// `--unverified-provenance{,-all}` and `--ignore-provenance-drift{,-all}`
    /// pairs canonicalize the same way: `-all` supersedes the
    /// per-package list (no clap mutex, just collapse).
    pub fn from_cli(unverified_names: Vec<String>, unverified_all: bool) -> Self {
        if unverified_all {
            return Self::All;
        }
        if unverified_names.is_empty() {
            return Self::None;
        }
        Self::Names(unverified_names.into_iter().collect())
    }

    /// `true` iff this specific package name is skip-listed.
    /// `All` returns `true` for every name; `None` returns `false`
    /// for every name; `Names` consults the set.
    pub fn skips_name(&self, name: &str) -> bool {
        match self {
            Self::None => false,
            Self::Names(set) => set.contains(name),
            Self::All => true,
        }
    }
}

/// Composed verification policy: the (`EnforceMode`, `SkipPolicy`)
/// pair that drives the install- and approve-time provenance gates.
///
/// Held together in one struct so `run_with_options` and the batch
/// caller take a single parameter instead of two. The fields are
/// independent — see [`SkipPolicy`] for why.
#[derive(Debug, Clone, Default)]
pub struct VerifyPolicy {
    pub enforce: EnforceMode,
    pub skip: SkipPolicy,
}

impl VerifyPolicy {
    /// Construct from the install-time CLI inputs + env-resolved
    /// enforce mode. Defers to [`EnforceMode::from_env`] (env-only)
    /// — used by internal callers (`upgrade`, `add`, `dev`, `dlx`,
    /// etc.) that don't surface their own `--unverified-provenance`
    /// flags and have no config-tier override resolution in scope.
    ///
    /// The `lpm install` dispatcher in `main.rs` uses
    /// [`Self::resolve_from_chain`] instead so the
    /// `[sigstore] verify` config tier is honored.
    pub fn from_cli(unverified_names: Vec<String>, unverified_all: bool) -> Self {
        Self {
            enforce: EnforceMode::from_env(),
            skip: SkipPolicy::from_cli(unverified_names, unverified_all),
        }
    }

    /// Construct via the full precedence chain.
    ///
    /// - **CLI** flags drive `SkipPolicy` (per-package). They don't
    ///   touch `EnforceMode` — the two axes are orthogonal so an
    ///   operator can set `LPM_PROVENANCE_ENFORCE=warn` AND skip a
    ///   specific package; the env knob still drives the rest of the
    ///   install while the skip-listed package produces `Unverified`
    ///   directly.
    /// - **Env** `LPM_PROVENANCE_ENFORCE` is the first tier for
    ///   `EnforceMode` resolution.
    /// - **Config** `[sigstore] verify` in `~/.lpm/config.toml`
    ///   (read via `config_reader`) is the second tier.
    /// - **Default** is `Deny` (fail-closed).
    ///
    /// Also returns the [`EnforceModeSource`] so the caller can
    /// emit one loud-when-degraded log line per install run (the
    /// `OnceCell`-gated hint that names the re-enable command).
    pub fn resolve_from_chain(
        unverified_names: Vec<String>,
        unverified_all: bool,
        env_value: Option<&str>,
        config_reader: impl FnOnce() -> Option<String>,
    ) -> (Self, EnforceModeSource) {
        let (enforce, source) = EnforceMode::resolve_from_chain(env_value, config_reader);
        let skip = SkipPolicy::from_cli(unverified_names, unverified_all);
        (Self { enforce, skip }, source)
    }

    /// Resolve the operator-persistent posture for commands that do
    /// NOT surface their own `--unverified-provenance{,-all}` flags
    /// (`upgrade`, `add`, `dev`, `dlx`/`run`, `doctor`, `migrate`,
    /// `update_global`, `deploy`, and `approve-scripts`'s batch
    /// fetcher).
    ///
    /// Threads the same env > config > default chain that `lpm
    /// install` uses so an operator who sets
    /// `LPM_PROVENANCE_ENFORCE=warn` (or persists
    /// `[sigstore] verify = "off"`) gets that posture honored
    /// uniformly across every install-shaped command — not just
    /// `lpm install`. Without this, `lpm upgrade` would block under
    /// the default `Deny` even when the operator's persisted
    /// posture said `Warn`, surprising operators with inconsistent
    /// behavior across the CLI surface.
    ///
    /// `SkipPolicy` is fixed at `None` because the per-package
    /// opt-out only makes sense at the `lpm install` invocation
    /// surface (where the operator explicitly names a package).
    /// Internal callers honor the global posture but cannot carve
    /// out individual packages.
    ///
    /// Reads `~/.lpm/config.toml` once per call. Bounded by config
    /// file size (~kilobytes); the perf cost is negligible relative
    /// to the install pipeline it gates.
    pub fn resolve_no_cli() -> Self {
        let cfg = crate::commands::config::GlobalConfig::load();
        let (enforce, _source) = EnforceMode::resolve_from_chain(
            std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref(),
            || cfg.get_sigstore_verify(),
        );
        Self {
            enforce,
            skip: SkipPolicy::None,
        }
    }

    /// `true` iff the cryptographic verifier should be bypassed for
    /// this specific package — either because the operator carved
    /// it out via `--unverified-provenance` OR because
    /// `EnforceMode::Off` is the fleet-wide posture.
    ///
    /// Single source of truth for the "should we run verification?"
    /// decision so the install drift gate and the batch caller
    /// stay in lockstep. Without this, the two axes could conflate
    /// independently at each call site and the orthogonality
    /// contract would break.
    pub fn should_skip_verification_for(&self, name: &str) -> bool {
        matches!(self.enforce, EnforceMode::Off) || self.skip.skips_name(name)
    }
}

/// perf decomposition of [`fetch_provenance_snapshot`].
///
/// Each atomic accumulates time spent in one stage across many
/// concurrent calls. Caller (e.g. `build_blocked_set_metadata`) creates
/// one of these, threads it as `Some(&timings)` into every
/// [`fetch_provenance_snapshot`] call, and emits the breakdown after
/// the surrounding `join_all` settles.
///
/// Stages:
/// - `cache_hit_ns` — time inside [`read_cache`] when it returns
///   `Some`. Cache misses do not contribute here; their downstream
///   fetch is timed under `http_ns`.
/// - `http_ns` — time inside the HTTP fetch from `send` through the
///   final body chunk being buffered. Includes status-check, content-
///   length-cap, and stream-cap rejections.
/// - `parse_ns` — time inside JSON parse + cert lookup + base64
///   decode + SAN extraction. Pure CPU.
///
/// These three cover the dominant cost shapes (warm-cache /
/// cold-fetch / cold-parse). Other paths (no-URL early return, the
/// cache-miss `read_cache` call itself, cache-write) are deliberately
/// not split — they are bounded small and would add report noise
/// without changing what design decision the breakdown informs.
#[derive(Default, Debug)]
pub struct ProvenanceTimings {
    pub cache_hit_ns: AtomicU64,
    pub http_ns: AtomicU64,
    pub parse_ns: AtomicU64,
    pub cache_hit_count: AtomicU64,
    pub http_count: AtomicU64,
    pub verify_count: AtomicU64,
    verify_max_ns: AtomicU64,
    slow_verify: Mutex<Vec<ProvenancePackageTiming>>,
}

impl ProvenanceTimings {
    fn record_verify(&self, name: &str, version: &str, elapsed: std::time::Duration) {
        let ns = elapsed.as_nanos() as u64;
        self.parse_ns.fetch_add(ns, Ordering::Relaxed);
        self.verify_count.fetch_add(1, Ordering::Relaxed);
        let mut current = self.verify_max_ns.load(Ordering::Relaxed);
        while ns > current {
            match self.verify_max_ns.compare_exchange_weak(
                current,
                ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
        if let Ok(mut slow) = self.slow_verify.lock() {
            slow.push(ProvenancePackageTiming {
                package: format!("{name}@{version}"),
                ms: ns / 1_000_000,
            });
            slow.sort_unstable_by(|a, b| b.ms.cmp(&a.ms).then_with(|| a.package.cmp(&b.package)));
            slow.truncate(10);
        }
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "cache_hit": {
                "sum_ms": self.cache_hit_ns.load(Ordering::Relaxed) / 1_000_000,
                "count": self.cache_hit_count.load(Ordering::Relaxed),
            },
            "http": {
                "sum_ms": self.http_ns.load(Ordering::Relaxed) / 1_000_000,
                "count": self.http_count.load(Ordering::Relaxed),
            },
            "verify": {
                "sum_ms": self.parse_ns.load(Ordering::Relaxed) / 1_000_000,
                "max_ms": self.verify_max_ns.load(Ordering::Relaxed) / 1_000_000,
                "count": self.verify_count.load(Ordering::Relaxed),
            },
        })
    }

    pub(crate) fn slow_verify_json(&self) -> serde_json::Value {
        self.slow_verify.lock().map_or_else(
            |_| serde_json::Value::Array(Vec::new()),
            |slow| {
                serde_json::Value::Array(
                    slow.iter()
                        .map(|entry| {
                            serde_json::json!({
                                "package": entry.package,
                                "ms": entry.ms,
                            })
                        })
                        .collect(),
                )
            },
        )
    }
}

#[derive(Debug, Clone)]
struct ProvenancePackageTiming {
    package: String,
    ms: u64,
}

// ── Public API ──────────────────────────────────────────────────

/// Fetch (or read from cache) the `ProvenanceSnapshot` for one
/// package version.
///
/// See module docs for the return-value semantics. Never writes a
/// `None` result to cache — those are always transient and the next
/// install should retry.
pub async fn fetch_provenance_snapshot(
    http: &reqwest::Client,
    cache_root: &Path,
    name: &str,
    version: &str,
    attestation_ref: Option<&AttestationRef>,
    timings: Option<&ProvenanceTimings>,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    // Registry said "no attestation for this version" — that is the
    // axios signal. Return a definitive `present: false` snapshot.
    //
    // Do not cache absent snapshots. Always-absent packages never read
    // this cache path because registry metadata keeps returning no URL;
    // if a later release adds a URL, a stale cached absence would mask
    // the new attestation.
    let url = match attestation_ref.and_then(|a| a.url.as_deref()) {
        Some(u) => u,
        None => {
            return Ok(Some(ProvenanceSnapshot {
                present: false,
                ..Default::default()
            }));
        }
    };

    // Cache hit + fresh → skip the network round-trip. Time only the
    // hit case: misses fall through and their downstream fetch is
    // covered by `http_ns`. The `read_cache` call itself on a miss
    // is bounded small and intentionally not split out (see
    // [`ProvenanceTimings`] doc).
    let cache_start = Instant::now();
    if let Some(cached) = read_cache(cache_root, name, version)? {
        if let Some(t) = timings {
            t.cache_hit_ns
                .fetch_add(cache_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
            t.cache_hit_count.fetch_add(1, Ordering::Relaxed);
        }
        return Ok(Some(cached));
    }

    // Cache miss → fetch (network) + parse (CPU), timed separately so
    // the perf decomposition can attribute cold-install cost. Any
    // error from either stage degrades to `Ok(None)` and is NOT
    // cached — the next install retries.
    let http_start = Instant::now();
    let buf = match fetch_bundle_bytes(http, url).await {
        Ok(b) => b,
        Err(()) => return Ok(None),
    };
    if let Some(t) = timings {
        t.http_ns
            .fetch_add(http_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        t.http_count.fetch_add(1, Ordering::Relaxed);
    }

    // Verification: bytes are in hand, run the full
    // verifier. Failure here is NOT degraded to `Ok(None)` because
    // it represents an attack signal (registry served a bundle that
    // claimed signed provenance but failed crypto). Transport-class
    // failures are already absorbed above at `fetch_bundle_bytes`.
    let parse_start = Instant::now();
    let snapshot = verify_bundle_or_err(&buf, url)?;
    if let Some(t) = timings {
        t.record_verify(name, version, parse_start.elapsed());
    }

    // Successful parse — cache it and return. Cache-write failures
    // are logged but not propagated: the snapshot is already
    // computed and usable; future invalidation is at worst one
    // extra fetch.
    if let Err(e) = write_cache(cache_root, name, version, &snapshot) {
        tracing::warn!(
            "provenance cache write failed for {name}@{version}: {e}; \
             continuing with fresh snapshot"
        );
    }
    Ok(Some(snapshot))
}

pub(crate) fn read_cached_provenance_snapshot(
    cache_root: &Path,
    name: &str,
    version: &str,
) -> Result<Option<ProvenanceSnapshot>, LpmError> {
    read_cache(cache_root, name, version)
}

/// Map one [`fetch_provenance_snapshot`] outcome to a
/// [`ProvenanceStatus`] for the batch caller.
///
/// Pure mapping (no I/O) so verifier rejection handling is directly
/// testable without mocking the registry-client cascade. A prior
/// `.ok.flatten` collapse made
/// `Err(LpmError::ProvenanceVerification)` into the same `None` as a
/// transport failure, blanking the approval binding and disarming
/// drift on subsequent installs. This helper preserves the four
/// states distinct:
///
/// - `Ok(Some(snap))` with `snap.present == true` → `Verified`
/// - `Ok(Some(snap))` with `snap.present == false` → `Absent`
///   (registry confirmed no attestation — the axios drop signal)
/// - `Ok(None)` → `TransportDegraded`
/// - `Err(LpmError::ProvenanceVerification(reason))` →
///   `VerificationRejected { reason }`
/// - `Err(other)` → `TransportDegraded` (fatal I/O degrades rather
///   than failing the whole batch; the per-package path retains
///   the typed-error contract for install-time `?`-propagation)
pub(crate) fn map_fetch_result_to_status(
    name: &str,
    version: &str,
    result: Result<Option<ProvenanceSnapshot>, LpmError>,
) -> ProvenanceStatus {
    match result {
        Ok(Some(snap)) => {
            if snap.present {
                ProvenanceStatus::Verified(snap)
            } else {
                ProvenanceStatus::Absent
            }
        }
        Ok(None) => ProvenanceStatus::TransportDegraded,
        Err(LpmError::ProvenanceVerification(reason)) => {
            tracing::warn!(
                target = "lpm::provenance",
                pkg = %name,
                version = %version,
                reason = %reason,
                "provenance bundle rejected by verifier; approval will be refused"
            );
            ProvenanceStatus::VerificationRejected { reason }
        }
        Err(other) => {
            tracing::debug!(
                target = "lpm::provenance",
                pkg = %name,
                version = %version,
                err = %other,
                "provenance fetch failed (non-verification error); degrading to transport"
            );
            ProvenanceStatus::TransportDegraded
        }
    }
}

/// Batch-fetch attestation snapshots for many `(name, version)` pairs
/// in parallel. Single source of truth for both the project-level
/// `lpm approve-scripts` write path and the global-scope
/// `lpm approve-scripts --global` write path.
///
/// Returns one [`ProvenanceStatus`] per input pair (never collapses
/// distinct outcomes into a single `None`). A previous implementation
/// used `.ok().flatten()` here, which made
/// a verifier rejection (`Err(LpmError::ProvenanceVerification)`)
/// indistinguishable from a network failure. Recording the resulting
/// `provenance_at_approval = None` would silently disarm the drift
/// comparator's `(None, _) => NoDrift` arm on every future install,
/// permanently defeating publisher-swap detection after a single
/// attack-window install. The explicit match below preserves the four
/// states end-to-end so the approval-capture path can refuse to
/// record a binding on rejection while still degrading to `NoDrift`
/// on genuine transport failures.
///
/// `verify_policy.skip` carves a per-package opt-out: for every
/// name listed (or every name when `SkipPolicy::All`), the verifier
/// is bypassed and the bundle is parsed through the legacy
/// identity-only extractor; the result lands as
/// [`ProvenanceStatus::Unverified`] (snapshot present, audit trail
/// records the operator's downgrade). `verify_policy.enforce` only
/// affects the verifier path — when the package is skip-listed
/// there is nothing to enforce against. The two axes are
/// independent on purpose (see [`SkipPolicy`] doc).
///
/// The lpm-vs-npm metadata-fetch dispatch by `@lpm.dev/` name prefix
/// mirrors `install.rs::build_blocked_set_metadata`. The 5-min metadata
/// cache absorbs the typical "install then immediately approve-scripts"
/// case (no network call); the on-disk attestation cache under
/// `~/.lpm/cache/metadata/attestations/` (7-day TTL) covers repeated
/// approvals across runs.
pub async fn fetch_provenance_for_pkgs(
    pkgs: &[(String, String)],
    verify_policy: &VerifyPolicy,
) -> HashMap<(String, String), ProvenanceStatus> {
    let cache_root = match lpm_common::paths::LpmRoot::from_env() {
        Ok(root) => root.cache_metadata_attestations(),
        Err(_) => {
            // Degraded — no cache root. Match the pre-existing install
            // behavior: every package degrades.
            return pkgs
                .iter()
                .map(|p| (p.clone(), ProvenanceStatus::TransportDegraded))
                .collect();
        }
    };
    let http = reqwest::Client::new();
    let registry = lpm_registry::RegistryClient::new();

    let cache_root_ref = &cache_root;
    let http_ref = &http;
    let registry_ref = &registry;
    let verify_policy_ref = verify_policy;

    let futures = pkgs.iter().map(move |(name, version)| async move {
        // lpm vs npm dispatch by name prefix mirrors
        // `install.rs::build_blocked_set_metadata`.
        let meta = if name.starts_with("@lpm.dev/") {
            match lpm_common::PackageName::parse(name) {
                Ok(pkg_name) => registry_ref.get_package_metadata(&pkg_name).await.ok(),
                Err(_) => None,
            }
        } else {
            registry_ref.get_npm_package_metadata(name).await.ok()
        };
        let attestation_ref = meta
            .as_ref()
            .and_then(|m| m.versions.get(version))
            .and_then(|v| v.dist.as_ref())
            .and_then(|d| d.attestations.clone());

        // Skip path: operator opted out of cryptographic
        // verification for this name (CLI flag) OR fleet-wide
        // (`EnforceMode::Off`). Pull the bytes through the legacy
        // identity-only parser and land the snapshot as
        // `Unverified` so the binding records the operator's
        // downgrade explicitly instead of falsely claiming
        // verification.
        if verify_policy_ref.should_skip_verification_for(name) {
            let raw =
                fetch_unverified_snapshot(http_ref, name, version, attestation_ref.as_ref()).await;
            let status = relabel_skip_status_for_enforce_mode(raw, verify_policy_ref.enforce);
            return ((name.clone(), version.clone()), status);
        }

        let raw = fetch_provenance_snapshot(
            http_ref,
            cache_root_ref,
            name,
            version,
            attestation_ref.as_ref(),
            None,
        )
        .await;
        let status = map_fetch_result_to_status(name, version, raw);
        ((name.clone(), version.clone()), status)
    });
    futures::future::join_all(futures)
        .await
        .into_iter()
        .collect()
}

/// Re-label a [`ProvenanceStatus`] produced by the skip path so the
/// JSON envelope distinguishes per-package opt-out from fleet-wide
/// opt-out. Single source of truth for the "what does the trust
/// binding's audit trail say happened?" decision; the install drift
/// gate and the batch caller both go through this so they cannot
/// drift on the labeling rule.
///
/// Re-label rules:
///
/// - `EnforceMode::Off` + `Unverified(snap)` → `Disabled(snap)`. The
///   operator declared "we don't verify anything fleet-wide"; the
///   bundle exists but the verifier was bypassed by global posture,
///   so the audit trail says `verified: "disabled"` (not
///   `"skipped"`, which is reserved for the per-package CLI carve-
///   out).
///
/// - Every other `(mode, status)` pair → identity. Specifically
///   under `Off`:
///   - `Absent` stays `Absent` (`verified: false`): the registry
///     served no attestation. That observation is independent of
///     the operator's verification posture. An audit pipeline
///     reading `verified: "disabled"` learns "operator skipped
///     verification but the bundle was real"; reading
///     `verified: false` learns "there was nothing to verify
///     regardless of posture." Conflating them loses the
///     registry-absence signal.
///   - `TransportDegraded` stays `TransportDegraded`
///     (`verified: null`): transient network failure is also
///     independent of the posture choice, and `null` is the right
///     "unknown" signal.
///   - `Verified` and `VerificationRejected` are unreachable on the
///     skip path (the verifier didn't run), so they pass through
///     unchanged as a defensive identity.
///
/// Under `Warn` and `Deny` the skip path still runs only when
/// `SkipPolicy` matched, so `Unverified` is the operator's surgical
/// per-package decision and must remain `"skipped"` (not
/// `"disabled"`). Identity again.
pub(crate) fn relabel_skip_status_for_enforce_mode(
    status: ProvenanceStatus,
    mode: EnforceMode,
) -> ProvenanceStatus {
    match (mode, status) {
        (EnforceMode::Off, ProvenanceStatus::Unverified(snap)) => ProvenanceStatus::Disabled(snap),
        (_, status) => status,
    }
}

/// Skip-list fetch: pull the bundle bytes, run the legacy
/// identity-only parser, and emit [`ProvenanceStatus::Unverified`]
/// without engaging the cryptographic verifier. Errors degrade to
/// `TransportDegraded` — even on the skip path, a missing URL or a
/// malformed bundle means we observed nothing; the drift comparator's
/// `(_, None) => NoDrift` arm then absorbs it.
///
/// Cache-bypass on purpose: cached entries are
/// `CACHE_SCHEMA_VERSION = 2` and were written by the verifier path
/// (`Verified` semantics). Reading them on the skip path would
/// silently upgrade an Unverified observation to "the operator opted
/// out, but the cache says it was verified yesterday" — confusing
/// the audit trail. The skip path is rare; the extra fetch is fine.
/// We also do NOT write a cache entry: a future verifier-mode install
/// must not be allowed to short-circuit through an entry that bypassed
/// crypto.
pub async fn fetch_unverified_snapshot(
    http: &reqwest::Client,
    name: &str,
    version: &str,
    attestation_ref: Option<&AttestationRef>,
) -> ProvenanceStatus {
    let url = match attestation_ref.and_then(|a| a.url.as_deref()) {
        Some(u) => u,
        None => {
            tracing::debug!(
                target: "lpm_cli::provenance_fetch",
                pkg = %name,
                version = %version,
                "skip-list package has no attestation URL — recording Absent"
            );
            return ProvenanceStatus::Absent;
        }
    };
    let buf = match fetch_bundle_bytes(http, url).await {
        Ok(b) => b,
        Err(()) => return ProvenanceStatus::TransportDegraded,
    };
    match parse_sigstore_bundle(&buf) {
        Ok(snap) => {
            tracing::warn!(
                target = "lpm::provenance",
                pkg = %name,
                version = %version,
                "operator opted out of cryptographic verification for this package; \
                 recording identity-only snapshot (--unverified-provenance)"
            );
            ProvenanceStatus::Unverified(snap)
        }
        Err(()) => {
            tracing::debug!(
                target: "lpm_cli::provenance_fetch",
                pkg = %name,
                version = %version,
                "skip-list package bundle failed identity-only parse — degrading to transport"
            );
            ProvenanceStatus::TransportDegraded
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, Ia5String, KeyPair, SanType};

    // ── DriftIgnorePolicy::from_cli ─────────────────────────────

    /// Default state (no flags passed) enforces drift normally. This
    /// is the baseline every non-Install caller relies on via
    /// [`DriftIgnorePolicy::default`].
    #[test]
    fn drift_ignore_policy_no_flags_enforces_all() {
        let policy = DriftIgnorePolicy::from_cli(vec![], false);
        assert!(!policy.ignores_all());
        assert!(!policy.ignores_name("axios"));
    }

    /// `--ignore-provenance-drift axios --ignore-provenance-drift lodash`
    /// produces `IgnoreNames`. Other names are still enforced.
    #[test]
    fn drift_ignore_policy_per_package_collapses_into_set() {
        let policy = DriftIgnorePolicy::from_cli(vec!["axios".into(), "lodash".into()], false);
        assert!(!policy.ignores_all());
        assert!(policy.ignores_name("axios"));
        assert!(policy.ignores_name("lodash"));
        assert!(
            !policy.ignores_name("express"),
            "unnamed packages must still enforce drift",
        );
    }

    /// `--ignore-provenance-drift-all` alone → `IgnoreAll`. The
    /// short-circuit drops into the blanket-waive path in the
    /// install gate.
    #[test]
    fn drift_ignore_policy_all_flag_alone_ignores_all() {
        let policy = DriftIgnorePolicy::from_cli(vec![], true);
        assert!(policy.ignores_all());
        assert!(policy.ignores_name("any"));
        assert!(policy.ignores_name("package"));
    }

    /// Passing both flags is NOT an error: `-all` supersedes the
    /// per-package list. No clap mutex needed; the combination is
    /// unambiguous and the broader flag wins.
    #[test]
    fn drift_ignore_policy_all_flag_supersedes_per_package_list() {
        let policy = DriftIgnorePolicy::from_cli(vec!["axios".into(), "lodash".into()], true);
        // When -all wins, every name is ignored — including names
        // NOT in the per-package list, which is the whole point.
        assert!(policy.ignores_all());
        assert!(policy.ignores_name("axios"));
        assert!(policy.ignores_name("express"));
    }

    /// Empty per-package list + false flag → `EnforceAll`, NOT
    /// `IgnoreNames(empty set)`. The latter would behave identically
    /// but would obscure the "we're enforcing" signal in debug output.
    #[test]
    fn drift_ignore_policy_empty_inputs_canonicalize_to_enforce_all() {
        let policy = DriftIgnorePolicy::from_cli(vec![], false);
        assert!(matches!(policy, DriftIgnorePolicy::EnforceAll));
    }

    // ── SkipPolicy::from_cli ────────────────────────────────────
    //
    // Mirrors the DriftIgnorePolicy canonicalization shape so an
    // operator can rely on `--unverified-provenance{,-all}` composing
    // the same way as `--ignore-provenance-drift{,-all}`. Each test
    // pins one specific behavior we expect to survive future refactors.

    #[test]
    fn skip_policy_no_flags_skips_nothing() {
        let policy = SkipPolicy::from_cli(vec![], false);
        assert!(matches!(policy, SkipPolicy::None));
        assert!(
            !policy.skips_name("axios"),
            "default policy must NOT skip verification for any name",
        );
    }

    #[test]
    fn skip_policy_per_package_collapses_into_set() {
        let policy = SkipPolicy::from_cli(vec!["axios".into(), "lodash".into()], false);
        assert!(matches!(policy, SkipPolicy::Names(_)));
        assert!(policy.skips_name("axios"));
        assert!(policy.skips_name("lodash"));
        assert!(
            !policy.skips_name("express"),
            "unnamed packages must still verify",
        );
    }

    #[test]
    fn skip_policy_all_flag_alone_skips_every_name() {
        let policy = SkipPolicy::from_cli(vec![], true);
        assert!(matches!(policy, SkipPolicy::All));
        assert!(policy.skips_name("any"));
        assert!(policy.skips_name("package"));
    }

    /// Same composition semantics as DriftIgnorePolicy: `-all`
    /// supersedes the per-package list, no clap mutex needed. Test
    /// pins the contract - collapsing to `SkipPolicy::All` even when
    /// per-package names are listed.
    #[test]
    fn skip_policy_all_flag_supersedes_per_package_list() {
        let policy = SkipPolicy::from_cli(vec!["axios".into(), "lodash".into()], true);
        assert!(matches!(policy, SkipPolicy::All));
        assert!(policy.skips_name("axios"));
        assert!(
            policy.skips_name("express"),
            "All variant must skip every name, including names NOT in the per-package list",
        );
    }

    // ── VerifyPolicy composed shape ────────────────────────────

    /// The composed default `VerifyPolicy` walks the env chain for
    /// `EnforceMode` and lands on `SkipPolicy::None`. With no env var
    /// set the resolved enforce mode is `Deny` (fail-closed) — pin
    /// both axes so a future change to either default surfaces in
    /// review rather than silently weakening the posture.
    #[test]
    fn verify_policy_default_is_deny_and_skip_none() {
        let policy = VerifyPolicy::default();
        // EnforceMode::Deny is the default per `Default` derive.
        assert_eq!(policy.enforce, EnforceMode::Deny);
        assert!(matches!(policy.skip, SkipPolicy::None));
    }

    /// `VerifyPolicy::from_cli` composes the two axes independently:
    /// the env-derived `EnforceMode` is untouched by the per-package
    /// CLI flags, and vice versa. A future refactor that conflates
    /// the two axes would defeat "LPM_PROVENANCE_ENFORCE=warn +
    /// --unverified-provenance foo composes cleanly" — the
    /// workflow test
    /// `install_skip_flag_short_circuits_verifier_under_enforce_warn`
    /// pins that contract end-to-end.
    #[test]
    fn verify_policy_from_cli_composes_skip_independently_of_enforce() {
        let policy = VerifyPolicy::from_cli(vec!["foo".into()], false);
        // The env is unset in this test, so EnforceMode is the default
        // (Deny). The skip-list still carves foo out — both axes are
        // independently resolved.
        assert_eq!(policy.enforce, EnforceMode::Deny);
        assert!(policy.skip.skips_name("foo"));
        assert!(
            !policy.skip.skips_name("bar"),
            "skip-list must NOT spill across to unrelated names",
        );
    }

    // ── EnforceMode parse + precedence resolver ────────────────

    #[test]
    fn enforce_mode_parses_three_canonical_values() {
        assert_eq!(EnforceMode::from_env_value(Some("deny")), EnforceMode::Deny);
        assert_eq!(EnforceMode::from_env_value(Some("warn")), EnforceMode::Warn);
        assert_eq!(EnforceMode::from_env_value(Some("off")), EnforceMode::Off);
    }

    /// Unknown values still fall back to fail-closed `Deny` at the
    /// internal parser layer (defense-in-depth) — but the
    /// operator-visible enforcement is the
    /// [`EnforceMode::validate_env_value`] startup gate, which
    /// hard-fails with [`LpmError::Registry`] so a typo never
    /// silently downgrades the posture.
    #[test]
    fn enforce_mode_unknown_value_falls_back_to_deny_internally() {
        assert_eq!(
            EnforceMode::from_env_value(Some("yolo")),
            EnforceMode::Deny,
            "internal parser must fall back to fail-closed default; \
             the startup validator catches the typo separately",
        );
    }

    #[test]
    fn validate_env_value_accepts_the_three_canonical_values() {
        EnforceMode::validate_env_value(Some("deny")).expect("`deny` must validate");
        EnforceMode::validate_env_value(Some("warn")).expect("`warn` must validate");
        EnforceMode::validate_env_value(Some("off")).expect("`off` must validate");
        EnforceMode::validate_env_value(None).expect("absent env var must validate (unset)");
    }

    #[test]
    fn validate_env_value_hard_fails_on_typo_and_names_the_valid_set() {
        let err = EnforceMode::validate_env_value(Some("warm"))
            .expect_err("typo'd value MUST hard-fail; silent default-fallback was the bug");
        let msg = format!("{err}");
        assert!(
            msg.contains("warm"),
            "error must quote the offending value; got: {msg}",
        );
        assert!(
            msg.contains("deny") && msg.contains("warn") && msg.contains("off"),
            "error must name all three valid values so the operator can fix the typo; got: {msg}",
        );
    }

    #[test]
    fn validate_env_value_rejects_empty_string() {
        EnforceMode::validate_env_value(Some(""))
            .expect_err("empty string is not the same as absent — must hard-fail");
    }

    /// Precedence chain: env wins over config wins over default.
    /// Three positive cases pin each tier.
    #[test]
    fn enforce_mode_resolve_env_wins_over_config_and_default() {
        let (mode, source) =
            EnforceMode::resolve_from_chain(Some("warn"), || Some("off".to_string()));
        assert_eq!(mode, EnforceMode::Warn);
        assert_eq!(source, EnforceModeSource::Env);
    }

    #[test]
    fn enforce_mode_resolve_config_used_when_env_absent() {
        let (mode, source) = EnforceMode::resolve_from_chain(None, || Some("off".to_string()));
        assert_eq!(mode, EnforceMode::Off);
        assert_eq!(source, EnforceModeSource::Config);
    }

    #[test]
    fn enforce_mode_resolve_default_when_both_absent() {
        let (mode, source) = EnforceMode::resolve_from_chain(None, || None);
        assert_eq!(mode, EnforceMode::Deny);
        assert_eq!(source, EnforceModeSource::Default);
    }

    /// Edge case: env has a typo, config is valid — config wins, env
    /// is silently ignored with a tracing::warn. This is the
    /// "operator typo'd LPM_PROVENANCE_ENFORCE=warn1 but their
    /// config persists the right value" path — must not crash or
    /// hard-fall to default.
    #[test]
    fn enforce_mode_resolve_env_typo_falls_through_to_config() {
        let (mode, source) =
            EnforceMode::resolve_from_chain(Some("yolo"), || Some("warn".to_string()));
        assert_eq!(mode, EnforceMode::Warn);
        assert_eq!(source, EnforceModeSource::Config);
    }

    /// `should_skip_verification_for` is the single source of truth
    /// the install drift gate and the batch caller both consult.
    /// Both axes drive it: per-package skip-list OR fleet-wide
    /// `EnforceMode::Off`.
    #[test]
    fn verify_policy_should_skip_verification_unifies_skip_and_off() {
        // Per-package skip alone — only the named package skips.
        let p = VerifyPolicy {
            enforce: EnforceMode::Deny,
            skip: SkipPolicy::Names({
                let mut s = HashSet::new();
                s.insert("axios".into());
                s
            }),
        };
        assert!(p.should_skip_verification_for("axios"));
        assert!(!p.should_skip_verification_for("lodash"));

        // EnforceMode::Off — every package skips, regardless of
        // SkipPolicy.
        let p = VerifyPolicy {
            enforce: EnforceMode::Off,
            skip: SkipPolicy::None,
        };
        assert!(p.should_skip_verification_for("axios"));
        assert!(p.should_skip_verification_for("anything"));

        // Both axes default — nothing skips.
        let p = VerifyPolicy::default();
        assert!(!p.should_skip_verification_for("axios"));
    }

    /// `EnforceModeSource::re_enable_hint` returns the canonical
    /// recovery command per source — pinned so the install heads-up
    /// line stays actionable. All three variants are covered
    /// including `Default`: the hint never fires today (default IS
    /// `Deny`, so the loud-line predicate skips it), but the arm is
    /// kept defensively in case the default ever flips during a
    /// rollout window. Testing the hint string ensures the
    /// defensive arm has a sensible fallback rather than panicking
    /// or returning placeholder text.
    #[test]
    fn enforce_mode_source_re_enable_hints_are_canonical() {
        assert!(
            EnforceModeSource::Env
                .re_enable_hint()
                .contains("LPM_PROVENANCE_ENFORCE"),
            "env hint must name the env var",
        );
        assert!(
            EnforceModeSource::Config
                .re_enable_hint()
                .contains("lpm config sigstore"),
            "config hint must name the wizard command",
        );
        // Defensive arm: never fires under current defaults but
        // must still produce a usable recovery instruction in case
        // the default ever flips during a rollout window.
        assert!(
            EnforceModeSource::Default
                .re_enable_hint()
                .contains("LPM_PROVENANCE_ENFORCE"),
            "default hint must name a concrete re-enable knob even though it's currently \
             unreachable; keeps the defensive arm meaningful for any future default flip",
        );
    }

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;

    fn cert_der_with_san_uri(uri: &str) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(uri).unwrap())];
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
    }

    fn sigstore_bundle_with_cert(der: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
            "verificationMaterial": {
                "x509CertificateChain": {
                    "certificates": [
                        { "rawBytes": BASE64.encode(der) }
                    ]
                }
            }
        })
    }

    fn fresh_snapshot() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-abc".into()),
        }
    }

    // ── fetch_provenance_snapshot (public API) — non-network paths ──

    /// `attestation_ref = None` is the "registry didn't ship an
    /// attestation" signal. Must return `Some(present: false)` without
    /// writing an absent marker to the attestation cache.
    #[tokio::test]
    async fn fetch_returns_absent_snapshot_when_ref_is_none() {
        let cache = tempfile::tempdir().unwrap();
        let http = reqwest::Client::new();
        let snap = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", None, None)
            .await
            .unwrap()
            .unwrap();
        assert!(!snap.present);
        assert!(snap.publisher.is_none());
        assert!(snap.workflow_path.is_none());
        assert!(snap.workflow_ref.is_none());

        // Absent snapshots are returned in-memory only. A cached
        // "absent" marker would be unused while metadata still has no
        // URL, and stale if a later release adds an attestation URL.
        let cached = read_cache(cache.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(cached, None, "absent snapshot must not be cached");
    }

    /// `attestation_ref.url = None` is semantically the same as
    /// `ref = None` — the registry said "no attestation here."
    #[tokio::test]
    async fn fetch_returns_absent_snapshot_when_url_is_none() {
        let cache = tempfile::tempdir().unwrap();
        let http = reqwest::Client::new();
        let att = AttestationRef {
            url: None,
            provenance: None,
        };
        let snap = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att), None)
            .await
            .unwrap()
            .unwrap();
        assert!(!snap.present);
    }

    /// A fresh cache entry short-circuits the network entirely.
    /// Driving the test through the public API proves the cache-hit
    /// branch is wired correctly even though the http client in the
    /// test isn't pointed at any real server.
    #[tokio::test]
    async fn fetch_uses_cache_hit_without_network_roundtrip() {
        let cache = tempfile::tempdir().unwrap();
        let pre = fresh_snapshot();
        write_cache(cache.path(), "pkg", "1.0.0", &pre).unwrap();

        let att = AttestationRef {
            url: Some("http://localhost:1/definitely-unreachable".into()),
            provenance: None,
        };
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let snap = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att), None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snap, pre, "cache hit must not perform an HTTP request");
    }

    /// A structurally present but unverifiable bundle surfaces as a
    /// hard `ProvenanceVerification` error rather than degrading to
    /// unknown.
    #[tokio::test]
    async fn fetch_returns_provenance_verification_err_on_unverifiable_bundle() {
        // behavioral pin: a registry that serves a 200
        // response whose body is structurally a Sigstore bundle but
        // cannot pass cryptographic verification MUST surface as
        // `Err(LpmError::ProvenanceVerification(...))`, NOT degrade
        // to `Ok(None)`. The old identity-only parse would have either
        // returned Ok(snapshot) or Ok(None) depending on whether the
        // JSON was well-formed; neither was
        // an attack signal. Now the verifier's failure IS the
        // signal.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // A structurally-valid Sigstore bundle JSON whose contents
        // cannot pass verification — random certs / no real Rekor
        // entry. Verifier rejects at chain parse / DSSE / SET /
        // Rekor body etc. — the SPECIFIC variant doesn't matter
        // here; the contract is "any verify failure → LpmError".
        let der = cert_der_with_san_uri(
            "https://github.com/attacker/forged/.github/workflows/build.yml@refs/tags/v1",
        );
        let bundle_bytes = sigstore_bundle_with_cert(&der).to_string().into_bytes();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/att"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bundle_bytes))
            .mount(&server)
            .await;

        let cache = tempfile::tempdir().unwrap();
        let att = AttestationRef {
            url: Some(format!("{}/att", server.uri())),
            provenance: None,
        };
        let http = reqwest::Client::new();
        let err = fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att), None)
            .await
            .expect_err("unverifiable bundle must surface as ProvenanceVerification error");
        match err {
            LpmError::ProvenanceVerification(msg) => {
                // Diagnostic must name a verify-side concern, not a
                // generic JSON parse / network error.
                assert!(
                    !msg.is_empty(),
                    "ProvenanceVerification error must carry a non-empty diagnostic"
                );
            }
            other => panic!(
                "expected LpmError::ProvenanceVerification on unverifiable bundle, got: {other:?}"
            ),
        }

        // Cache MUST stay empty — we do not persist verification
        // failures (registry might be transiently compromised; the
        // next install retries with a fresh fetch).
        let cached = read_cache(cache.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(cached, None, "verification failure must not be cached");
    }

    /// Skip-list pin: `fetch_unverified_snapshot` must succeed on
    /// the same unverifiable-but-structurally-valid bundle that
    /// `fetch_provenance_snapshot` rejects under the `Verified`
    /// path. The legacy identity-only parser extracts the SAN
    /// identity; the verifier is bypassed entirely; the result
    /// lands as `ProvenanceStatus::Unverified(snap)` with the SAN
    /// fields populated. This is the contract the
    /// `--unverified-provenance <name>` flag depends on.
    #[tokio::test]
    async fn fetch_unverified_snapshot_extracts_identity_without_verifier() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let der = cert_der_with_san_uri(
            "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.14.1",
        );
        let bundle_bytes = sigstore_bundle_with_cert(&der).to_string().into_bytes();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/att"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bundle_bytes))
            .mount(&server)
            .await;

        let att = AttestationRef {
            url: Some(format!("{}/att", server.uri())),
            provenance: None,
        };
        let http = reqwest::Client::new();

        // Same bundle that the verifier rejects via
        // `fetch_provenance_snapshot` (see the test above) — but the
        // skip-list path bypasses the verifier and lands on Unverified
        // with the identity intact.
        let status = fetch_unverified_snapshot(&http, "axios", "1.14.1", Some(&att)).await;
        match status {
            ProvenanceStatus::Unverified(snap) => {
                assert!(snap.present, "unverified snapshot must be present:true");
                assert_eq!(snap.publisher.as_deref(), Some("github:axios/axios"));
                assert_eq!(
                    snap.workflow_path.as_deref(),
                    Some(".github/workflows/publish.yml"),
                    "identity-only parser must still extract workflow_path so \
                     the drift comparator has something to compare against",
                );
            }
            other => panic!(
                "skip-list path must produce Unverified on a structurally-valid bundle, got: {other:?}"
            ),
        }
    }

    /// Skip-list edge case: when the package has no attestation URL
    /// at all (registry returned `dist.attestations: null` or
    /// omitted the field), the skip-list path produces `Absent` —
    /// same signal as the verifier path. No observation was
    /// possible to record, but we don't degrade to
    /// `TransportDegraded` because the registry was definitive
    /// about "no provenance shipped" (the axios drop signal
    /// direction).
    #[tokio::test]
    async fn fetch_unverified_snapshot_returns_absent_when_url_missing() {
        let http = reqwest::Client::new();
        let status = fetch_unverified_snapshot(&http, "no-prov", "1.0.0", None).await;
        assert!(
            matches!(status, ProvenanceStatus::Absent),
            "skip-list with no attestation URL must record Absent, got: {status:?}",
        );
    }

    // ── relabel_skip_status_for_enforce_mode ────────────────────
    //
    // Five-variant table: under each `EnforceMode`, what does each
    // `ProvenanceStatus` produced by the skip path become? Pins the
    // labeling contract the JSON envelope depends on. The off-axis
    // arms (Deny, Warn under skip-list) are also pinned so a future
    // refactor that conflates per-package skip with wholesale
    // opt-out has to break a test.

    fn synth_snap() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-leaf".into()),
        }
    }

    #[test]
    fn relabel_under_off_promotes_unverified_to_disabled() {
        let out = relabel_skip_status_for_enforce_mode(
            ProvenanceStatus::Unverified(synth_snap()),
            EnforceMode::Off,
        );
        match out {
            ProvenanceStatus::Disabled(snap) => assert_eq!(snap, synth_snap()),
            other => panic!(
                "Off + Unverified must re-label to Disabled (audit-trail \
                 contract for fleet-wide opt-out), got: {other:?}"
            ),
        }
    }

    /// Under fleet-wide opt-out, an `Absent` observation MUST stay
    /// `Absent` so the JSON envelope reports `verified: false`
    /// (registry served no attestation), not `"disabled"`. An audit
    /// pipeline reading the envelope needs to distinguish "operator
    /// skipped a real bundle" from "there was nothing to verify" -
    /// conflating them would lose the registry-absence signal.
    #[test]
    fn relabel_under_off_preserves_absent_distinct_from_disabled() {
        let out = relabel_skip_status_for_enforce_mode(ProvenanceStatus::Absent, EnforceMode::Off);
        assert!(
            matches!(out, ProvenanceStatus::Absent),
            "Off + Absent must stay Absent — registry-absence signal is independent of \
             operator posture; conflating into Disabled loses the audit-trail \
             distinction, got: {out:?}",
        );
    }

    /// Under fleet-wide opt-out, a transient transport failure is
    /// also a posture-independent signal — stays
    /// `TransportDegraded` (`verified: null`) so the drift gate's
    /// degrade-to-NoDrift contract holds.
    #[test]
    fn relabel_under_off_preserves_transport_degraded() {
        let out = relabel_skip_status_for_enforce_mode(
            ProvenanceStatus::TransportDegraded,
            EnforceMode::Off,
        );
        assert!(
            matches!(out, ProvenanceStatus::TransportDegraded),
            "Off + TransportDegraded must stay TransportDegraded, got: {out:?}",
        );
    }

    /// Per-package skip under non-`Off` modes (the operator
    /// surgically carved foo out via `--unverified-provenance foo`)
    /// keeps `Unverified` so the JSON envelope reports
    /// `verified: "skipped"`. The label distinguishes from
    /// `"disabled"` (which is reserved for the fleet-wide
    /// `EnforceMode::Off` posture).
    #[test]
    fn relabel_under_deny_keeps_unverified_as_skipped_label() {
        let out = relabel_skip_status_for_enforce_mode(
            ProvenanceStatus::Unverified(synth_snap()),
            EnforceMode::Deny,
        );
        assert!(
            matches!(out, ProvenanceStatus::Unverified(_)),
            "Deny + per-package Unverified must keep the surgical label; \
             re-labeling to Disabled would falsely report a fleet-wide opt-out",
        );
    }

    #[test]
    fn relabel_under_warn_keeps_unverified_as_skipped_label() {
        let out = relabel_skip_status_for_enforce_mode(
            ProvenanceStatus::Unverified(synth_snap()),
            EnforceMode::Warn,
        );
        assert!(matches!(out, ProvenanceStatus::Unverified(_)));
    }

    /// Network failures degrade to `Ok(None)` (unknown) and do not
    /// poison future installs with a cached transient failure.
    #[tokio::test]
    async fn fetch_returns_none_on_network_failure_and_does_not_cache() {
        let cache = tempfile::tempdir().unwrap();
        let att = AttestationRef {
            // Loopback to an unused port — connection refused instantly.
            url: Some("http://127.0.0.1:1/never-listens".into()),
            provenance: None,
        };
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let result =
            fetch_provenance_snapshot(&http, cache.path(), "pkg", "1.0.0", Some(&att), None)
                .await
                .unwrap();
        assert_eq!(
            result, None,
            "network failure must degrade to unknown (Ok(None))"
        );

        // Most importantly: the failure must not have written a
        // stub entry to cache. The drift-rule contract depends on
        // `None` never being persisted.
        let cached = read_cache(cache.path(), "pkg", "1.0.0").unwrap();
        assert_eq!(cached, None, "network failure must not be cached");
    }

    // ── map_fetch_result_to_status ──────

    fn snap_present() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-leaf-aaa".into()),
        }
    }

    /// `Ok(Some(snap))` with `present:true` (the verifier returned
    /// a populated, identity-bound snapshot) maps to `Verified`.
    #[test]
    fn batch_maps_verified_snapshot_to_status_verified() {
        let status = map_fetch_result_to_status("axios", "1.14.0", Ok(Some(snap_present())));
        match status {
            ProvenanceStatus::Verified(s) => assert!(s.present),
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    /// `Ok(Some(snap{present:false}))` (registry returned no
    /// attestation URL) maps to `Absent`. This is the axios drop
    /// signal — it must not collapse with `TransportDegraded`.
    #[test]
    fn batch_maps_present_false_snapshot_to_status_absent() {
        let absent_snap = ProvenanceSnapshot {
            present: false,
            ..Default::default()
        };
        let status = map_fetch_result_to_status("axios", "1.14.0", Ok(Some(absent_snap)));
        assert!(
            matches!(status, ProvenanceStatus::Absent),
            "registry-confirmed absence must surface as Absent (the axios drop signal), \
             not collapse with the transport-degrade path",
        );
    }

    /// `Ok(None)` (transient fetch failure, oversized body, etc.)
    /// maps to `TransportDegraded`. Drift comparator's
    /// `(_, None) => NoDrift` arm absorbs this state.
    #[test]
    fn batch_maps_ok_none_to_status_transport_degraded() {
        let status = map_fetch_result_to_status("axios", "1.14.0", Ok(None));
        assert!(matches!(status, ProvenanceStatus::TransportDegraded));
    }

    /// The batch caller's `.ok().flatten()` chain previously collapsed
    /// `Err(LpmError::ProvenanceVerification)` into the same `None`
    /// as a transport failure, blanking the trust binding's
    /// `provenance_at_approval` and disarming the drift comparator's
    /// `(None, _) => NoDrift` arm on every subsequent install.
    /// The verifier rejection MUST surface as
    /// `VerificationRejected { reason }`, distinct from
    /// `TransportDegraded`, with the underlying verifier diagnostic
    /// preserved so the approval-capture path can refuse the binding
    /// and the operator can diagnose the failure mode.
    #[test]
    fn batch_preserves_verification_rejected_distinct_from_transport_degraded() {
        let result = Err(LpmError::ProvenanceVerification(
            "DSSE signature mismatch on payload hash".into(),
        ));
        let status = map_fetch_result_to_status("axios", "1.14.1", result);
        match status {
            ProvenanceStatus::VerificationRejected { reason } => {
                assert!(
                    reason.contains("DSSE signature mismatch"),
                    "verifier diagnostic must propagate through the batch caller, got: {reason}",
                );
            }
            ProvenanceStatus::TransportDegraded => panic!(
                "REGRESSION — verification rejection was collapsed back into TransportDegraded. \
                 Subsequent installs would treat this as a benign transient failure and never \
                 re-flag the forged bundle.",
            ),
            other => panic!("expected VerificationRejected, got {other:?}"),
        }
    }

    /// Non-verification `Err` variants (cache I/O, etc.) degrade to
    /// `TransportDegraded` rather than failing the whole batch. The
    /// install-time path's `?`-propagation contract is preserved by
    /// the single-package fetcher; only the batch caller absorbs
    /// these so one bad row doesn't take down N approvals.
    #[test]
    fn batch_maps_other_errors_to_status_transport_degraded() {
        let result: Result<Option<ProvenanceSnapshot>, LpmError> =
            Err(LpmError::Registry("simulated I/O error".into()));
        let status = map_fetch_result_to_status("axios", "1.14.0", result);
        assert!(
            matches!(status, ProvenanceStatus::TransportDegraded),
            "non-verification errors degrade (the typed-error contract is for the single-package \
             fetcher's `?`-propagation path, not the batch caller)",
        );
    }

    // ── EnforceMode env-var parsing (rollout knob) ──────

    /// Unset env → fail-closed default. This is the production
    /// posture for users who never touch `LPM_PROVENANCE_ENFORCE`.
    #[test]
    fn enforce_mode_from_env_unset_is_deny() {
        assert_eq!(EnforceMode::from_env_value(None), EnforceMode::Deny);
    }

    /// `LPM_PROVENANCE_ENFORCE=warn` → `Warn` (the rollout-window
    /// posture). Approval-capture path logs + records None instead
    /// of refusing.
    #[test]
    fn enforce_mode_from_env_warn_is_warn() {
        assert_eq!(EnforceMode::from_env_value(Some("warn")), EnforceMode::Warn);
    }

    /// `LPM_PROVENANCE_ENFORCE=deny` → `Deny` (explicit). Same as
    /// unset, but operators sometimes set this defensively in
    /// CI/CD env so they can `grep` for the policy.
    #[test]
    fn enforce_mode_from_env_explicit_deny_is_deny() {
        assert_eq!(EnforceMode::from_env_value(Some("deny")), EnforceMode::Deny);
    }

    /// Unknown values (typo, mis-cased, etc.) must fall back to
    /// `Deny` so a misconfiguration NEVER silently weakens the
    /// posture. A `tracing::warn` surfaces the fallback; we don't
    /// assert on that here (the tracing subscriber would need to be
    /// wired up), but the fail-closed behavior is the load-bearing
    /// guarantee.
    ///
    /// `"off"` is a valid value (the fleet-wide opt-out posture);
    /// it's not in the unknown-fallback set. The canonical-values
    /// pin (`enforce_mode_parses_three_canonical_values`) covers
    /// it.
    #[test]
    fn enforce_mode_from_env_unknown_value_falls_back_to_deny() {
        assert_eq!(EnforceMode::from_env_value(Some("DENY")), EnforceMode::Deny);
        assert_eq!(EnforceMode::from_env_value(Some("typo")), EnforceMode::Deny);
        assert_eq!(EnforceMode::from_env_value(Some("")), EnforceMode::Deny);
    }
}
