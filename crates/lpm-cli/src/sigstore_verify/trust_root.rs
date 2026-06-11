use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Duration, Utc};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use super::VerifyError;

pub(super) const EMBEDDED_TRUST_ROOT_JSON: &[u8] =
    include_bytes!("../../assets/sigstore_trusted_root.json");

/// Warn-window in days before `expires_at_soonest`. Operator hint
/// only — does not affect fail-closed behaviour.
pub(super) const TRUST_ROOT_EXPIRY_WARN_DAYS: i64 = 30;

/// Vendored Sigstore trust root. Parsed once at startup from
/// `assets/sigstore_trusted_root.json` and cached via [`trust_root`].
#[allow(dead_code)]
#[derive(Debug)]
pub struct TrustRoot {
    pub fulcio_roots: Vec<FulcioRoot>,
    pub rekor_keys: Vec<RekorKey>,
    pub ctlog_keys: Vec<CtLogKey>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct FulcioRoot {
    /// DER-encoded certs in chain order — the trust anchor (root)
    /// is `[0]`. Most public-good Fulcio roots ship a single cert,
    /// but the schema permits a chain (root + intermediates) when
    /// Sigstore rotates a cross-signed root through.
    pub cert_chain_der: Vec<Vec<u8>>,
    pub valid_for: ValidityWindow,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RekorKey {
    /// Sha-256 of the SPKI bytes — what Rekor embeds as `logID` in
    /// transparency-log entries. Stored raw so the verifier compares
    /// by byte slice; Rekor's API exposes it as hex, the trust root
    /// carries it as base64 — both decode to
    /// the same 32-byte hash, that's the canonical form.
    pub log_id: Vec<u8>,
    /// DER-encoded SubjectPublicKeyInfo for verifying the SET.
    pub spki_der: Vec<u8>,
    pub valid_for: ValidityWindow,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct CtLogKey {
    pub log_id: Vec<u8>,
    pub spki_der: Vec<u8>,
    pub valid_for: ValidityWindow,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidityWindow {
    pub start: DateTime<Utc>,
    /// `None` means open-ended — entry is still in service per
    /// Sigstore; no announced retirement date.
    pub end: Option<DateTime<Utc>>,
}

impl ValidityWindow {
    /// Inclusive lower bound, exclusive upper bound. An open-ended
    /// window contains every `t >= start`.
    #[allow(dead_code)]
    pub fn contains(&self, t: SystemTime) -> bool {
        let t: DateTime<Utc> = t.into();
        t >= self.start && self.end.is_none_or(|end| t < end)
    }
}

// ─── JSON DTOs matching trusted_root.json (protobuf-JSON shape) ──

#[derive(Debug, serde::Deserialize)]
struct TrustedRootJson {
    #[serde(rename = "certificateAuthorities", default)]
    certificate_authorities: Vec<TrustedRootCa>,
    #[serde(default)]
    tlogs: Vec<TrustedRootLog>,
    #[serde(default)]
    ctlogs: Vec<TrustedRootLog>,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootCa {
    #[serde(rename = "certChain")]
    cert_chain: TrustedRootCertChain,
    #[serde(rename = "validFor")]
    valid_for: TrustedRootValidFor,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootCertChain {
    certificates: Vec<TrustedRootCertEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootCertEntry {
    #[serde(rename = "rawBytes")]
    raw_bytes: String,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootLog {
    #[serde(rename = "logId")]
    log_id: TrustedRootLogId,
    #[serde(rename = "publicKey")]
    public_key: TrustedRootKey,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootLogId {
    #[serde(rename = "keyId")]
    key_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootKey {
    #[serde(rename = "rawBytes")]
    raw_bytes: String,
    #[serde(rename = "validFor")]
    valid_for: TrustedRootValidFor,
}

#[derive(Debug, serde::Deserialize)]
struct TrustedRootValidFor {
    start: DateTime<Utc>,
    #[serde(default)]
    end: Option<DateTime<Utc>>,
}

impl From<TrustedRootValidFor> for ValidityWindow {
    fn from(v: TrustedRootValidFor) -> Self {
        ValidityWindow {
            start: v.start,
            end: v.end,
        }
    }
}

// ─── Parser + accessors ──────────────────────────────────────────

#[allow(dead_code)]
impl TrustRoot {
    /// Parse a trust root from raw JSON bytes. Pure — no I/O, no
    /// global state. Use [`trust_root`] for the production
    /// embedded-bytes entry; this is the test seam and is also
    /// available for future code that wants to consume a non-embedded
    /// root. Callers that accept non-embedded roots must preserve the
    /// same fail-closed validation semantics as the embedded path.
    pub fn parse(bytes: &[u8]) -> Result<TrustRoot, VerifyError> {
        let raw: TrustedRootJson = serde_json::from_slice(bytes)
            .map_err(|e| VerifyError::TrustRoot(format!("JSON parse: {e}")))?;

        let fulcio_roots = raw
            .certificate_authorities
            .into_iter()
            .map(parse_fulcio_root)
            .collect::<Result<Vec<_>, _>>()?;

        let rekor_keys = raw
            .tlogs
            .into_iter()
            .map(parse_log_key)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(log_id, spki_der, valid_for)| RekorKey {
                log_id,
                spki_der,
                valid_for,
            })
            .collect();

        let ctlog_keys = raw
            .ctlogs
            .into_iter()
            .map(parse_log_key)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(log_id, spki_der, valid_for)| CtLogKey {
                log_id,
                spki_der,
                valid_for,
            })
            .collect();

        Ok(TrustRoot {
            fulcio_roots,
            rekor_keys,
            ctlog_keys,
        })
    }

    /// Fulcio roots whose CA-level validity window contains `t`. The
    /// individual certs inside also have intrinsic notBefore/notAfter
    /// that the chain walker checks; this filter is the
    /// outer gate from Sigstore's published service-window metadata.
    pub fn fulcio_roots_at(&self, t: SystemTime) -> Vec<&FulcioRoot> {
        self.fulcio_roots
            .iter()
            .filter(|r| r.valid_for.contains(t))
            .collect()
    }

    /// Rekor signing key for the entry's `logID`, valid at `t`.
    /// `log_id` is the raw 32-byte sha256 of the SPKI — callers
    /// hex-decode (Rekor canonical body) or base64-decode (TUF
    /// metadata) into this form.
    pub fn rekor_key_at(&self, log_id: &[u8], t: SystemTime) -> Option<&RekorKey> {
        self.rekor_keys
            .iter()
            .find(|k| k.log_id == log_id && k.valid_for.contains(t))
    }

    /// CT log key for an SCT's `logID`, valid at `t`.
    pub fn ctlog_key_at(&self, log_id: &[u8], t: SystemTime) -> Option<&CtLogKey> {
        self.ctlog_keys
            .iter()
            .find(|k| k.log_id == log_id && k.valid_for.contains(t))
    }

    /// Hard-fail path: error if any role (Fulcio, Rekor, CT log)
    /// has zero currently-active keys at `now`. Pure for testability.
    /// Wall-clock invocation lives in [`trust_root`].
    ///
    /// "Currently active at `now`" = `valid_for.contains(now)` — both
    /// `start <= now` and (`end is None` OR `end > now`). Retired
    /// entries (end <= now) don't count.
    pub fn check_expiry(&self, now: SystemTime) -> Result<(), VerifyError> {
        let mut missing: Vec<&str> = Vec::new();
        if !self.fulcio_roots.iter().any(|r| r.valid_for.contains(now)) {
            missing.push("Fulcio CA");
        }
        if !self.rekor_keys.iter().any(|k| k.valid_for.contains(now)) {
            missing.push("Rekor signing key");
        }
        if !self.ctlog_keys.iter().any(|k| k.valid_for.contains(now)) {
            missing.push("CT log key");
        }
        if missing.is_empty() {
            return Ok(());
        }
        Err(VerifyError::TrustRootExpired {
            missing_roles: missing.join(", "),
        })
    }

    /// Soonest "next currently-active key retirement" date. Per
    /// role, the role's retirement date is the LATEST `end` among
    /// currently-active keys (because the artifact remains useful
    /// while at least one key is active). The artifact's effective
    /// retirement is the EARLIEST such per-role retirement.
    ///
    /// Returns `None` when at least one currently-active key for
    /// every role is open-ended — no announced retirement, so no
    /// warn anchor.
    pub fn next_role_retirement_at(&self, now: SystemTime) -> Option<DateTime<Utc>> {
        fn latest_active_end<'a, I>(windows: I, now: SystemTime) -> Option<DateTime<Utc>>
        where
            I: IntoIterator<Item = &'a ValidityWindow>,
        {
            let mut latest: Option<DateTime<Utc>> = None;
            let mut saw_active = false;
            for w in windows {
                if !w.contains(now) {
                    continue;
                }
                saw_active = true;
                match w.end {
                    // Open-ended active entry → role has no retirement anchor.
                    None => return None,
                    Some(end) => {
                        latest = Some(latest.map_or(end, |l| l.max(end)));
                    }
                }
            }
            if saw_active { latest } else { None }
        }
        let fulcio = latest_active_end(self.fulcio_roots.iter().map(|r| &r.valid_for), now);
        let rekor = latest_active_end(self.rekor_keys.iter().map(|k| &k.valid_for), now);
        let ctlog = latest_active_end(self.ctlog_keys.iter().map(|k| &k.valid_for), now);
        [fulcio, rekor, ctlog].into_iter().flatten().min()
    }

    /// Whether [`Self::next_role_retirement_at`] is within
    /// `TRUST_ROOT_EXPIRY_WARN_DAYS` of `now`. Used by [`trust_root`]'s
    /// startup `tracing::warn`. Returns `None` when no anchor or
    /// when the anchor is further out than the warn window.
    pub fn within_warn_window(&self, now: SystemTime) -> Option<DateTime<Utc>> {
        let soonest = self.next_role_retirement_at(now)?;
        let now_dt: DateTime<Utc> = now.into();
        let warn_at = soonest - Duration::days(TRUST_ROOT_EXPIRY_WARN_DAYS);
        if now_dt > warn_at && now_dt <= soonest {
            Some(soonest)
        } else {
            None
        }
    }
}

fn parse_fulcio_root(raw: TrustedRootCa) -> Result<FulcioRoot, VerifyError> {
    let mut cert_chain_der = Vec::with_capacity(raw.cert_chain.certificates.len());
    for cert in raw.cert_chain.certificates {
        let der = BASE64.decode(cert.raw_bytes.as_bytes()).map_err(|e| {
            VerifyError::TrustRoot(format!("Fulcio CA cert rawBytes not base64: {e}"))
        })?;
        cert_chain_der.push(der);
    }
    if cert_chain_der.is_empty() {
        return Err(VerifyError::TrustRoot(
            "Fulcio CA entry has an empty certChain".into(),
        ));
    }
    Ok(FulcioRoot {
        cert_chain_der,
        valid_for: raw.valid_for.into(),
    })
}

fn parse_log_key(raw: TrustedRootLog) -> Result<(Vec<u8>, Vec<u8>, ValidityWindow), VerifyError> {
    let log_id = BASE64
        .decode(raw.log_id.key_id.as_bytes())
        .map_err(|e| VerifyError::TrustRoot(format!("logId.keyId not base64: {e}")))?;
    let spki_der = BASE64
        .decode(raw.public_key.raw_bytes.as_bytes())
        .map_err(|e| VerifyError::TrustRoot(format!("log publicKey.rawBytes not base64: {e}")))?;
    Ok((log_id, spki_der, raw.public_key.valid_for.into()))
}

/// Cached parsed trust root, populated on first [`trust_root`] call.
static TRUST_ROOT_CELL: OnceLock<Result<Arc<TrustRoot>, String>> = OnceLock::new();

/// Production accessor: lazily loads the embedded trust root, runs
/// the startup expiry check, and emits the 30-day warn if applicable.
/// Subsequent calls return a cheap `Arc::clone` of the cached root.
///
/// Error semantics: parse failures and post-expiry rejection are both
/// surfaced via the cached `Err` variant — once this function
/// returns an error for the process lifetime, it always will. That's
/// load-bearing: a verifier path that succeeded the first call must
/// not silently start failing mid-install because something flapped.
#[allow(dead_code)] // wired into provenance_fetch
pub fn trust_root() -> Result<Arc<TrustRoot>, VerifyError> {
    let cached = TRUST_ROOT_CELL.get_or_init(|| {
        let parsed =
            TrustRoot::parse(EMBEDDED_TRUST_ROOT_JSON).map_err(|e| format!("parse failed: {e}"))?;
        let now = SystemTime::now();

        if let Some(expires) = parsed.within_warn_window(now) {
            tracing::warn!(
                target: "lpm_cli::sigstore_verify",
                expires_at = %expires,
                "vendored Sigstore trust root expires within {} days; update lpm to refresh",
                TRUST_ROOT_EXPIRY_WARN_DAYS,
            );
        }

        if let Err(VerifyError::TrustRootExpired { missing_roles }) = parsed.check_expiry(now) {
            return Err(format!(
                "vendored Sigstore trust root has no currently-active key for role(s) \
                 {missing_roles}; update lpm to refresh"
            ));
        }

        Ok(Arc::new(parsed))
    });
    match cached {
        Ok(arc) => Ok(Arc::clone(arc)),
        Err(msg) => Err(VerifyError::TrustRoot(msg.clone())),
    }
}
