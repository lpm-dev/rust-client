use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use lpm_common::Timestamp;
use lpm_common::timestamp::Duration;
use std::sync::Arc;
use std::time::SystemTime;

use super::VerifyError;

pub(super) const EMBEDDED_TRUST_ROOT_JSON: &[u8] =
    include_bytes!("../../assets/sigstore_trusted_root.json");

/// Warn-window in days before `expires_at_soonest`. Operator hint
/// only — does not affect fail-closed behaviour.
pub(super) const TRUST_ROOT_EXPIRY_WARN_DAYS: i64 = 30;

/// A parsed Sigstore trust root: the Fulcio certificate authorities,
/// Rekor logs and CT logs bundles are verified against.
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
    pub start: Timestamp,
    /// `None` means open-ended — entry is still in service per
    /// Sigstore; no announced retirement date.
    pub end: Option<Timestamp>,
}

impl ValidityWindow {
    /// Inclusive lower bound, exclusive upper bound. An open-ended
    /// window contains every `t >= start`.
    #[allow(dead_code)]
    pub fn contains(&self, t: SystemTime) -> bool {
        let t: Timestamp = t.into();
        t >= self.start && self.end.is_none_or(|end| t < end)
    }
}

// ─── JSON DTOs matching trusted_root.json (protobuf-JSON shape) ──

#[derive(Debug, serde::Deserialize)]
struct TrustedRootJson {
    #[serde(rename = "certificateAuthorities", default)]
    certificate_authorities: Vec<serde_json::Value>,
    #[serde(default)]
    tlogs: Vec<serde_json::Value>,
    #[serde(default)]
    ctlogs: Vec<serde_json::Value>,
}

fn deserialize_entry<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, VerifyError> {
    serde_json::from_value(value).map_err(|e| VerifyError::TrustRoot(format!("JSON parse: {e}")))
}

fn collect_entries<T>(
    values: Vec<serde_json::Value>,
    skip_unreadable: bool,
    parse: impl Fn(serde_json::Value) -> Result<T, VerifyError>,
) -> Result<Vec<T>, VerifyError> {
    let mut entries = Vec::with_capacity(values.len());
    for value in values {
        match parse(value) {
            Ok(entry) => entries.push(entry),
            Err(error) if skip_unreadable => {
                tracing::debug!(
                    target: "lpm_cli::sigstore_verify",
                    %error,
                    "skipping a Sigstore trust root entry this version can't read",
                );
            }
            Err(error) => return Err(error),
        }
    }
    Ok(entries)
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
    start: Timestamp,
    #[serde(default)]
    end: Option<Timestamp>,
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
    /// global state. Use [`trust_root`] for the one verification
    /// uses; bytes passed here must come from the binary or from
    /// Sigstore's TUF repository through [`super::tuf`].
    pub fn parse(bytes: &[u8]) -> Result<TrustRoot, VerifyError> {
        Self::parse_entries(bytes, false)
    }

    /// Parse a trust root from Sigstore's TUF repository, skipping any
    /// entry this version can't read rather than refusing the whole
    /// root. Sigstore can add entries in shapes newer than this
    /// version, and the entries it can read must stay usable.
    pub fn parse_skipping_unreadable(bytes: &[u8]) -> Result<TrustRoot, VerifyError> {
        Self::parse_entries(bytes, true)
    }

    fn parse_entries(bytes: &[u8], skip_unreadable: bool) -> Result<TrustRoot, VerifyError> {
        let raw: TrustedRootJson = serde_json::from_slice(bytes)
            .map_err(|e| VerifyError::TrustRoot(format!("JSON parse: {e}")))?;
        let fulcio_roots =
            collect_entries(raw.certificate_authorities, skip_unreadable, |value| {
                parse_fulcio_root(deserialize_entry(value)?)
            })?;
        let rekor_keys = collect_entries(raw.tlogs, skip_unreadable, |value| {
            let (log_id, spki_der, valid_for) = parse_log_key(deserialize_entry(value)?)?;
            Ok(RekorKey {
                log_id,
                spki_der,
                valid_for,
            })
        })?;
        let ctlog_keys = collect_entries(raw.ctlogs, skip_unreadable, |value| {
            let (log_id, spki_der, valid_for) = parse_log_key(deserialize_entry(value)?)?;
            Ok(CtLogKey {
                log_id,
                spki_der,
                valid_for,
            })
        })?;
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
    pub fn next_role_retirement_at(&self, now: SystemTime) -> Option<Timestamp> {
        fn latest_active_end<'a, I>(windows: I, now: SystemTime) -> Option<Timestamp>
        where
            I: IntoIterator<Item = &'a ValidityWindow>,
        {
            let mut latest: Option<Timestamp> = None;
            let mut saw_active = false;
            for w in windows {
                if !w.contains(now) {
                    continue;
                }
                saw_active = true;
                // Open-ended active entry → role has no retirement anchor.
                let end = w.end?;
                latest = Some(latest.map_or(end, |l| l.max(end)));
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
    pub fn within_warn_window(&self, now: SystemTime) -> Option<Timestamp> {
        let soonest = self.next_role_retirement_at(now)?;
        let now_dt: Timestamp = now.into();
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

/// The trust root verification uses: the newest one Sigstore's TUF
/// repository has delivered to this machine, or the one built into the
/// binary. See [`super::trust_store`].
pub fn trust_root() -> Result<Arc<TrustRoot>, VerifyError> {
    super::trust_store::global().current()
}
