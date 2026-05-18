//! Publisher-identity snapshot captured from a package version's
//! Sigstore attestation bundle.
//!
//! Used to detect **provenance drift** between a previously-approved
//! version and a candidate version. The axios 1.14.1 compromise is
//! the motivating case: every legitimate v1 release shipped with GitHub
//! OIDC + Sigstore provenance; the malicious v1.14.1 did not. The drift
//! check compares the tuple field-by-field.
//!
//! This type lives in `lpm-common` because it is pure schema consumed by
//! both `lpm-workspace` (via `TrustedDependencyBinding.provenance_at_approval`)
//! AND `lpm-global` (via `GlobalTrustedDependencies::TrustedDependencyBinding.provenance_at_approval`).
//! Owning it in `lpm-common` keeps `lpm-global` from depending on
//! `lpm-workspace` while still letting both bindings share one
//! authoritative serde shape. `lpm-workspace` re-exports the type
//! (`pub use lpm_common::ProvenanceSnapshot;`) so existing call sites
//! continue importing it unchanged.

use serde::{Deserialize, Serialize};

/// Outcome of fetching a single package's provenance bundle.
///
/// Distinguishes the four states the install-time and approve-time
/// paths must treat differently. Phase 2.1 introduced the
/// cryptographic verifier and `LpmError::ProvenanceVerification`,
/// but the batch caller in `provenance_fetch::fetch_provenance_for_pkgs`
/// previously collapsed every result through `.ok().flatten()`,
/// making a verifier rejection indistinguishable from a network
/// failure. Recording the resulting `provenance_at_approval = None`
/// would then disarm the drift comparator on every subsequent
/// install (its `(None, _) => NoDrift` arm). `ProvenanceStatus`
/// exists so the four states stay distinct end-to-end: the
/// approval-capture path can refuse to record a binding on
/// `VerificationRejected`, while still degrading to `NoDrift` on
/// genuine `TransportDegraded` per the offline contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceStatus {
    /// Bundle fetched, cryptographically verified, identity bound.
    /// The contained snapshot has `present == true` and the SAN
    /// fields populated.
    Verified(ProvenanceSnapshot),
    /// Bundle fetched and identity extracted, but the cryptographic
    /// verifier was bypassed because the operator carved this package
    /// out via `--unverified-provenance <name>` /
    /// `--unverified-provenance-all` (the `SkipPolicy` axis added in
    /// Phase 2.2.c). The snapshot carries the same SAN identity fields
    /// as `Verified` so drift detection still runs against the
    /// identity tuple, but the binding's audit trail records that this
    /// observation was NOT cryptographically attested. JSON envelope
    /// reports `verified: "skipped"` for this state.
    ///
    /// **Why a distinct variant rather than collapsing back into
    /// `Verified`:** an operator-driven skip is an explicit downgrade
    /// — surfacing it as a separate state lets the trust binding and
    /// approve-scripts audit trail say "this identity was accepted
    /// without crypto" instead of falsely claiming verification.
    Unverified(ProvenanceSnapshot),
    /// Registry returned no attestation URL for this version
    /// (definitive "no provenance shipped"). This is the axios drop
    /// signal direction — when compared against an approved-side
    /// snapshot that DID carry provenance, the drift comparator
    /// emits `ProvenanceDropped`.
    Absent,
    /// Transient failure post-attempt: network error, oversized body,
    /// 4xx/5xx, malformed bundle JSON. The fetcher cannot produce a
    /// definitive answer and the drift comparator degrades to
    /// `NoDrift` per the offline-mode contract documented at
    /// `provenance_fetch.rs:20`. The next install retries.
    TransportDegraded,
    /// Bundle was fetched successfully but the cryptographic verifier
    /// rejected it (DSSE signature, X.509 chain, embedded SCT, Rekor
    /// body match, Rekor SET, inclusion proof, or identity pin
    /// failure). This is an attack signal distinct from
    /// `TransportDegraded` — the approval-capture path refuses to
    /// record a binding rather than silently overwriting the prior
    /// `provenance_at_approval` with `None` and disarming the drift
    /// comparator on subsequent installs.
    VerificationRejected { reason: String },
}

impl ProvenanceStatus {
    /// Project the status to the legacy `Option<ProvenanceSnapshot>`
    /// shape used by the trust-binding `provenance_at_approval`
    /// field, with explicit refusal on `VerificationRejected`.
    ///
    /// Returns:
    /// - `Ok(Some(snap))` for `Verified` — caller records the
    ///   identity in the binding.
    /// - `Ok(Some(snap{present:false}))` for `Absent` — caller
    ///   records the axios drop signal in the binding so the next
    ///   install's drift gate can detect a regression if the package
    ///   later gains provenance.
    /// - `Ok(None)` for `TransportDegraded` — caller records no
    ///   provenance reference; the drift comparator's
    ///   `(_, None) => NoDrift` arm absorbs this transient state.
    /// - `Err(LpmError::ProvenanceVerification(_))` for
    ///   `VerificationRejected` — caller MUST surface this rather
    ///   than swallow it. Default-deny: the approval is refused and
    ///   the prior binding (if any) is preserved by the caller's
    ///   read-modify-write loop NOT executing.
    pub fn into_snapshot_for_binding(
        self,
        name: &str,
        version: &str,
    ) -> Result<Option<ProvenanceSnapshot>, crate::LpmError> {
        match self {
            ProvenanceStatus::Verified(s) | ProvenanceStatus::Unverified(s) => Ok(Some(s)),
            ProvenanceStatus::Absent => Ok(Some(ProvenanceSnapshot {
                present: false,
                ..Default::default()
            })),
            ProvenanceStatus::TransportDegraded => Ok(None),
            ProvenanceStatus::VerificationRejected { reason } => {
                Err(crate::LpmError::ProvenanceVerification(format!(
                    "verification of provenance bundle for '{name}@{version}' failed: \
                     {reason}. Approval refused so the prior trust binding \
                     (if any) is preserved. Re-run after the registry serves \
                     a verifiable bundle, or pass `--unverified-provenance \
                     {name}` to fall back to identity-only capture."
                )))
            }
        }
    }

    /// `true` iff this status carries an attack signal that should
    /// block the install or approval rather than degrade silently.
    /// Currently only `VerificationRejected`; future statuses (e.g.
    /// chain-of-trust mismatch warnings) can extend this.
    pub fn is_rejection(&self) -> bool {
        matches!(self, ProvenanceStatus::VerificationRejected { .. })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ProvenanceSnapshot {
    /// `true` iff the registry returned a non-empty attestations
    /// bundle for this version. `false` indicates "registry has no
    /// provenance for this version" — which is the exact axios-case
    /// signal when compared against a prior-approved version that had
    /// provenance.
    pub present: bool,
    /// Publisher identity extracted from the Sigstore cert SAN —
    /// `github:<org>/<repo>`. Stable across releases from the same
    /// repo. **Part of the drift-check identity tuple** (see
    /// `lpm_security::provenance::check_provenance_drift`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// Workflow file path: `.github/workflows/<filename>`. Stable
    /// across releases from the same workflow. **Part of the
    /// drift-check identity tuple.** Split from the full SAN URI so
    /// the per-release ref (which IS captured in [`workflow_ref`])
    /// does not falsely trigger identity drift between legitimate
    /// releases.
    ///
    /// [`workflow_ref`]: ProvenanceSnapshot::workflow_ref
    #[serde(
        default,
        rename = "workflowPath",
        skip_serializing_if = "Option::is_none"
    )]
    pub workflow_path: Option<String>,
    /// Git ref the workflow ran against: `refs/tags/<tag>`,
    /// `refs/heads/<branch>`, or `refs/pull/<n>/merge`. **Varies per
    /// release** — excluded from the identity tuple. Retained for
    /// audit / UX: the drift-gate renders it in the "last approved
    /// via X at REF" line so reviewers can see which specific
    /// release produced the approved reference.
    ///
    /// **Why this is NOT part of identity equality:** axios v1.14.0
    /// and v1.14.1 from the same repo + workflow carry the same
    /// publisher and workflow_path but necessarily different refs.
    /// Comparing refs would falsely mark every patch bump as
    /// "identity changed" — the exact "reviewer finding: drift
    /// comparator flags normal provenance-preserving releases" bug
    /// this field split prevents.
    #[serde(
        default,
        rename = "workflowRef",
        skip_serializing_if = "Option::is_none"
    )]
    pub workflow_ref: Option<String>,
    /// SHA-256 of the leaf attestation certificate (DER-encoded).
    /// **Ephemeral** — Fulcio issues a fresh leaf per signing, so
    /// the cert SHA rotates every release. **Excluded from identity
    /// equality** for the same reason as `workflow_ref`; retained
    /// for audit (the approved reference's cert SHA is surfaced in
    /// verbose drift diagnostics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_cert_sha256: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_snapshot_full_roundtrips() {
        let snap = ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-abc123".into()),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: ProvenanceSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn provenance_snapshot_absent_minimal_json() {
        // When `present == false` and the extraction path didn't fill
        // in any optional fields, the serialized form should be minimal
        // (no `null` keys for the optionals, thanks to
        // skip_serializing_if).
        let snap = ProvenanceSnapshot {
            present: false,
            ..Default::default()
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert_eq!(
            json, r#"{"present":false}"#,
            "absent snapshot should not emit null keys for optional \
             fields — smaller JSON + less noise in build-state.json"
        );
    }

    #[test]
    fn provenance_snapshot_partial_parse() {
        // Real-world path: attestation bundle parses but the SAN
        // extractor only got the publisher, not the workflow or cert
        // SHA. The type must accept this degraded input.
        let json = r#"{
            "present": true,
            "publisher": "github:axios/axios"
        }"#;
        let snap: ProvenanceSnapshot = serde_json::from_str(json).unwrap();
        assert!(snap.present);
        assert_eq!(snap.publisher.as_deref(), Some("github:axios/axios"));
        assert!(snap.workflow_path.is_none());
        assert!(snap.workflow_ref.is_none());
        assert!(snap.attestation_cert_sha256.is_none());
    }

    /// Field-by-field equality of the full snapshot is used by the
    /// cache round-trip paths (serialize → read back, assert equal)
    /// and by the schema-test round-trips here. The DRIFT comparator
    /// in `lpm-security::provenance` uses a narrower identity-only
    /// equality (publisher + workflow_path) — see that crate's
    /// `identity_equal` helper + its regression guards for
    /// release-varying fields.
    #[test]
    fn provenance_snapshot_full_equality_is_tuple_strict() {
        let base = ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-aaa".into()),
        };
        let differ_publisher = ProvenanceSnapshot {
            publisher: Some("github:someone-else/axios".into()),
            ..base.clone()
        };
        let differ_workflow_path = ProvenanceSnapshot {
            workflow_path: Some(".github/workflows/pr-workflow.yml".into()),
            ..base.clone()
        };
        let differ_workflow_ref = ProvenanceSnapshot {
            workflow_ref: Some("refs/tags/v1.14.1".into()),
            ..base.clone()
        };
        let differ_cert = ProvenanceSnapshot {
            attestation_cert_sha256: Some("sha256-bbb".into()),
            ..base.clone()
        };
        assert_ne!(base, differ_publisher);
        assert_ne!(base, differ_workflow_path);
        assert_ne!(base, differ_workflow_ref);
        assert_ne!(base, differ_cert);
        assert_eq!(base, base.clone());
    }

    // ── ProvenanceStatus → binding projection (Phase 2.2 SILENT-DROP) ──

    fn axios_snap() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some("github:axios/axios".into()),
            workflow_path: Some(".github/workflows/publish.yml".into()),
            workflow_ref: Some("refs/tags/v1.14.0".into()),
            attestation_cert_sha256: Some("sha256-leaf-aaa".into()),
        }
    }

    /// `Verified` projects to `Some(snap)` for the trust binding so
    /// the next install's drift gate can compare identity tuples.
    #[test]
    fn provenance_status_verified_projects_to_some_snapshot() {
        let snap = axios_snap();
        let status = ProvenanceStatus::Verified(snap.clone());
        let projected = status
            .into_snapshot_for_binding("axios", "1.14.0")
            .expect("Verified must project to Ok(Some)");
        assert_eq!(projected, Some(snap));
    }

    /// `Absent` projects to `Some(snap{present:false})` — the axios
    /// drop signal. If projected to `None`, the next install would
    /// hit the comparator's `(None, _) => NoDrift` arm and miss a
    /// regression where the package later gained provenance.
    #[test]
    fn provenance_status_absent_projects_to_present_false_snapshot() {
        let projected = ProvenanceStatus::Absent
            .into_snapshot_for_binding("some-pkg", "1.0.0")
            .expect("Absent must project to Ok(Some(present:false))");
        let snap = projected.expect("Absent must not collapse to None");
        assert!(
            !snap.present,
            "Absent must surface as present:false so the drift \
             comparator can detect a later transition to present:true",
        );
    }

    /// `TransportDegraded` projects to `None` so the drift
    /// comparator's `(_, None) => NoDrift` arm absorbs the transient
    /// state. This is the legitimate degrade-to-pass contract.
    #[test]
    fn provenance_status_transport_degraded_projects_to_none() {
        let projected = ProvenanceStatus::TransportDegraded
            .into_snapshot_for_binding("some-pkg", "1.0.0")
            .expect("TransportDegraded is not an attack signal");
        assert!(projected.is_none(), "transport-degraded must record no binding");
    }

    /// `VerificationRejected` propagates as
    /// `LpmError::ProvenanceVerification(_)` rather than projecting
    /// to `None`. This is the **regression guard** for the
    /// post-Phase-2.1 SILENT-DROP audit finding: pre-fix
    /// `.ok().flatten()` swallowed this state into `None`, which the
    /// drift comparator then read as "first observation, no drift"
    /// on every subsequent install — permanently disarming
    /// publisher-swap detection after a single attack-window
    /// approval. The error MUST surface so the caller's `?` refuses
    /// the approval.
    #[test]
    fn provenance_status_verification_rejected_propagates_as_error() {
        let status = ProvenanceStatus::VerificationRejected {
            reason: "DSSE signature mismatch".into(),
        };
        let err = status
            .into_snapshot_for_binding("axios", "1.14.1")
            .expect_err("VerificationRejected MUST NOT collapse to Ok(None)");
        assert!(
            matches!(err, crate::LpmError::ProvenanceVerification(_)),
            "must be the typed verification variant, got {err:?}",
        );
        // The error message must name the package + version so the
        // operator can identify what was rejected without consulting
        // tracing output.
        let msg = err.to_string();
        assert!(
            msg.contains("axios") && msg.contains("1.14.1"),
            "error must name the package + version. got: {msg}",
        );
        // It must also carry the underlying verifier reason so the
        // failure mode (DSSE / Rekor / SCT / chain / identity) is
        // diagnosable from a single line.
        assert!(
            msg.contains("DSSE signature mismatch"),
            "error must include the verifier's reason. got: {msg}",
        );
    }

    /// `is_rejection` lets call sites short-circuit before any
    /// trust-store mutation. The other four states must not flag.
    #[test]
    fn provenance_status_is_rejection_only_for_verification_rejected() {
        assert!(
            !ProvenanceStatus::Verified(axios_snap()).is_rejection(),
            "Verified is not a rejection",
        );
        assert!(
            !ProvenanceStatus::Unverified(axios_snap()).is_rejection(),
            "Unverified (operator-skipped) is not a rejection — it's an opt-out",
        );
        assert!(!ProvenanceStatus::Absent.is_rejection(), "Absent is not a rejection");
        assert!(
            !ProvenanceStatus::TransportDegraded.is_rejection(),
            "TransportDegraded is not a rejection",
        );
        assert!(
            ProvenanceStatus::VerificationRejected {
                reason: "x".into()
            }
            .is_rejection(),
            "VerificationRejected must be flagged",
        );
    }

    /// `Unverified` projects to `Some(snap)` so the operator's
    /// explicit opt-out still records the identity in the binding —
    /// the next install's drift gate can still compare publisher /
    /// workflow_path. JSON envelope downstream distinguishes the
    /// audit-trail state (`verified: "skipped"`) without losing the
    /// drift-detection signal.
    #[test]
    fn provenance_status_unverified_projects_to_some_snapshot() {
        let snap = axios_snap();
        let status = ProvenanceStatus::Unverified(snap.clone());
        let projected = status
            .into_snapshot_for_binding("axios", "1.14.0")
            .expect("Unverified must project to Ok(Some) — identity still drives drift");
        assert_eq!(projected, Some(snap));
    }
}
