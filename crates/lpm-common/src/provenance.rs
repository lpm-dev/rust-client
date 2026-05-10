//! Publisher-identity snapshot captured from a package version's
//! Sigstore attestation bundle.
//!
//! Phase 46 uses this to detect **provenance drift** between a
//! previously-approved version and a candidate version. The axios
//! 1.14.1 compromise is the motivating case: every legitimate v1
//! release shipped with GitHub OIDC + Sigstore provenance; the
//! malicious v1.14.1 did not. The drift check (§7.2 of the plan)
//! compares the tuple field-by-field.
//!
//! Populated from the Sigstore bundle's leaf-cert SAN. P1 defined the
//! type's shape and the `Option<ProvenanceSnapshot>` field placements
//! on `lpm_workspace::TrustedDependencyBinding` (added by P4) and
//! `lpm_cli::build_state::BlockedPackage` (added by P1). P4 wires the
//! actual fetch + parse in the CLI.
//!
//! **Schema-crate placement (Phase 68 relocation):** this type lives
//! in `lpm-common` because it is pure schema consumed by both
//! `lpm-workspace` (via `TrustedDependencyBinding.provenance_at_approval`)
//! AND `lpm-global` (via `GlobalTrustedDependencies::TrustedDependencyBinding.provenance_at_approval`).
//! Owning it in `lpm-common` keeps `lpm-global` from depending on
//! `lpm-workspace` while still letting both bindings share one
//! authoritative serde shape. `lpm-workspace` re-exports the type
//! (`pub use lpm_common::ProvenanceSnapshot;`) so existing call sites
//! continue importing it unchanged.

use serde::{Deserialize, Serialize};

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
}
