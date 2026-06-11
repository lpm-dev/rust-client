#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum VerifyError {
    /// DSSE envelope verification failed. Reasons: envelope carried
    /// no signatures, payload was not valid base64, every signature
    /// failed to parse as either raw R||S or DER, the leaf cert's
    /// SPKI was not a Sigstore-profile P-256 key, or no signature
    /// verified against the leaf cert's signing key (tampered
    /// payload or signing key did not match the cert).
    #[error("DSSE signature verification failed: {0}")]
    DsseSignature(String),

    /// A semantically-checked Rekor body field disagreed with the
    /// bundle's DSSE envelope or the leaf cert. Today's hard-fail
    /// fields: `publicKey` (binds the Rekor entry to the same
    /// signing identity that signed the DSSE envelope) and
    /// `payloadHash` (binds the Rekor entry to exactly the in-toto
    /// statement we're about to trust). Envelope hash is advisory
    /// only and never produces this variant; see
    /// [`verify_rekor_body`].
    #[error(
        "Rekor body field `{field}` mismatch: expected sha256={expected_sha256}, \
         actual sha256={actual_sha256}"
    )]
    RekorBodyMismatch {
        field: &'static str,
        expected_sha256: String,
        actual_sha256: String,
    },

    /// Rekor body's `apiVersion` is not in the supported set
    /// (`0.0.2`, `0.0.1`). Reject rather than skip so a future signer
    /// emitting an unknown shape doesn't bypass verification silently.
    #[error("Rekor body apiVersion `{api_version}` is not in the supported set (0.0.1, 0.0.2)")]
    RekorBodyUnknownVersion { api_version: String },

    /// Rekor body could not be parsed at all: `canonicalizedBody`
    /// wasn't base64, the decoded bytes weren't JSON, top-level
    /// `kind` wasn't `intoto`, or required fields were missing /
    /// of the wrong shape. Distinct from [`Self::RekorBodyMismatch`]
    /// which is reserved for "we parsed the body but its claims
    /// disagree with the bundle."
    #[error("Rekor body is malformed: {0}")]
    RekorBodyMalformed(String),

    /// The vendored Sigstore trust root could not be parsed (JSON
    /// shape drift, base64 decode failure on cert / key material,
    /// missing required field, etc.).
    #[error("vendored Sigstore trust root failed to load: {0}")]
    TrustRoot(String),

    /// The vendored trust root no longer has at least one currently-
    /// active key for every role (Fulcio CA, Rekor signing key, CT
    /// log key). The artifact is stale; the user must update `lpm`
    /// to a release that ships a refreshed root before any Sigstore
    /// verification can succeed.
    ///
    /// Trust roots intentionally carry retired entries alongside
    /// active ones so that bundles signed during retired windows
    /// can still verify against the integratedTime they declare
    /// — so a single past `validFor.end` is NOT expiry; the
    /// artifact is expired when an entire role has gone retired-
    /// only.
    #[error(
        "vendored Sigstore trust root has no currently-active key for role(s): {missing_roles}; \
         update lpm to refresh"
    )]
    TrustRootExpired { missing_roles: String },

    /// Rekor SET (Signed Entry Timestamp) verification failed:
    /// signature did not verify under the pinned Rekor key, the
    /// pinned key for the entry's `logID` is absent / not active at
    /// `integratedTime`, the SET signature was not valid DER, or the
    /// pinned key's SPKI did not decode as ECDSA P-256.
    #[error("Rekor SET verification failed: {0}")]
    RekorSet(String),

    /// The Rekor body did not carry a Signed Entry Timestamp, but
    /// the caller's [`RekorInclusionProofPolicy`] required one
    /// (`RequireSet` or `RequireBoth`). The inclusion-proof path is
    /// the alternative offline anchor; under `Either`
    /// or `RequireInclusionProof` this case is not an error.
    #[error("Rekor SET is required by policy but missing from the bundle")]
    RekorSetMissing,

    /// Rekor Merkle inclusion proof verification failed: signed
    /// checkpoint did not verify under the pinned Rekor key, the
    /// walked Merkle root did not match the checkpoint's signed
    /// root, the proof was internally inconsistent (e.g. `logIndex`
    /// outside the `treeSize` range), the checkpoint envelope was
    /// malformed, or the proof's `hashes` slice had the wrong arity.
    #[error("Rekor inclusion proof verification failed: {0}")]
    InclusionProof(String),

    /// The Rekor body did not carry an inclusion proof, but the
    /// caller's [`RekorInclusionProofPolicy`] required one
    /// (`RequireInclusionProof` or `RequireBoth`). The SET path is
    /// the alternative offline anchor; under `Either`
    /// or `RequireSet` this case is not an error.
    #[error("Rekor inclusion proof is required by policy but missing from the bundle")]
    InclusionProofMissing,

    /// X.509 chain validation failed: a cert's notBefore/notAfter
    /// window did not contain `integratedTime`, an issuer/subject
    /// pair didn't line up, a link's signature didn't verify under
    /// its parent, no path to a trusted Fulcio root could be built,
    /// or the chain used an unsupported signature algorithm.
    /// AIA fetch is intentionally NOT implemented (the verifier
    /// refuses to fetch missing intermediates from the URL embedded
    /// in the cert — Sigstore bundles always ship the full chain,
    /// and AIA fetch would re-open a supply-chain redirect arm).
    #[error("X.509 chain validation failed: {0}")]
    Chain(String),

    /// Embedded Signed Certificate Timestamp (SCT) verification
    /// failed: leaf cert has no SCT extension at the documented
    /// OID, the SCT list TLS encoding was malformed, the precert
    /// signed-input could not be reconstructed (TBS DER manipulation
    /// failed), no pinned CT log key matched the SCT's `logId` at
    /// `integratedTime`, the SCT signature did not verify under the
    /// pinned key, or zero SCTs in the list verified (the threshold
    /// is "at least one valid").
    #[error("SCT verification failed: {0}")]
    Sct(String),

    /// Bundle parse failed: JSON malformed, missing required field,
    /// unrecognized shape (none of the three known: Sigstore Bundle
    /// v0.2 chain, v0.3 single-cert, npm attestations wrapper), or
    /// a sub-component (DSSE envelope, cert chain, tlog entry)
    /// could not be deserialized into the bundle schema.
    #[error("Sigstore bundle parse failed: {0}")]
    BundleParse(String),

    /// Leaf cert's identity (SAN URI or Fulcio OIDC issuer
    /// extension) did not match the caller's `IdentityExpectations`.
    /// Self-update populates expectations to bind the signing
    /// identity to `lpm-dev/rust-client/.github/workflows/release.yml`.
    /// npm attestation verification can pass `IdentityExpectations::none()`
    /// when per-package identity tracking happens outside this verifier.
    #[error(
        "leaf cert identity does not match expectations: {field}: expected `{expected}`, \
         got `{actual}`"
    )]
    IdentityMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
}

/// Policy for which Rekor inclusion artifacts a bundle must carry to
/// be considered verifiable. Threaded through [`verify_rekor_set`] and
/// [`verify_inclusion_proof`]; the composed
/// entry point ([`verify_sigstore_bundle`]) sets it per call site.
///
/// `Either` is the right default for npm-attestation consumption
/// (some npm cohorts ship SET-only, others inclusion-proof-only,
/// some both). `RequireBoth` is the self-update default because binary
/// replacement is the highest-trust operation, so it requires both
/// offline anchors. The variant is the *single* authority on what's required;
/// there is intentionally no parallel `require_inclusion_proof: bool`
/// (adding one re-creates a dual-authority bug).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekorInclusionProofPolicy {
    /// Accept the bundle if at least one of SET, inclusion proof is
    /// present and verifies. Verify the other if it's also present
    /// (defense in depth). Reject if both are absent.
    Either,
    /// SET must be present and verify. Inclusion proof is verified
    /// only when present (advisory).
    RequireSet,
    /// Inclusion proof must be present and verify. SET is verified
    /// only when present (advisory).
    RequireInclusionProof,
    /// Both SET and inclusion proof must be present and both must
    /// verify. The strongest claim.
    RequireBoth,
}

impl RekorInclusionProofPolicy {
    /// True when SET absence should hard-fail per this policy.
    #[allow(dead_code)]
    pub fn requires_set(self) -> bool {
        matches!(self, Self::RequireSet | Self::RequireBoth)
    }

    /// True when inclusion-proof absence should hard-fail per this policy.
    #[allow(dead_code)]
    pub fn requires_inclusion_proof(self) -> bool {
        matches!(self, Self::RequireInclusionProof | Self::RequireBoth)
    }
}
