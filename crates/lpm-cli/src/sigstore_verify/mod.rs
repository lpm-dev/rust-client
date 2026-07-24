//! Sigstore attestation verifier.
//!
//! Cryptographic-verification primitives that prove every claim in an
//! in-toto statement attached to a Sigstore bundle. The data schema in
//! [`crate::sigstore`] is the precondition for these checks:
//!
//! - vendored Sigstore trust root.
//! - DSSE envelope verification against the leaf cert.
//! - X.509 chain validation at `integratedTime`.
//! - embedded SCT verification.
//! - semantic Rekor body match.
//! - Rekor SET verification.
//! - Merkle inclusion proof verification.
//! - composed `verify_sigstore_bundle` entry point.
//!
//! PAE is re-encoded from the envelope's `payload_type` and raw decoded
//! `payload`, and verified against the leaf cert's SPKI via ECDSA-P256.
//! Both DER and raw R||S signature encodings are accepted; Sigstore's
//! profile is fixed at P-256, so any non-P256 SPKI on the leaf cert is
//! rejected before signature work runs.

mod bundle;
mod chain;
mod dsse;
mod error;
mod inclusion;
mod rekor_body;
mod rekor_set;
mod sct;
#[cfg(test)]
mod tests;
mod trust_root;

pub use self::bundle::{
    IdentityExpectations, VerifiedProvenance, VerifyOptions, verify_sigstore_bundle,
};
pub(crate) use self::bundle::{extract_in_toto_subject_digest, extract_npm_subject_sha512};
pub use self::chain::verify_cert_chain;
pub(crate) use self::dsse::pae;
pub use self::dsse::verify_dsse;
pub use self::error::{RekorInclusionProofPolicy, VerifyError};
pub use self::inclusion::verify_inclusion_proof;
pub use self::rekor_body::verify_rekor_body;
pub use self::rekor_set::verify_rekor_set;
pub use self::sct::verify_embedded_sct;
pub use self::trust_root::{CtLogKey, FulcioRoot, RekorKey, TrustRoot, trust_root};

#[cfg(test)]
use self::bundle::{
    FULCIO_OIDC_ISSUER_OID_V1, check_identity_expectations, find_leaf_issuer_spki,
    parse_bundle_components,
};
#[cfg(test)]
use self::chain::{
    OID_ECDSA_WITH_SHA256, OID_ECDSA_WITH_SHA384, enforce_issuer_constraints, oid_components_match,
};
#[cfg(test)]
use self::inclusion::{rfc6962_hash_children, rfc6962_leaf_hash, rfc6962_verify_inclusion};
#[cfg(test)]
use self::rekor_set::build_set_input_canonical_json;
#[cfg(test)]
use self::sct::{
    MIN_SCT_LEN, SCT_EXTENSION_OID_COMPONENTS, der_decode_length, der_encode_length,
    reconstruct_precert_tbs_without_sct,
};
#[cfg(test)]
use self::trust_root::{EMBEDDED_TRUST_ROOT_JSON, TRUST_ROOT_EXPIRY_WARN_DAYS, ValidityWindow};
