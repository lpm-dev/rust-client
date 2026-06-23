use super::types::{
    LoadedProvenanceFile, NpmTargetArtifact, NpmTargetArtifactInput, ResolvedProvenance,
};
use super::version_data::integrity_to_sha512_hex;
use crate::commands::publish_common::{self, NpmProvenanceAttachment};
use crate::{install_ui, provenance, sigstore};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use lpm_common::LpmError;
use std::io::Read as _;
use std::path::Path;

const PROVENANCE_FILE_MAX_BYTES: u64 = 10 * 1024 * 1024;
const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
const IN_TOTO_STATEMENT_V01: &str = "https://in-toto.io/Statement/v0.1";
const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";
const SLSA_PROVENANCE_V02: &str = "https://slsa.dev/provenance/v0.2";
const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const SIGSTORE_BUNDLE_V03_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

pub(crate) async fn prepare_npm_target_artifact(
    input: NpmTargetArtifactInput<'_>,
) -> Result<NpmTargetArtifact, LpmError> {
    let tarball_data = if input.npm_name != input.package_json_name {
        publish_common::rewrite_tarball_name(
            input.base_tarball_data,
            input.package_json_name,
            input.npm_name,
        )?
    } else {
        input.base_tarball_data.to_vec()
    };

    let mut version_data = input.base_version_data.clone();
    let mut provenance_attachment = None;
    if let Some(provenance) = input.provenance_context {
        let final_hashes = publish_common::compute_hashes(&tarball_data);
        let sha512_hex = integrity_to_sha512_hex(&final_hashes.integrity);
        let expected_subject = provenance::npm_package_purl(input.npm_name, input.version);

        match provenance {
            ResolvedProvenance::Generate(context) => {
                let slsa = provenance::build_slsa_statement(
                    &context.ci,
                    input.npm_name,
                    input.version,
                    &sha512_hex,
                );
                let slsa_json = serde_json::to_vec(&slsa).map_err(|e| {
                    LpmError::Registry(format!("failed to serialize SLSA statement: {e}"))
                })?;

                let bundle = sigstore::sign_and_record(&context.jwt, &slsa_json)
                    .await
                    .map_err(|e| {
                        LpmError::Registry(format!(
                            "Sigstore provenance failed: {e}. \
                             Publish aborted because provenance requires successful provenance generation."
                        ))
                    })?;

                if !input.json_output {
                    install_ui::done(&format!(
                        "Sigstore provenance generated for {} → Rekor",
                        input.target_label
                    ));
                }
                let bundle_data = serde_json::to_string(&bundle).map_err(|e| {
                    LpmError::Registry(format!("failed to serialize Sigstore bundle: {e}"))
                })?;
                let bundle_json = serde_json::to_value(&bundle).map_err(|e| {
                    LpmError::Registry(format!("failed to encode Sigstore bundle: {e}"))
                })?;
                version_data["_provenance"] = bundle_json.clone();
                version_data["_npmProvenanceAttestations"] = bundle_json;
                provenance_attachment = Some(NpmProvenanceAttachment {
                    media_type: bundle.media_type,
                    data: bundle_data,
                });
            }
            ResolvedProvenance::File(file) => {
                validate_provenance_file_for_target(file, &expected_subject, &sha512_hex)?;
                provenance_attachment = Some(file.attachment.clone());
            }
        }
    }

    Ok(NpmTargetArtifact {
        tarball_data,
        version_data,
        provenance_attachment,
    })
}

pub(crate) fn load_provenance_file(path: &Path) -> Result<LoadedProvenanceFile, LpmError> {
    let file = open_provenance_file(path)?;
    let metadata = file.metadata().map_err(LpmError::Io)?;
    if !metadata.is_file() {
        return Err(LpmError::Registry(format!(
            "provenance file {} must be a regular file",
            path.display()
        )));
    }
    if metadata.len() > PROVENANCE_FILE_MAX_BYTES {
        return Err(LpmError::Registry(format!(
            "provenance file {} is too large ({} bytes, max {PROVENANCE_FILE_MAX_BYTES})",
            path.display(),
            metadata.len()
        )));
    }
    let mut limited = file.take(PROVENANCE_FILE_MAX_BYTES + 1);
    let mut bytes = Vec::with_capacity(metadata.len().min(PROVENANCE_FILE_MAX_BYTES) as usize);
    limited.read_to_end(&mut bytes).map_err(LpmError::Io)?;
    if bytes.len() as u64 > PROVENANCE_FILE_MAX_BYTES {
        return Err(LpmError::Registry(format!(
            "provenance file {} is too large (read more than {PROVENANCE_FILE_MAX_BYTES} bytes)",
            path.display()
        )));
    }
    let data = String::from_utf8(bytes).map_err(|e| {
        LpmError::Registry(format!(
            "invalid provenance file {}: expected UTF-8 Sigstore bundle JSON: {e}",
            path.display()
        ))
    })?;
    let bundle: serde_json::Value = serde_json::from_str(&data).map_err(|e| {
        LpmError::Registry(format!(
            "invalid provenance file {}: expected Sigstore bundle JSON: {e}",
            path.display()
        ))
    })?;
    let media_type = validate_provenance_bundle_media_type(&bundle)?.to_string();
    let statement = provenance_statement_from_bundle(&bundle)?;
    validate_slsa_provenance_statement(&statement)?;

    let verified = crate::sigstore_verify::verify_sigstore_bundle(
        data.as_bytes(),
        &crate::sigstore_verify::IdentityExpectations::none(),
        crate::sigstore_verify::VerifyOptions::npm_attestation(),
    )
    .map_err(|e| {
        LpmError::Registry(format!(
            "provenance file {} failed Sigstore verification: {e}",
            path.display()
        ))
    })?;
    validate_identity_matches_predicate(&statement, &verified)?;

    Ok(LoadedProvenanceFile {
        attachment: NpmProvenanceAttachment { media_type, data },
        statement,
    })
}

#[cfg(unix)]
fn open_provenance_file(path: &Path) -> Result<std::fs::File, LpmError> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(LpmError::Io)
}

#[cfg(not(unix))]
fn open_provenance_file(path: &Path) -> Result<std::fs::File, LpmError> {
    std::fs::File::open(path).map_err(LpmError::Io)
}

fn validate_provenance_file_for_target(
    file: &LoadedProvenanceFile,
    expected_subject: &str,
    expected_sha512_hex: &str,
) -> Result<(), LpmError> {
    validate_provenance_statement_subject(&file.statement, expected_subject, expected_sha512_hex)
}

fn validate_provenance_bundle_media_type(bundle: &serde_json::Value) -> Result<&str, LpmError> {
    let media_type = bundle
        .get("mediaType")
        .and_then(|value| value.as_str())
        .ok_or_else(|| LpmError::Registry("provenance bundle is missing mediaType".into()))?;
    if !matches!(
        media_type,
        sigstore::SIGSTORE_BUNDLE_MEDIA_TYPE | SIGSTORE_BUNDLE_V03_MEDIA_TYPE
    ) {
        return Err(LpmError::Registry(format!(
            "provenance bundle mediaType {media_type:?} is not supported (expected {:?} or {SIGSTORE_BUNDLE_V03_MEDIA_TYPE:?})",
            sigstore::SIGSTORE_BUNDLE_MEDIA_TYPE
        )));
    }
    Ok(media_type)
}

fn provenance_statement_from_bundle(
    bundle: &serde_json::Value,
) -> Result<serde_json::Value, LpmError> {
    let payload_type = bundle
        .get("dsseEnvelope")
        .and_then(|envelope| envelope.get("payloadType"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            LpmError::Registry("provenance bundle missing dsseEnvelope.payloadType".into())
        })?;
    if payload_type != IN_TOTO_PAYLOAD_TYPE {
        return Err(LpmError::Registry(format!(
            "provenance bundle payloadType {payload_type:?} is not supported (expected {IN_TOTO_PAYLOAD_TYPE:?})"
        )));
    }
    let payload = bundle
        .get("dsseEnvelope")
        .and_then(|envelope| envelope.get("payload"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            LpmError::Registry("provenance bundle missing dsseEnvelope.payload".into())
        })?;
    let payload_bytes = BASE64
        .decode(payload.as_bytes())
        .map_err(|e| LpmError::Registry(format!("provenance bundle payload is not base64: {e}")))?;
    serde_json::from_slice(&payload_bytes).map_err(|e| {
        LpmError::Registry(format!("provenance bundle payload is not valid JSON: {e}"))
    })
}

fn validate_slsa_provenance_statement(statement: &serde_json::Value) -> Result<(), LpmError> {
    let statement_type = statement
        .get("_type")
        .and_then(|value| value.as_str())
        .ok_or_else(|| LpmError::Registry("provenance statement is missing _type".into()))?;
    if !matches!(statement_type, IN_TOTO_STATEMENT_V1 | IN_TOTO_STATEMENT_V01) {
        return Err(LpmError::Registry(format!(
            "provenance statement _type {statement_type:?} is not supported (expected {IN_TOTO_STATEMENT_V1:?} or {IN_TOTO_STATEMENT_V01:?})"
        )));
    }
    let predicate_type = statement
        .get("predicateType")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            LpmError::Registry("provenance statement is missing predicateType".into())
        })?;
    if !matches!(predicate_type, SLSA_PROVENANCE_V1 | SLSA_PROVENANCE_V02) {
        return Err(LpmError::Registry(format!(
            "provenance statement predicateType {predicate_type:?} is not supported (expected {SLSA_PROVENANCE_V1:?} or {SLSA_PROVENANCE_V02:?})"
        )));
    }
    statement
        .get("predicate")
        .and_then(|value| value.as_object())
        .ok_or_else(|| LpmError::Registry("provenance statement is missing predicate".into()))?;
    source_repository_from_statement(statement)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            LpmError::Registry("provenance statement is missing source repository metadata".into())
        })?;
    Ok(())
}

fn validate_identity_matches_predicate(
    statement: &serde_json::Value,
    verified: &crate::sigstore_verify::VerifiedProvenance,
) -> Result<(), LpmError> {
    let Some(publisher) = verified.snapshot.publisher.as_deref() else {
        return Ok(());
    };
    let Some(repo) = publisher.strip_prefix("github:") else {
        return Ok(());
    };
    let expected_repository = normalize_source_repository(&format!("https://github.com/{repo}"));
    let actual_repository = source_repository_from_statement(statement)
        .map(normalize_source_repository)
        .ok_or_else(|| {
            LpmError::Registry("provenance statement is missing source repository metadata".into())
        })?;
    if actual_repository != expected_repository {
        return Err(LpmError::Registry(format!(
            "provenance statement workflow repository {actual_repository:?} does not match signing identity {expected_repository:?}"
        )));
    }
    if let Some(expected_path) = verified.snapshot.workflow_path.as_deref() {
        if let Some(actual_path) = workflow_path_from_statement(statement)
            && actual_path != expected_path
        {
            return Err(LpmError::Registry(format!(
                "provenance statement workflow path {actual_path:?} does not match signing identity {expected_path:?}"
            )));
        }
    }
    if let Some(expected_ref) = verified.snapshot.workflow_ref.as_deref()
        && let Some(actual_ref) = workflow_ref_from_statement(statement)
        && actual_ref != expected_ref
    {
        return Err(LpmError::Registry(format!(
            "provenance statement workflow ref {actual_ref:?} does not match signing identity {expected_ref:?}"
        )));
    }
    Ok(())
}

fn source_repository_from_statement(statement: &serde_json::Value) -> Option<&str> {
    statement
        .pointer("/predicate/buildDefinition/externalParameters/workflow/repository")
        .and_then(|value| value.as_str())
        .or_else(|| {
            statement
                .pointer("/predicate/invocation/configSource/uri")
                .and_then(|value| value.as_str())
        })
}

fn workflow_path_from_statement(statement: &serde_json::Value) -> Option<&str> {
    statement
        .pointer("/predicate/buildDefinition/externalParameters/workflow/path")
        .and_then(|value| value.as_str())
}

fn workflow_ref_from_statement(statement: &serde_json::Value) -> Option<&str> {
    statement
        .pointer("/predicate/buildDefinition/externalParameters/workflow/ref")
        .and_then(|value| value.as_str())
}

fn normalize_source_repository(value: &str) -> String {
    let trimmed = value.trim();
    let without_scheme = trimmed.strip_prefix("git+").unwrap_or(trimmed);
    let without_trailing_slash = without_scheme.trim_end_matches('/');
    without_trailing_slash
        .strip_suffix(".git")
        .unwrap_or(without_trailing_slash)
        .to_string()
}

fn validate_provenance_statement_subject(
    statement: &serde_json::Value,
    expected_subject: &str,
    expected_sha512_hex: &str,
) -> Result<(), LpmError> {
    let subjects = statement
        .get("subject")
        .and_then(|value| value.as_array())
        .ok_or_else(|| LpmError::Registry("provenance statement has no subject array".into()))?;
    if subjects.len() != 1 {
        return Err(LpmError::Registry(format!(
            "provenance statement must contain exactly one subject, got {}",
            subjects.len()
        )));
    }
    let subject = &subjects[0];
    let actual_subject = subject
        .get("name")
        .and_then(|value| value.as_str())
        .ok_or_else(|| LpmError::Registry("provenance subject is missing name".into()))?;
    if actual_subject != expected_subject {
        return Err(LpmError::Registry(format!(
            "provenance subject {actual_subject:?} does not match package {expected_subject:?}"
        )));
    }
    let actual_digest = subject
        .get("digest")
        .and_then(|digest| digest.get("sha512"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| LpmError::Registry("provenance subject is missing digest.sha512".into()))?;
    if actual_digest != expected_sha512_hex {
        return Err(LpmError::Registry(
            "provenance subject digest does not match the final tarball".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement_with_subject(subject: &str, sha512: &str) -> serde_json::Value {
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": subject,
                "digest": {"sha512": sha512}
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "workflow": {
                            "repository": "https://github.com/owner/repo",
                            "path": ".github/workflows/publish.yml",
                            "ref": "refs/heads/main"
                        }
                    }
                }
            }
        })
    }

    fn slsa_v0_2_statement_with_subject(subject: &str, sha512: &str) -> serde_json::Value {
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": subject,
                "digest": {"sha512": sha512}
            }],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {"id": "https://gitlab.com/gitlab-org/gitlab-runner"},
                "buildType": "https://gitlab.com/gitlab-org/gitlab/-/blob/master/doc/ci/yaml/README.md",
                "invocation": {
                    "configSource": {
                        "uri": "git+https://gitlab.com/owner/repo.git",
                        "digest": {"sha1": "abc123"},
                        "entryPoint": "publish"
                    }
                }
            }
        })
    }

    fn bundle_with_statement(statement: &serde_json::Value) -> serde_json::Value {
        let payload_b64 = BASE64.encode(serde_json::to_vec(statement).unwrap());
        serde_json::json!({
            "mediaType": sigstore::SIGSTORE_BUNDLE_MEDIA_TYPE,
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": payload_b64,
                "signatures": []
            },
            "verificationMaterial": {
                "x509CertificateChain": {"certificates": []},
                "tlogEntries": []
            }
        })
    }

    #[test]
    fn validate_provenance_statement_subject_accepts_matching_subject_and_digest() {
        let statement = statement_with_subject("pkg:npm/%40scope/pkg@1.0.0", "abc123");
        validate_provenance_statement_subject(&statement, "pkg:npm/%40scope/pkg@1.0.0", "abc123")
            .unwrap();
    }

    #[test]
    fn validate_provenance_statement_subject_rejects_mismatched_digest() {
        let statement = statement_with_subject("pkg:npm/%40scope/pkg@1.0.0", "abc123");
        let err = validate_provenance_statement_subject(
            &statement,
            "pkg:npm/%40scope/pkg@1.0.0",
            "def456",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("digest does not match the final tarball")
        );
    }

    #[test]
    fn provenance_statement_from_bundle_requires_in_toto_payload_type() {
        let statement = statement_with_subject("pkg:npm/pkg@1.0.0", "abc123");
        let mut bundle = bundle_with_statement(&statement);
        bundle["dsseEnvelope"]["payloadType"] = serde_json::json!("application/json");

        let err = provenance_statement_from_bundle(&bundle).unwrap_err();

        assert!(err.to_string().contains("payloadType"));
    }

    #[test]
    fn validate_provenance_bundle_media_type_accepts_v0_3_bundle() {
        let statement = statement_with_subject("pkg:npm/pkg@1.0.0", "abc123");
        let mut bundle = bundle_with_statement(&statement);
        bundle["mediaType"] = serde_json::json!(SIGSTORE_BUNDLE_V03_MEDIA_TYPE);

        let media_type = validate_provenance_bundle_media_type(&bundle).unwrap();

        assert_eq!(media_type, SIGSTORE_BUNDLE_V03_MEDIA_TYPE);
    }

    #[test]
    fn validate_slsa_provenance_statement_requires_slsa_predicate() {
        let mut statement = statement_with_subject("pkg:npm/pkg@1.0.0", "abc123");
        statement["predicateType"] = serde_json::json!("https://example.com/not-slsa");

        let err = validate_slsa_provenance_statement(&statement).unwrap_err();

        assert!(err.to_string().contains("predicateType"));
    }

    #[test]
    fn validate_slsa_provenance_statement_accepts_npm_slsa_v0_2_shape() {
        let statement = slsa_v0_2_statement_with_subject("pkg:npm/pkg@1.0.0", "abc123");

        validate_slsa_provenance_statement(&statement).unwrap();
    }

    #[test]
    fn validate_identity_matches_predicate_accepts_normalized_v0_2_git_uri() {
        let statement = slsa_v0_2_statement_with_subject("pkg:npm/pkg@1.0.0", "abc123");
        let verified = crate::sigstore_verify::VerifiedProvenance {
            snapshot: lpm_workspace::ProvenanceSnapshot {
                present: true,
                publisher: Some("github:owner/repo".into()),
                workflow_path: Some(".github/workflows/publish.yml".into()),
                workflow_ref: Some("refs/heads/main".into()),
                attestation_cert_sha256: Some("sha256-test".into()),
            },
            integrated_time: std::time::SystemTime::UNIX_EPOCH,
            leaf_cert_sha256: "sha256-test".into(),
            log_id: "log".into(),
            log_index: 1,
        };
        let mut statement = statement;
        statement["predicate"]["invocation"]["configSource"]["uri"] =
            serde_json::json!("git+https://github.com/owner/repo.git");

        validate_identity_matches_predicate(&statement, &verified).unwrap();
    }

    #[test]
    fn validate_identity_matches_predicate_rejects_github_repository_mismatch() {
        let mut statement = statement_with_subject("pkg:npm/pkg@1.0.0", "abc123");
        statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["repository"] =
            serde_json::json!("https://github.com/other/repo");
        let verified = crate::sigstore_verify::VerifiedProvenance {
            snapshot: lpm_workspace::ProvenanceSnapshot {
                present: true,
                publisher: Some("github:owner/repo".into()),
                workflow_path: Some(".github/workflows/publish.yml".into()),
                workflow_ref: Some("refs/heads/main".into()),
                attestation_cert_sha256: Some("sha256-test".into()),
            },
            integrated_time: std::time::SystemTime::UNIX_EPOCH,
            leaf_cert_sha256: "sha256-test".into(),
            log_id: "log".into(),
            log_index: 1,
        };

        let err = validate_identity_matches_predicate(&statement, &verified).unwrap_err();

        assert!(err.to_string().contains("does not match signing identity"));
    }

    #[test]
    fn load_provenance_file_rejects_oversized_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("too-large.sigstore");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(PROVENANCE_FILE_MAX_BYTES + 1).unwrap();

        let err = load_provenance_file(&path).unwrap_err();

        assert!(err.to_string().contains("too large"));
    }

    #[cfg(unix)]
    #[test]
    fn load_provenance_file_rejects_special_file() {
        let err = load_provenance_file(Path::new("/dev/null")).unwrap_err();

        assert!(err.to_string().contains("regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn load_provenance_file_rejects_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.sigstore");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is a NUL-terminated path owned by this test, and mkfifo
        // only observes the pointer for the duration of the call.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo must create the test fifo");

        let err = load_provenance_file(&path).unwrap_err();

        assert!(err.to_string().contains("regular file"));
    }

    #[tokio::test]
    async fn prepare_npm_target_artifact_rejects_file_provenance_subject_mismatch() {
        let tarball_data = b"fake-tarball";
        let final_hashes = publish_common::compute_hashes(tarball_data);
        let sha512_hex = integrity_to_sha512_hex(&final_hashes.integrity);
        let file = LoadedProvenanceFile {
            attachment: NpmProvenanceAttachment {
                media_type: sigstore::SIGSTORE_BUNDLE_MEDIA_TYPE.to_string(),
                data: "{}".into(),
            },
            statement: statement_with_subject("pkg:npm/other@1.0.0", &sha512_hex),
        };
        let provenance = ResolvedProvenance::File(file);

        let err = prepare_npm_target_artifact(NpmTargetArtifactInput {
            package_json_name: "pkg",
            npm_name: "pkg",
            version: "1.0.0",
            base_version_data: &serde_json::json!({"name": "pkg", "version": "1.0.0"}),
            base_tarball_data: tarball_data,
            provenance_context: Some(&provenance),
            target_label: "npm",
            json_output: true,
        })
        .await
        .unwrap_err();

        assert!(err.to_string().contains("does not match package"));
    }
}
