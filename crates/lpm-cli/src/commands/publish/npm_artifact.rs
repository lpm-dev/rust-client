use super::types::{NpmTargetArtifact, NpmTargetArtifactInput};
use super::version_data::integrity_to_sha512_hex;
use crate::commands::publish_common;
use crate::{install_ui, provenance, sigstore};
use lpm_common::LpmError;

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
    if let Some(context) = input.provenance_context {
        let final_hashes = publish_common::compute_hashes(&tarball_data);
        let sha512_hex = integrity_to_sha512_hex(&final_hashes.integrity);
        let slsa = provenance::build_slsa_statement(
            &context.ci,
            input.npm_name,
            input.version,
            &sha512_hex,
        );
        let slsa_json = serde_json::to_vec(&slsa)
            .map_err(|e| LpmError::Registry(format!("failed to serialize SLSA statement: {e}")))?;

        let bundle = sigstore::sign_and_record(&context.jwt, &slsa_json)
            .await
            .map_err(|e| {
                LpmError::Registry(format!(
                    "Sigstore provenance failed: {e}. \
                     Publish aborted because --provenance requires successful provenance generation."
                ))
            })?;

        if !input.json_output {
            install_ui::done(&format!(
                "Sigstore provenance generated for {} → Rekor",
                input.target_label
            ));
        }
        let bundle_json = serde_json::to_value(&bundle).unwrap_or_default();
        version_data["_provenance"] = bundle_json.clone();
        version_data["_npmProvenanceAttestations"] = bundle_json;
    }

    Ok(NpmTargetArtifact {
        tarball_data,
        version_data,
    })
}
