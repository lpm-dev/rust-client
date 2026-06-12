use super::types::ProvenanceContext;
use crate::oidc;
use lpm_common::LpmError;

pub(crate) async fn resolve_provenance_context(
    provenance_flag: bool,
) -> Result<Option<ProvenanceContext>, LpmError> {
    if !provenance_flag {
        return Ok(None);
    }

    let (ci, jwt) = oidc::resolve_provenance_jwt().await?;
    Ok(Some(ProvenanceContext { ci, jwt }))
}
