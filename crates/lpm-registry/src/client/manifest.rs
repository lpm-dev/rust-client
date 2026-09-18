use super::*;

/// Published manifest fields used by inventory exports. Install metadata remains separate.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ManifestVersionMetadata {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license: Option<serde_json::Value>,
    #[serde(default)]
    pub licenses: Option<serde_json::Value>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub repository: Option<serde_json::Value>,
    #[serde(default)]
    pub author: Option<serde_json::Value>,
    #[serde(default)]
    pub dist: Option<DistInfo>,
}

#[derive(serde::Deserialize)]
struct ManifestPackument {
    name: String,
    versions: HashMap<String, ManifestVersionMetadata>,
}

impl ManifestPackument {
    fn into_versions(
        self,
        name: &str,
    ) -> Result<HashMap<String, ManifestVersionMetadata>, LpmError> {
        if self.name != name
            || self
                .versions
                .iter()
                .any(|(version, metadata)| metadata.name != name || metadata.version != *version)
        {
            return Err(LpmError::Registry(format!(
                "registry manifest metadata does not match requested package {name}"
            )));
        }
        Ok(self.versions)
    }
}

impl RegistryClient {
    /// Fetch current full manifest declarations from an explicit npm registry.
    pub async fn get_manifest_metadata_from(
        &self,
        base_url: &str,
        name: &str,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<HashMap<String, ManifestVersionMetadata>, LpmError> {
        validate_manifest_registry_base(base_url)?;
        let destination =
            RequestDestination::parse(&format!("{}/{name}", base_url.trim_end_matches('/')))?;
        let request = self
            .http
            .for_destination(&destination)
            .await?
            .get(destination.as_url().clone())
            .header("Accept", "application/json");
        let request = apply_npmrc_auth_to_destination(request, &destination, auth)?;
        let response = self
            .send_package_metadata_request_with_npmrc_auth(request, auth)
            .await?;
        let metadata: ManifestPackument =
            parse_capped_metadata(response, &format!("manifest metadata for {name}")).await?;
        metadata.into_versions(name)
    }

    /// Fetch locked manifest versions, with one stored-session recovery for hidden private history.
    pub async fn get_package_manifest_metadata(
        &self,
        name: &PackageName,
        required_versions: &[&str],
    ) -> Result<HashMap<String, ManifestVersionMetadata>, LpmError> {
        validate_manifest_registry_base(&self.base_url)?;
        let bearer = self.current_bearer(AuthPosture::PackageRead)?;
        let metadata = self.fetch_package_manifest_metadata(name).await?;
        if required_versions
            .iter()
            .any(|version| !metadata.contains_key(*version))
            && self.recover_package_read_session(bearer.as_deref()).await?
        {
            return self.fetch_package_manifest_metadata(name).await;
        }
        Ok(metadata)
    }

    /// Fetch current full manifest declarations from the configured LPM.dev Registry.
    async fn fetch_package_manifest_metadata(
        &self,
        name: &PackageName,
    ) -> Result<HashMap<String, ManifestVersionMetadata>, LpmError> {
        let scoped = name.scoped();
        let url = format!("{}/api/registry/{scoped}", self.base_url);
        self.execute_with_package_access_recovery(|| async {
            let bearer = self.current_bearer(AuthPosture::AuthRequired)?;
            let request = self
                .build_worker_metadata_get_with_bearer(&url, bearer.as_deref())
                .await?;
            let response = self.send_package_metadata_request(request).await?;
            let metadata: ManifestPackument =
                parse_capped_metadata(response, &format!("manifest metadata for {scoped}")).await?;
            metadata.into_versions(&scoped)
        })
        .await
    }
}

fn validate_manifest_registry_base(base_url: &str) -> Result<(), LpmError> {
    let base = reqwest::Url::parse(base_url)
        .map_err(|_| LpmError::Registry("invalid metadata registry URL".into()))?;
    if base.query().is_some() || base.fragment().is_some() {
        return Err(LpmError::Registry(
            "metadata registry URL must not contain a query or fragment".into(),
        ));
    }
    Ok(())
}
