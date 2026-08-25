use super::*;

impl RegistryClient {
    // ─── Discovery Endpoints ────────────────────────────────────────

    /// Search packages.
    ///
    /// Posture: `AnonymousPreferred` — public discovery endpoint, no
    /// bearer attached even when stored.
    ///
    /// Calls: GET /api/search/packages?q=...&limit=...&mode=semantic
    pub async fn search_packages(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<SearchResponse, LpmError> {
        let url = format!(
            "{}/api/search/packages?q={}&limit={}&mode=semantic",
            self.base_url,
            urlencoding::encode(query),
            limit.min(20)
        );
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    pub async fn search_npm_packages_routed(
        &self,
        query: &str,
        limit: u32,
        route: crate::UpstreamRoute,
    ) -> Result<SearchResponse, LpmError> {
        match route {
            crate::UpstreamRoute::LpmWorker => self.search_packages(query, limit).await,
            crate::UpstreamRoute::NpmDirect => self.search_npm_packages(query, limit).await,
            crate::UpstreamRoute::Custom { target, auth } => {
                self.search_npm_packages_from(&target.base_url, query, limit, auth.as_deref())
                    .await
            }
        }
    }

    pub async fn search_npm_packages(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<SearchResponse, LpmError> {
        self.search_npm_packages_from(&self.npm_registry_url, query, limit, None)
            .await
    }

    pub async fn search_npm_packages_from(
        &self,
        base_url: &str,
        query: &str,
        limit: u32,
        auth: Option<&crate::npmrc::RegistryAuth>,
    ) -> Result<SearchResponse, LpmError> {
        #[derive(serde::Deserialize)]
        struct NpmSearchEnvelope {
            #[serde(default)]
            objects: Vec<NpmSearchObject>,
        }

        #[derive(serde::Deserialize)]
        struct NpmSearchObject {
            package: NpmSearchPackage,
        }

        #[derive(serde::Deserialize)]
        struct NpmSearchPackage {
            name: String,
            #[serde(default)]
            description: Option<String>,
            version: String,
        }

        let destination = RequestDestination::parse(&format!(
            "{base_url}/-/v1/search?text={}&size={}",
            urlencoding::encode(query),
            limit.min(20)
        ))?;
        let req = self
            .http
            .for_destination(&destination)
            .await?
            .get(destination.as_url().clone())
            .header("Accept", "application/json");
        let req = apply_npmrc_auth_to_destination(req, &destination, auth)?;
        let response = self.send_with_retry_with_npmrc_auth(req, auth).await?;
        let envelope: NpmSearchEnvelope =
            parse_capped_api_json(response, &format!("response from {}", destination.as_str()))
                .await?;

        Ok(SearchResponse {
            packages: envelope
                .objects
                .into_iter()
                .map(|object| SearchPackage {
                    id: None,
                    name: object.package.name,
                    owner: None,
                    description: object.package.description,
                    distribution_mode: Some("npm".to_string()),
                    download_count: None,
                    latest_version: Some(object.package.version),
                    ecosystem: Some("js".to_string()),
                    quality_score: None,
                    category: None,
                    avatar_url: None,
                    is_org: None,
                    archived: None,
                })
                .collect(),
        })
    }

    /// Search owners (users and organizations).
    ///
    /// Posture: `AnonymousPreferred` — public discovery endpoint.
    ///
    /// Calls: GET /api/search/owners?q=...&limit=...
    pub async fn search_owners(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<OwnerSearchResponse, LpmError> {
        let url = format!(
            "{}/api/search/owners?q={}&limit={}",
            self.base_url,
            urlencoding::encode(query),
            limit.min(10)
        );
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Check if a package name is available.
    ///
    /// Posture: `AuthRequired` — the original docstring noted "prevents
    /// enumeration", which means the server gates this endpoint.
    /// Wrapped in `execute_with_recovery` so a stale stored session
    /// self-heals.
    ///
    /// Calls: GET /api/registry/check-name?name=owner.package-name
    pub async fn check_name(&self, name: &str) -> Result<CheckNameResponse, LpmError> {
        let url = format!(
            "{}/api/registry/check-name?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    // ─── Auth Endpoints ─────────────────────────────────────────────

    /// Get current user info.
    ///
    /// Posture: `AuthRequired`. On 401 with a refresh-backed session,
    /// `execute_with_recovery` performs one silent refresh + retry.
    ///
    /// Calls: GET /api/registry/-/whoami
    pub async fn whoami(&self) -> Result<WhoamiResponse, LpmError> {
        const MAX_ORGANIZATION_PAGES: usize = 100;

        #[derive(serde::Deserialize)]
        struct WhoamiOrganizationsPage {
            #[serde(default)]
            organizations: Vec<WhoamiOrg>,
            #[serde(default, rename = "organizations_next_cursor")]
            organizations_next_cursor: Option<String>,
        }

        let url = format!("{}/api/registry/-/whoami", self.base_url);
        let mut response: WhoamiResponse = self
            .execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await?;
        let mut next_cursor = response.organizations_next_cursor.take();
        let mut seen_cursors = std::collections::HashSet::new();
        let mut seen_scopes: std::collections::HashSet<String> =
            response.available_scopes.iter().cloned().collect();

        for _ in 0..MAX_ORGANIZATION_PAGES {
            let Some(cursor) = next_cursor.take() else {
                return Ok(response);
            };
            if !seen_cursors.insert(cursor.clone()) {
                return Err(LpmError::Registry(
                    "registry returned a repeated whoami organization cursor".to_string(),
                ));
            }

            let continuation_url = format!(
                "{}/api/registry/-/whoami/organizations?cursor={}",
                self.base_url,
                urlencoding::encode(&cursor)
            );
            let page: WhoamiOrganizationsPage = self
                .execute_with_recovery(AuthPosture::AuthRequired, || {
                    self.get_json(&continuation_url)
                })
                .await?;

            for organization in page.organizations {
                let scope = format!("@{}", organization.slug);
                if seen_scopes.insert(scope.clone()) {
                    response.available_scopes.push(scope);
                }
                response.organizations.push(organization);
            }
            next_cursor = page.organizations_next_cursor;
        }

        Err(LpmError::Registry(
            "registry returned too many whoami organization pages".to_string(),
        ))
    }

    /// Validate the current token.
    ///
    /// Posture: `AuthRequired`.
    ///
    /// Calls: GET /api/registry/cli/check
    pub async fn check_token(&self) -> Result<TokenCheckResponse, LpmError> {
        let url = format!("{}/api/registry/cli/check", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    /// Validate publish authorization and version availability without
    /// reserving a version or creating Registry state.
    pub async fn publish_preflight(
        &self,
        name: &str,
        version: &str,
    ) -> Result<PublishPreflightResponse, LpmError> {
        let url = format!(
            "{}/api/registry/-/package/publish-preflight?name={}&version={}",
            self.base_url,
            urlencoding::encode(name),
            urlencoding::encode(version)
        );
        let response: PublishPreflightResponse = self
            .execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await?;
        if !response.success {
            return Err(LpmError::Registry(format!(
                "publish preflight was denied for {name}@{version}"
            )));
        }
        if response.name != name || response.version != version {
            return Err(LpmError::Registry(format!(
                "publish preflight returned a mismatched package identity (expected {name}@{version}, received {}@{})",
                response.name, response.version
            )));
        }
        Ok(response)
    }

    /// Read the current publication lifecycle state for an uploaded LPM version.
    pub async fn get_publication_status(
        &self,
        name: &str,
        version: &str,
    ) -> Result<PublicationStatusResponse, LpmError> {
        let url = format!(
            "{}/api/registry/-/package/publication-status?name={}&version={}",
            self.base_url,
            urlencoding::encode(name),
            urlencoding::encode(version)
        );
        let response: PublicationStatusResponse = self
            .execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await?;
        if response.name != name || response.version != version {
            return Err(LpmError::Registry(format!(
                "publication status returned a mismatched package identity (expected {name}@{version}, received {}@{})",
                response.name, response.version
            )));
        }
        Ok(response)
    }

    /// Revoke every browser pairing authorized by the current stored session.
    ///
    /// Posture: `SessionRequired`. The bearer is re-resolved inside the
    /// recovery closure so a stale access token gets one refresh and retry.
    ///
    /// Calls: POST /api/vault/pair/revoke-all
    pub async fn revoke_all_pairings(&self) -> Result<(), LpmError> {
        let url = format!("{}/api/vault/pair/revoke-all", self.base_url);

        self.execute_with_recovery(AuthPosture::SessionRequired, || async {
            let response = self
                .post_json_raw_status(&url, &serde_json::json!({}))
                .await?;
            let status = response.status();

            match status {
                status if status.is_success() => Ok(()),
                reqwest::StatusCode::UNAUTHORIZED => Err(LpmError::AuthRequired),
                reqwest::StatusCode::FORBIDDEN => {
                    let body = read_capped_error_text(response).await;
                    Err(forbidden_error_from_body(body))
                }
                reqwest::StatusCode::NOT_FOUND => {
                    let body = read_capped_error_text(response).await;
                    Err(LpmError::NotFound(body))
                }
                _ => {
                    let body = read_capped_error_text(response).await;
                    Err(LpmError::Registry(format!(
                        "pairing revocation failed: HTTP {status}: {body}"
                    )))
                }
            }
        })
        .await
    }

    /// Revoke the current refresh-backed CLI session on the server.
    ///
    /// Posture: `SessionRequired`. The bearer is re-resolved inside the
    /// recovery closure so that, on a 401 → refresh → retry, the
    /// rotated token is sent on the second attempt.
    ///
    /// Calls: POST /api/cli/revoke
    pub async fn revoke_session(&self) -> Result<(), LpmError> {
        let url = format!("{}/api/cli/revoke", self.base_url);

        self.execute_with_recovery(AuthPosture::SessionRequired, || async {
            let bearer = self
                .current_bearer(AuthPosture::SessionRequired)?
                .ok_or(LpmError::SessionExpired)?;
            let req = self
                .http
                .for_url(&url)
                .await?
                .post(&url)
                .bearer_auth(&bearer);
            let response = self.send_with_retry(req).await?;
            if response.status().is_success() {
                Ok(())
            } else {
                Err(LpmError::Registry(format!(
                    "session revocation failed: {}",
                    response.status()
                )))
            }
        })
        .await
    }

    /// Publish a package to the registry.
    ///
    /// Posture: `AuthRequired`. Wrapped in `execute_with_recovery`
    /// so a stale access token on a refresh-backed session triggers
    /// one silent refresh + retry of the entire publish. The bespoke
    /// 500-handling inside `send_publish_safe` is preserved because it
    /// lives inside the closure and runs on each attempt.
    ///
    /// Calls: PUT /api/registry/{encoded_name}
    /// Optional `otp` header for 2FA-enabled users.
    ///
    /// Uses publish-safe retry logic (S4): does NOT retry on HTTP 500
    /// (the server may have stored the version before crashing). Only retries
    /// on gateway errors (502/503/504) and network-level failures.
    ///
    /// Timeout is scaled based on tarball size (S3): 60s + 2s per MB, cap 600s.
    pub async fn publish_package(
        &self,
        encoded_name: &str,
        payload: &lpm_http::ReplayableRequestBody,
        otp: Option<&str>,
        tarball_size_bytes: usize,
    ) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/registry/{}", self.base_url, encoded_name);

        // S3: Scale timeout based on tarball size
        let tarball_mb = tarball_size_bytes as u64 / (1024 * 1024);
        let timeout_secs = std::cmp::min(60 + tarball_mb * 2, 600);
        let timeout = Duration::from_secs(timeout_secs);
        let publish_client = lpm_http::client_builder()
            .timeout(timeout)
            .user_agent(format!("lpm-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| LpmError::Network(format!("failed to build publish client: {e}")))?;

        self.execute_with_recovery(AuthPosture::AuthRequired, || async {
            let bearer = self.current_bearer(AuthPosture::AuthRequired)?;

            // S4: Publish-safe send — no retry on 500, only on gateway errors
            let response = self
                .send_publish_safe(
                    || {
                        let body = payload.body();
                        let mut request = publish_client
                            .put(&url)
                            .header(reqwest::header::CONTENT_TYPE, "application/json")
                            .header(reqwest::header::CONTENT_LENGTH, payload.len())
                            .timeout(timeout)
                            .body(body);
                        if let Some(bearer) = bearer.as_ref() {
                            request = request.bearer_auth(bearer);
                        }
                        if let Some(code) = otp {
                            request = request.header("x-otp", code);
                        }
                        Ok(request)
                    },
                    payload,
                    encoded_name,
                )
                .await?;
            let status = response.status();
            let body: serde_json::Value =
                parse_capped_api_json(response, "publish response").await?;

            if status.is_success() {
                Ok(body)
            } else {
                let error_msg = body
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("unknown error");
                let code = body.get("code").and_then(|c| c.as_str()).unwrap_or("");

                Err(LpmError::Registry(format!(
                    "publish failed ({}): {} {}",
                    status,
                    error_msg,
                    if code.is_empty() {
                        String::new()
                    } else {
                        format!("[{code}]")
                    }
                )))
            }
        })
        .await
    }

    // ─── Intelligence Endpoints ─────────────────────────────────────

    /// Get quality report for a package.
    ///
    /// Posture: `AnonymousPreferred` — public read; bearer not attached.
    ///
    /// Calls: GET /api/registry/quality?name=owner.package-name
    pub async fn get_quality(&self, name: &str) -> Result<QualityResponse, LpmError> {
        let url = format!(
            "{}/api/registry/quality?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Get Agent Skills for a package.
    ///
    /// Posture: `AuthRequired` — private package skills and publisher-only
    /// pending versions must follow the same principal as package metadata
    /// and tarball access.
    ///
    /// Calls: GET /api/registry/skills?name=owner.package-name
    pub async fn get_skills(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<SkillsResponse, LpmError> {
        let mut url = format!(
            "{}/api/registry/skills?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        if let Some(v) = version {
            url.push_str(&format!("&version={}", urlencoding::encode(v)));
        }
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    /// Get API documentation for a package.
    ///
    /// Posture: `AnonymousPreferred`.
    ///
    /// Calls: GET /api/registry/api-docs?name=owner.package-name
    pub async fn get_api_docs(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<ApiDocsResponse, LpmError> {
        let mut url = format!(
            "{}/api/registry/api-docs?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        if let Some(v) = version {
            url.push_str(&format!("&version={}", urlencoding::encode(v)));
        }
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Get LLM context for a package.
    ///
    /// Posture: `AnonymousPreferred`.
    ///
    /// Calls: GET /api/registry/llm-context?name=owner.package-name
    pub async fn get_llm_context(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<LlmContextResponse, LpmError> {
        let mut url = format!(
            "{}/api/registry/llm-context?name={}",
            self.base_url,
            urlencoding::encode(name)
        );
        if let Some(v) = version {
            url.push_str(&format!("&version={}", urlencoding::encode(v)));
        }
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    // ─── Revenue Endpoints ──────────────────────────────────────────

    /// Get Pool revenue stats for the current user.
    ///
    /// Posture: `AuthRequired` (account-scoped data). Wrapped in
    /// `execute_with_recovery` so a stale stored session self-heals.
    ///
    /// Calls: GET /api/registry/pool/stats
    pub async fn get_pool_stats(&self) -> Result<PoolStatsResponse, LpmError> {
        let url = format!("{}/api/registry/pool/stats", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    /// Get Marketplace earnings for the current user.
    ///
    /// Posture: `AuthRequired` (account-scoped data). Same recovery
    /// contract as `get_pool_stats`.
    ///
    /// Calls: GET /api/registry/marketplace/earnings
    pub async fn get_marketplace_earnings(&self) -> Result<MarketplaceEarningsResponse, LpmError> {
        let url = format!("{}/api/registry/marketplace/earnings", self.base_url);
        self.execute_with_recovery(AuthPosture::AuthRequired, || self.get_json(&url))
            .await
    }

    // ─── Health ─────────────────────────────────────────────────────

    /// Check registry health.
    ///
    /// Posture: `AnonymousOnly` — health endpoint is universally
    /// public and must never carry a bearer.
    ///
    /// Calls: GET /api/registry/health
    pub async fn health_check(&self) -> Result<bool, LpmError> {
        let url = format!("{}/api/registry/health", self.base_url);
        let response = self
            .send_with_retry(
                self.build_get_with_posture(&url, AuthPosture::AnonymousOnly)
                    .await?,
            )
            .await?;
        Ok(response.status().is_success())
    }

    // ─── Tunnel Endpoints ──────────────────────────────────────────

    /// List claimed tunnel domains.
    ///
    /// Posture: `SessionRequired`. Wrapped in `execute_with_recovery`
    /// so stale-access-token cases still self-heal for refresh-backed
    /// sessions.
    ///
    /// Calls: GET /api/tunnel/domains or GET /api/tunnel/domains?org=slug
    pub async fn tunnel_list(&self, org_slug: Option<&str>) -> Result<serde_json::Value, LpmError> {
        let url = if let Some(slug) = org_slug {
            format!(
                "{}/api/tunnel/domains?org={}",
                self.base_url,
                urlencoding::encode(slug)
            )
        } else {
            format!("{}/api/tunnel/domains", self.base_url)
        };
        self.execute_with_recovery(AuthPosture::SessionRequired, || self.get_json(&url))
            .await
    }

    /// Claim a tunnel domain.
    ///
    /// Posture: `SessionRequired`. Same recovery contract as
    /// `tunnel_list`.
    ///
    /// Calls: POST /api/tunnel/domains
    /// Body: { domain: "acme-api.lpm.llc", org?: "acmecorp" }
    pub async fn tunnel_claim(
        &self,
        domain: &str,
        org_slug: Option<&str>,
    ) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/tunnel/domains", self.base_url);
        let mut body = serde_json::json!({ "domain": domain });
        if let Some(slug) = org_slug {
            body["org"] = serde_json::Value::String(slug.to_string());
        }
        self.execute_with_recovery(AuthPosture::SessionRequired, || async {
            let response = self.post_json_raw(&url, &body).await?;
            let status = response.status();
            let data: serde_json::Value =
                parse_capped_api_json(response, "tunnel claim response").await?;

            if !status.is_success() {
                let error = data["error"].as_str().unwrap_or("Unknown error");
                return Err(LpmError::Tunnel(error.to_string()));
            }

            Ok(data)
        })
        .await
    }

    /// Release a claimed tunnel domain.
    ///
    /// Posture: `SessionRequired`. Same recovery contract as
    /// `tunnel_list`.
    ///
    /// Calls: DELETE /api/tunnel/domains/{domain}
    pub async fn tunnel_unclaim(
        &self,
        domain: &str,
        org_slug: Option<&str>,
    ) -> Result<serde_json::Value, LpmError> {
        let url = if let Some(slug) = org_slug {
            format!(
                "{}/api/tunnel/domains/{}?org={}",
                self.base_url,
                urlencoding::encode(domain),
                urlencoding::encode(slug)
            )
        } else {
            format!(
                "{}/api/tunnel/domains/{}",
                self.base_url,
                urlencoding::encode(domain)
            )
        };
        self.execute_with_recovery(AuthPosture::SessionRequired, || async {
            let mut req = self.http.for_url(&url).await?.delete(&url);
            if let Some(bearer) = self.current_bearer(AuthPosture::SessionRequired)? {
                req = req.bearer_auth(bearer);
            }
            let response = self.send_with_retry(req).await?;
            let status = response.status();
            let data: serde_json::Value =
                parse_capped_api_json(response, "tunnel unclaim response").await?;

            if !status.is_success() {
                let error = data["error"].as_str().unwrap_or("Unknown error");
                return Err(LpmError::Tunnel(error.to_string()));
            }

            Ok(data)
        })
        .await
    }

    /// List available tunnel base domains.
    ///
    /// Posture: `AnonymousPreferred` — endpoint is documented public.
    /// No bearer attached, no recovery on 401.
    ///
    /// Calls: GET /api/tunnel/domains/available
    pub async fn tunnel_available_domains(&self) -> Result<serde_json::Value, LpmError> {
        let url = format!("{}/api/tunnel/domains/available", self.base_url);
        self.get_json_anon(&url, AuthPosture::AnonymousPreferred)
            .await
    }

    /// Look up a specific tunnel domain claim.
    ///
    /// Posture: `SessionRequired` (the response includes
    /// `ownedByYou` which depends on the caller's identity). Same
    /// recovery contract as `tunnel_list`.
    ///
    /// Calls: GET /api/tunnel/domains/{domain}
    pub async fn tunnel_domain_lookup(&self, domain: &str) -> Result<serde_json::Value, LpmError> {
        let url = format!(
            "{}/api/tunnel/domains/{}",
            self.base_url,
            urlencoding::encode(domain)
        );
        self.execute_with_recovery(AuthPosture::SessionRequired, || self.get_json(&url))
            .await
    }
}
