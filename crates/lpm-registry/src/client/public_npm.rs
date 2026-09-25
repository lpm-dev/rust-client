use super::*;

/// How one request reads the client's public npm registry: anonymously, or
/// with the credential `.npmrc` scopes to that registry.
///
/// Direct metadata paths attach the credential and partition their caches by
/// it, so an anonymous request never reads a credentialed response.
#[derive(Clone, Copy, Debug, Default)]
pub struct PublicNpmAccess<'a> {
    auth: Option<&'a crate::npmrc::RegistryAuth>,
}

impl<'a> PublicNpmAccess<'a> {
    pub const ANONYMOUS: Self = Self { auth: None };

    pub(super) fn with_auth(auth: Option<&'a crate::npmrc::RegistryAuth>) -> Self {
        Self { auth }
    }

    pub(super) fn auth(self) -> Option<&'a crate::npmrc::RegistryAuth> {
        self.auth
    }
}

impl RegistryClient {
    /// Public npm registry access for `route`, or `None` when the route reads
    /// another registry. An `.npmrc` route whose registry is the client's npm
    /// registry uses the direct paths with its credential.
    pub fn public_npm_access<'r>(
        &self,
        route: &'r crate::UpstreamRoute,
    ) -> Option<PublicNpmAccess<'r>> {
        match route {
            crate::UpstreamRoute::NpmDirect => Some(PublicNpmAccess::ANONYMOUS),
            crate::UpstreamRoute::Custom { target, auth }
                if self.is_npm_registry(&target.base_url) =>
            {
                Some(PublicNpmAccess::with_auth(auth.as_deref()))
            }
            crate::UpstreamRoute::Custom { .. } | crate::UpstreamRoute::LpmWorker => None,
        }
    }

    pub(super) fn is_npm_registry(&self, base_url: &str) -> bool {
        if base_url.trim_end_matches('/') == self.npm_registry_url.trim_end_matches('/') {
            return true;
        }
        let (Ok(candidate), Ok(registry)) = (
            reqwest::Url::parse(base_url),
            reqwest::Url::parse(&self.npm_registry_url),
        ) else {
            return false;
        };
        candidate.scheme() == registry.scheme()
            && candidate
                .host_str()
                .zip(registry.host_str())
                .is_some_and(|(candidate, registry)| candidate.eq_ignore_ascii_case(registry))
            && candidate.port_or_known_default() == registry.port_or_known_default()
            && candidate.path().trim_end_matches('/') == registry.path().trim_end_matches('/')
    }

    pub(super) fn npm_access_cache_key(
        &self,
        namespace: &str,
        document: &str,
        access: PublicNpmAccess<'_>,
    ) -> String {
        let principal = principal_fingerprint(
            access.auth,
            self.http.identity_fp_for_url(&self.npm_registry_url),
        );
        Self::metadata_cache_key_for_principal(
            namespace,
            &self.npm_registry_url,
            &principal,
            document,
        )
    }

    /// A GET against the client's npm registry carrying `access`'s credential.
    pub(super) async fn npm_registry_get(
        &self,
        url: &str,
        accept: &'static str,
        access: PublicNpmAccess<'_>,
    ) -> Result<reqwest::RequestBuilder, LpmError> {
        let request = self
            .http
            .for_url(url)
            .await?
            .get(url)
            .header("Accept", accept);
        apply_npmrc_auth(request, url, access.auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NpmrcConfig, RouteMode, RouteTable, UpstreamRoute};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn routes(npmrc: &str) -> RouteTable {
        RouteTable::new(
            RouteMode::Direct,
            NpmrcConfig::parse(npmrc, "test", &|_| None),
        )
        .expect("valid npmrc")
    }

    /// `.npmrc` that points the default registry at `server` with a token.
    fn credentialed_route(server: &MockServer) -> UpstreamRoute {
        let address = server.address();
        routes(&format!(
            "registry={}/\n//{}:{}/:_authToken=npm-token\n",
            server.uri(),
            address.ip(),
            address.port()
        ))
        .route_for_package("pkg")
    }

    fn client(server: &MockServer, cache: &std::path::Path) -> RegistryClient {
        RegistryClient::new()
            .with_npm_registry_url(server.uri())
            .with_cache_dir(Some(cache.to_path_buf()))
            .with_synchronous_cache_writes(true)
    }

    fn manifest(server: &MockServer, version: &str) -> serde_json::Value {
        serde_json::json!({
            "name": "pkg",
            "version": version,
            "dist": {
                "tarball": format!("{}/pkg/-/pkg-{version}.tgz", server.uri()),
                "integrity": format!("sha512-{}==", "A".repeat(86))
            }
        })
    }

    fn history(server: &MockServer) -> serde_json::Value {
        serde_json::json!({
            "name": "pkg",
            "dist-tags": {"latest": "2.0.0"},
            "versions": {"1.0.0": manifest(server, "1.0.0"), "2.0.0": manifest(server, "2.0.0")},
            "time": {"1.0.0": "2025-01-01T00:00:00.000Z", "2.0.0": "2025-02-01T00:00:00.000Z"}
        })
    }

    async fn authorizations(server: &MockServer, request_path: &str) -> Vec<Option<String>> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == request_path)
            .map(|request| {
                request
                    .headers
                    .get("authorization")
                    .map(|value| value.to_str().unwrap().to_owned())
            })
            .collect()
    }

    #[test]
    fn public_npm_access_follows_the_route_destination() {
        let client = RegistryClient::new();
        let anonymous = |route: &UpstreamRoute| {
            client
                .public_npm_access(route)
                .is_some_and(|access| access.auth().is_none())
        };
        assert!(anonymous(&UpstreamRoute::NpmDirect));
        assert!(
            client
                .public_npm_access(&UpstreamRoute::LpmWorker)
                .is_none()
        );

        let token = routes("//registry.npmjs.org/:_authToken=secret\n").route_for_package("react");
        assert!(matches!(token, UpstreamRoute::Custom { .. }));
        assert!(
            client
                .public_npm_access(&token)
                .is_some_and(|access| access.auth().is_some())
        );
        for registry in [
            "https://registry.npmjs.org/",
            "HTTPS://Registry.NPMJS.org:443",
        ] {
            let route = routes(&format!("registry={registry}\n")).route_for_package("react");
            assert!(anonymous(&route), "{registry}");
        }
        for registry in [
            "https://npm.internal.example/",
            "https://registry.npmjs.org/mirror/",
            "http://registry.npmjs.org/",
        ] {
            let route = routes(&format!("registry={registry}\n")).route_for_package("react");
            assert!(client.public_npm_access(&route).is_none(), "{registry}");
        }
        let mirrored = RegistryClient::new().with_npm_registry_url("https://npm.mirror.example");
        assert!(mirrored.public_npm_access(&token).is_none());
    }

    #[test]
    fn anonymous_access_keeps_persisted_cache_keys_and_credentials_stay_opaque() {
        let client = RegistryClient::new();
        assert_eq!(
            client.npm_direct_metadata_cache_key("react", PublicNpmAccess::ANONYMOUS),
            "npm-direct:26:https://registry.npmjs.org:anon:react"
        );
        let route = routes("//registry.npmjs.org/:_authToken=secret\n").route_for_package("react");
        let credentialed = client
            .npm_direct_metadata_cache_key("react", client.public_npm_access(&route).unwrap());
        assert!(credentialed.starts_with("npm-direct:26:https://registry.npmjs.org:principal-"));
        assert!(!credentialed.contains("secret"));
    }

    #[tokio::test]
    async fn credentialed_latest_documents_carry_the_token_and_never_serve_anonymous_reads() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(manifest(&server, "2.0.0")))
            .mount(&server)
            .await;
        // History raced against the latest document never answers in time.
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(history(&server))
                    .set_delay(std::time::Duration::from_secs(30)),
            )
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = client(&server, cache.path());
        let route = credentialed_route(&server);
        let credentialed = client.public_npm_access(&route).unwrap();

        for access in [credentialed, PublicNpmAccess::ANONYMOUS, credentialed] {
            let resolved = client
                .get_npm_preferred_resolution_metadata_with_timings("pkg", access, |_| true)
                .await
                .unwrap();
            assert!(resolved.fetched.metadata.versions.contains_key("2.0.0"));
        }

        assert_eq!(
            authorizations(&server, "/pkg/latest").await,
            [Some("Bearer npm-token".to_owned()), None]
        );
    }

    #[tokio::test]
    async fn npm_registry_custom_reads_share_the_direct_cache_and_routed_invalidation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .and(header("authorization", "Bearer npm-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(history(&server)))
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = client(&server, cache.path());
        let route = credentialed_route(&server);
        let UpstreamRoute::Custom { target, auth } = &route else {
            panic!("an npmrc registry is a custom route");
        };

        client
            .get_npm_metadata_from(&target.base_url, "pkg", auth.as_deref())
            .await
            .unwrap();
        let access = client.public_npm_access(&route).unwrap();
        let preferred = client
            .get_npm_preferred_resolution_metadata_with_timings("pkg", access, |_| true)
            .await
            .unwrap();
        assert!(preferred.fetched.timings.cache_hit);
        assert_eq!(authorizations(&server, "/pkg").await.len(), 1);

        client.invalidate_routed_metadata_cache(&route, "pkg", None);
        client
            .get_npm_metadata_from(&target.base_url, "pkg", auth.as_deref())
            .await
            .unwrap();
        assert_eq!(authorizations(&server, "/pkg").await.len(), 2);
    }

    #[tokio::test]
    async fn credentialed_exact_pins_feed_blocked_set_capture_without_another_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .and(header("accept", "application/json"))
            .and(header("authorization", "Bearer npm-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(history(&server)))
            .expect(1)
            .mount(&server)
            .await;
        let cache = tempfile::tempdir().unwrap();
        let client = client(&server, cache.path());
        let route = credentialed_route(&server);
        let access = client.public_npm_access(&route).unwrap();

        client
            .get_npm_version_from_history_attempt("pkg", "1.0.0", access)
            .await
            .unwrap();
        let captured = client
            .get_npm_blocked_set_meta_for_versions("pkg", &["1.0.0"], route.clone())
            .await
            .expect("selected history covers the pinned version");

        assert_eq!(captured.time["1.0.0"], "2025-01-01T00:00:00.000Z");
        server.verify().await;
    }
}
