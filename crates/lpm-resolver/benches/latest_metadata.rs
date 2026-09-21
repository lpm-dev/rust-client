//! Alternating local-registry comparison of history and latest-document hydration.
use lpm_registry::{RegistryClient, RouteMode, RouteTable};
use lpm_resolver::{CanonicalKey, ResolverPolicy};
use lpm_resolver::{
    experimental_fetch_cached_package_info_with_policy_and_timings,
    experimental_fetch_exact_cached_package_info_with_policy_and_timings,
};
use serde_json::json;
use std::time::Instant;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::main]
async fn main() {
    let server = MockServer::start().await;
    let versions = (0..2048).map(|patch| {
        let version = format!("1.0.{patch}");
        let document = json!({
            "name": "metadata-bench", "version": version,
            "dependencies": {"dependency-a": "^1", "dependency-b": "^2", "dependency-c": "^3"},
            "dist": {"tarball": "https://example.invalid/package.tgz", "integrity": "sha512-test"}
        });
        (version, document)
    }).collect::<serde_json::Map<_, _>>();
    let latest = versions["1.0.2047"].clone();
    let full = json!({"name": "metadata-bench", "dist-tags": {"latest": "1.0.2047"}, "versions": versions});
    Mock::given(method("GET"))
        .and(path("/metadata-bench"))
        .respond_with(ResponseTemplate::new(200).set_body_json(full))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/metadata-bench/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(latest))
        .mount(&server)
        .await;
    let client = RegistryClient::new()
        .with_npm_registry_url(server.uri())
        .with_cache_dir(None);
    let route = RouteTable::from_mode_only(RouteMode::Direct);
    let canonical = CanonicalKey::npm("metadata-bench");
    let policy = ResolverPolicy::default();
    for sample in 0..9 {
        let order = if sample % 2 == 0 {
            ["history", "latest"]
        } else {
            ["latest", "history"]
        };
        for variant in order {
            let start = Instant::now();
            let (info, timings) = if variant == "history" {
                experimental_fetch_cached_package_info_with_policy_and_timings(
                    &client, &route, &canonical, &policy,
                )
                .await
            } else {
                experimental_fetch_exact_cached_package_info_with_policy_and_timings(
                    &client, &route, &canonical, "latest", &policy,
                )
                .await
            }
            .expect("local metadata fixture resolves");
            assert_eq!(
                info.latest_version.as_ref().unwrap().to_string(),
                "1.0.2047"
            );
            if sample != 0 {
                println!(
                    "{}",
                    json!({"sample":sample, "variant":variant, "wall_us":start.elapsed().as_micros(), "body_bytes":timings.body_bytes, "version_count":timings.version_count})
                );
            }
        }
    }
}
