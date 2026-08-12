use super::*;
use lpm_common::integrity::{HashAlgorithm, Integrity};
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use std::time::Duration;

const GITHUB_API_BASE: &str = "https://api.github.com/";
const GITHUB_CODELOAD_BASE: &str = "https://codeload.github.com/";
const MAX_GITHUB_API_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_GITHUB_ARCHIVE_BYTES: u64 = lpm_registry::MAX_COMPRESSED_TARBALL_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GitHubRepository {
    owner: String,
    repository: String,
    canonical_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedGitHubSource {
    pub(super) locked_source: String,
    pub(super) commit: String,
    pub(super) archive_url: String,
}

#[derive(Debug, Clone)]
struct GitHubEndpoints {
    api: Url,
    codeload: Url,
}

#[derive(Debug, Deserialize)]
struct GitHubCommitResponse {
    sha: String,
}

pub(super) fn canonicalize_github_repository(url: &str) -> Result<GitHubRepository, LpmError> {
    let raw_url = url.strip_prefix("git+").ok_or_else(|| {
        LpmError::Registry("GitHub dependency URL must use the git+https scheme".to_string())
    })?;
    let parsed = Url::parse(raw_url).map_err(|_| {
        LpmError::Registry("GitHub dependency URL is malformed or unsupported".to_string())
    })?;

    if parsed.scheme() != "https" || parsed.host_str() != Some("github.com") {
        return Err(LpmError::Registry(
            "only public git+https://github.com dependencies are supported".to_string(),
        ));
    }
    if parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(LpmError::Registry(
            "GitHub dependency URLs cannot contain credentials, ports, query parameters, or fragments"
                .to_string(),
        ));
    }
    if raw_url.contains('%') {
        return Err(LpmError::Registry(
            "percent-encoded GitHub repository paths are not supported".to_string(),
        ));
    }

    let segments = parsed
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .unwrap_or_default();
    if segments.len() != 2 {
        return Err(LpmError::Registry(
            "GitHub dependency URL must identify exactly one owner/repository pair".to_string(),
        ));
    }
    let owner = segments[0];
    let repository = segments[1].strip_suffix(".git").unwrap_or(segments[1]);
    if !is_github_component(owner) || !is_github_component(repository) {
        return Err(LpmError::Registry(
            "GitHub dependency owner or repository contains unsupported characters".to_string(),
        ));
    }

    Ok(GitHubRepository {
        owner: owner.to_string(),
        repository: repository.to_string(),
        canonical_source: format!("git+https://github.com/{owner}/{repository}.git"),
    })
}

pub(super) async fn resolve_github_source(
    url: &str,
    reference: Option<&str>,
) -> Result<ResolvedGitHubSource, LpmError> {
    let repository = canonicalize_github_repository(url)?;
    let original_ref = validate_git_reference(reference)?;
    let endpoints = GitHubEndpoints::from_env()?;
    let commit = match original_ref.as_deref() {
        Some(reference) if is_full_commit(reference) => reference.to_ascii_lowercase(),
        reference => {
            resolve_github_commit(&repository, reference.unwrap_or("HEAD"), &endpoints).await?
        }
    };
    let archive_url = endpoints.archive_url(&repository, &commit)?;
    let locked_source = format!("{}#{commit}", repository.canonical_source);

    Ok(ResolvedGitHubSource {
        locked_source,
        commit,
        archive_url,
    })
}

pub(crate) fn github_archive_url(locked_source: &str) -> Result<String, LpmError> {
    let (url, commit) = locked_source.rsplit_once('#').ok_or_else(|| {
        LpmError::Registry("locked GitHub dependency is missing its resolved commit".to_string())
    })?;
    if !is_full_commit(commit) || commit.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(LpmError::Registry(
            "locked GitHub dependency has an invalid commit".to_string(),
        ));
    }
    let repository = canonicalize_github_repository(url)?;
    GitHubEndpoints::from_env()?.archive_url(&repository, commit)
}

pub(crate) async fn download_github_archive_to_file(
    archive_url: &str,
    expected_integrity: Option<&str>,
) -> Result<lpm_registry::DownloadedTarball, LpmError> {
    let endpoints = GitHubEndpoints::from_env()?;
    let url = Url::parse(archive_url)
        .map_err(|_| LpmError::Registry("locked GitHub archive URL is malformed".to_string()))?;
    if !endpoints.codeload_url_is_allowed(&url) {
        return Err(LpmError::Registry(
            "locked GitHub archive URL is outside the configured direct GitHub origin".to_string(),
        ));
    }

    let client = github_http_client()?;
    let mut response = client
        .get(url)
        .header(reqwest::header::USER_AGENT, "lpm-rs")
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "GitHub archive request failed: {}",
                lpm_http::display_error(&error)
            ))
        })?;
    ensure_success_status(response.status(), "GitHub archive")?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_GITHUB_ARCHIVE_BYTES)
    {
        return Err(response_size_error(
            "GitHub archive",
            MAX_GITHUB_ARCHIVE_BYTES,
        ));
    }
    let spool_reservation = lpm_registry::reserve_compressed_tarball_spool(
        response.content_length(),
        MAX_GITHUB_ARCHIVE_BYTES,
    )
    .await?;

    let mut file = tempfile::NamedTempFile::new().map_err(LpmError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(LpmError::Io)?;
    }
    use sha2::Digest;

    let mut sha512 = sha2::Sha512::new();
    let mut compressed_size = 0_u64;
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        LpmError::Network(format!("failed to read GitHub archive response: {error}"))
    })? {
        compressed_size = compressed_size
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| response_size_error("GitHub archive", MAX_GITHUB_ARCHIVE_BYTES))?;
        if compressed_size > MAX_GITHUB_ARCHIVE_BYTES {
            return Err(response_size_error(
                "GitHub archive",
                MAX_GITHUB_ARCHIVE_BYTES,
            ));
        }
        spool_reservation.ensure_size(compressed_size)?;
        sha512.update(&chunk);
        std::io::Write::write_all(&mut file, &chunk).map_err(LpmError::Io)?;
    }
    std::io::Write::flush(&mut file).map_err(LpmError::Io)?;
    let sha512_sri = Integrity {
        algorithm: HashAlgorithm::Sha512,
        hash: sha512.finalize().to_vec(),
    }
    .to_string();
    let sri = match expected_integrity {
        Some(expected) => {
            let integrity = Integrity::parse(expected)?;
            let path = file.path().to_path_buf();
            let integrity_for_verification = integrity.clone();
            tokio::task::spawn_blocking(move || integrity_for_verification.verify_file(&path))
                .await
                .map_err(|error| {
                    LpmError::Registry(format!("GitHub integrity task panicked: {error}"))
                })??;
            integrity.to_string()
        }
        None => sha512_sri.clone(),
    };

    lpm_registry::DownloadedTarball::new(file, sri, sha512_sri, compressed_size, spool_reservation)
}

async fn resolve_github_commit(
    repository: &GitHubRepository,
    reference: &str,
    endpoints: &GitHubEndpoints,
) -> Result<String, LpmError> {
    let url = endpoints.commit_url(repository, reference)?;
    let client = github_http_client()?;
    let mut response = client
        .get(url)
        .header(reqwest::header::USER_AGENT, "lpm-rs")
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "GitHub commit resolution failed: {}",
                lpm_http::display_error(&error)
            ))
        })?;
    ensure_success_status(response.status(), "GitHub commit resolution")?;
    let body = read_response_body_limited(
        &mut response,
        MAX_GITHUB_API_RESPONSE_BYTES as u64,
        "GitHub commit metadata",
    )
    .await?;
    let response: GitHubCommitResponse = serde_json::from_slice(&body).map_err(|_| {
        LpmError::Registry("GitHub commit response was not valid metadata".to_string())
    })?;
    if !is_full_commit(&response.sha) {
        return Err(LpmError::Registry(
            "GitHub commit response did not contain a full commit SHA".to_string(),
        ));
    }
    Ok(response.sha.to_ascii_lowercase())
}

async fn read_response_body_limited(
    response: &mut reqwest::Response,
    limit: u64,
    operation: &str,
) -> Result<Vec<u8>, LpmError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(response_size_error(operation, limit));
    }
    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0);
    let mut body = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        LpmError::Network(format!("failed to read {operation} response: {error}"))
    })? {
        let next_size = body
            .len()
            .checked_add(chunk.len())
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| response_size_error(operation, limit))?;
        if next_size > limit {
            return Err(response_size_error(operation, limit));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn response_size_error(operation: &str, limit: u64) -> LpmError {
    LpmError::Registry(format!(
        "{operation} exceeds the {limit}-byte response size limit"
    ))
}

fn github_http_client() -> Result<reqwest::Client, LpmError> {
    lpm_http::client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|error| LpmError::Network(format!("failed to build GitHub client: {error}")))
}

fn ensure_success_status(status: StatusCode, operation: &str) -> Result<(), LpmError> {
    if status.is_success() {
        return Ok(());
    }
    if status.is_redirection() {
        return Err(LpmError::Registry(format!(
            "{operation} refused an unexpected redirect"
        )));
    }
    Err(LpmError::Registry(format!(
        "{operation} failed with HTTP status {}",
        status.as_u16()
    )))
}

fn validate_git_reference(reference: Option<&str>) -> Result<Option<String>, LpmError> {
    let Some(reference) = reference else {
        return Ok(None);
    };
    if reference.is_empty()
        || reference.len() > 256
        || reference.chars().any(char::is_control)
        || reference.chars().any(char::is_whitespace)
    {
        return Err(LpmError::Registry(
            "GitHub dependency ref is empty, too long, or contains whitespace/control characters"
                .to_string(),
        ));
    }
    Ok(Some(reference.to_string()))
}

fn is_full_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_github_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

impl GitHubEndpoints {
    fn from_env() -> Result<Self, LpmError> {
        Ok(Self {
            api: endpoint_from_env("LPM_GITHUB_API_BASE_URL", GITHUB_API_BASE)?,
            codeload: endpoint_from_env("LPM_GITHUB_CODELOAD_BASE_URL", GITHUB_CODELOAD_BASE)?,
        })
    }

    fn commit_url(&self, repository: &GitHubRepository, reference: &str) -> Result<Url, LpmError> {
        let path = format!(
            "repos/{}/{}/commits/{}",
            repository.owner,
            repository.repository,
            urlencoding::encode(reference)
        );
        self.api
            .join(&path)
            .map_err(|_| LpmError::Registry("failed to construct GitHub commit URL".to_string()))
    }

    fn archive_url(&self, repository: &GitHubRepository, commit: &str) -> Result<String, LpmError> {
        let path = format!(
            "{}/{}/tar.gz/{commit}",
            repository.owner, repository.repository
        );
        self.codeload
            .join(&path)
            .map(|url| url.to_string())
            .map_err(|_| LpmError::Registry("failed to construct GitHub archive URL".to_string()))
    }

    fn codeload_url_is_allowed(&self, url: &Url) -> bool {
        same_origin(&self.codeload, url) && url.path().starts_with(self.codeload.path())
    }
}

fn endpoint_from_env(name: &str, default: &str) -> Result<Url, LpmError> {
    let raw = std::env::var(name).unwrap_or_else(|_| default.to_string());
    let mut url =
        Url::parse(&raw).map_err(|_| LpmError::Registry(format!("{name} must be a valid URL")))?;
    let is_default = raw == default;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(LpmError::Registry(format!(
            "{name} cannot contain credentials, query parameters, or fragments"
        )));
    }
    if !is_default && !is_loopback_endpoint(&url) {
        return Err(LpmError::Registry(format!(
            "{name} overrides are restricted to loopback test endpoints"
        )));
    }
    if !url.path().ends_with('/') {
        let mut path = url.path().to_string();
        path.push('/');
        url.set_path(&path);
    }
    Ok(url)
}

fn is_loopback_endpoint(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        })
}

#[cfg(test)]
mod security_and_resolution_tests {
    use super::*;

    const COMMIT: &str = "779219540f66cecaa159da32b3b8936697ba10a7";

    #[test]
    fn canonicalize_github_repository_normalizes_public_https_url() {
        let repository =
            canonicalize_github_repository("git+https://github.com/rhashimoto/wa-sqlite.git")
                .expect("public GitHub URL should canonicalize");

        assert_eq!(
            repository.canonical_source,
            "git+https://github.com/rhashimoto/wa-sqlite.git"
        );
    }

    #[test]
    fn canonicalize_github_repository_rejects_credentials_without_echoing_them() {
        let secret = "credential-that-must-not-leak";
        let error = canonicalize_github_repository(&format!(
            "git+https://user:{secret}@github.com/owner/repository.git"
        ))
        .expect_err("credential-bearing Git URL must be rejected");

        assert!(!error.to_string().contains(secret));
    }

    #[test]
    fn canonicalize_github_repository_rejects_non_github_origin() {
        let error =
            canonicalize_github_repository("git+https://example.com/rhashimoto/wa-sqlite.git")
                .expect_err("non-GitHub origin must be rejected");

        assert!(error.to_string().contains("github.com"));
    }

    #[test]
    fn validate_git_reference_rejects_control_characters() {
        let error = validate_git_reference(Some("main\nAuthorization: secret"))
            .expect_err("control characters must be rejected");

        assert!(error.to_string().contains("control"));
    }

    #[test]
    fn github_archive_url_requires_commit_pinned_source() {
        let error = github_archive_url("git+https://github.com/rhashimoto/wa-sqlite.git#main")
            .expect_err("symbolic ref must not be accepted as a locked source");

        assert!(error.to_string().contains("invalid commit"));
    }

    #[test]
    fn github_archive_url_reconstructs_direct_codeload_url() {
        let url = github_archive_url(&format!(
            "git+https://github.com/rhashimoto/wa-sqlite.git#{COMMIT}"
        ))
        .expect("pinned GitHub source should produce an archive URL");

        assert_eq!(
            url,
            format!("https://codeload.github.com/rhashimoto/wa-sqlite/tar.gz/{COMMIT}")
        );
    }

    #[tokio::test]
    async fn github_file_download_supports_tofu_and_declared_integrity() {
        use lpm_common::integrity::{HashAlgorithm, Integrity};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let archive = b"github archive fixture";
        let sha256 = Integrity::from_bytes(HashAlgorithm::Sha256, archive).to_string();
        Mock::given(method("GET"))
            .and(path(format!("/owner/repository/tar.gz/{COMMIT}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(archive.to_vec()))
            .expect(2)
            .mount(&server)
            .await;
        let endpoint = format!("{}/", server.uri());
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_GITHUB_CODELOAD_BASE_URL",
            endpoint.clone().into(),
        )]);
        let url = format!("{endpoint}owner/repository/tar.gz/{COMMIT}");

        let tofu = download_github_archive_to_file(&url, None)
            .await
            .expect("TOFU download must succeed");
        assert!(tofu.sri.starts_with("sha512-"));
        assert_eq!(tofu.sri, tofu.sha512_sri);

        let declared = download_github_archive_to_file(&url, Some(&sha256))
            .await
            .expect("matching declared integrity must succeed");
        assert_eq!(declared.sri, sha256);
        assert!(declared.sha512_sri.starts_with("sha512-"));
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_repository_canonicalization_rejects_credentials_and_non_github_hosts() {
        assert!(
            canonicalize_github_repository("git+https://user:secret@github.com/a/b.git").is_err()
        );
        assert!(canonicalize_github_repository("git+https://github.example/a/b.git").is_err());
        assert!(canonicalize_github_repository("git+ssh://git@github.com/a/b.git").is_err());
    }

    #[test]
    fn github_repository_canonicalization_normalizes_dot_git_suffix() {
        let repository =
            canonicalize_github_repository("git+https://github.com/rhashimoto/wa-sqlite").unwrap();
        assert_eq!(
            repository.canonical_source,
            "git+https://github.com/rhashimoto/wa-sqlite.git"
        );
    }
}
