use lpm_common::LpmError;

const GITHUB_API_URL: &str = "https://api.github.com";
const GITHUB_REPOSITORY_MAX_CHARS: usize = 140;

pub(super) fn validate_repository(repository: &str, flag: &str) -> Result<(), LpmError> {
    if repository.chars().count() > GITHUB_REPOSITORY_MAX_CHARS {
        return Err(LpmError::Script(format!(
            "{flag} must be at most {GITHUB_REPOSITORY_MAX_CHARS} characters"
        )));
    }
    let (owner, name) = split_repository(repository)
        .ok_or_else(|| LpmError::Script(format!("{flag} must use the owner/name format")))?;
    let valid_owner = owner
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '-')
        && !owner.starts_with('-')
        && !owner.ends_with('-');
    let valid_name = name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'));
    if !valid_owner || !valid_name {
        return Err(LpmError::Script(format!(
            "{flag} contains characters GitHub does not accept"
        )));
    }
    Ok(())
}

pub(super) fn split_repository(repository: &str) -> Option<(&str, &str)> {
    let (owner, name) = repository.split_once('/')?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return None;
    }
    Some((owner, name))
}

pub(super) fn validate_repository_id(repository_id: &str) -> Result<(), LpmError> {
    if repository_id.is_empty()
        || repository_id.len() > 20
        || repository_id.starts_with('0')
        || !repository_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LpmError::Script(
            "GitHub repository ID must be a positive decimal integer of at most 20 digits".into(),
        ));
    }
    Ok(())
}

pub(super) fn github_api_url() -> Result<String, LpmError> {
    if !cfg!(any(debug_assertions, feature = "acceptance-test-hooks")) {
        return Ok(GITHUB_API_URL.into());
    }
    let Some(candidate) = std::env::var_os("LPM_ACCEPTANCE_GITHUB_API_BASE_URL") else {
        return Ok(GITHUB_API_URL.into());
    };
    if std::env::var("ACCEPTANCE_RUN_ID")
        .ok()
        .is_none_or(|value| value.trim().is_empty())
    {
        return Ok(GITHUB_API_URL.into());
    }
    let candidate = candidate.to_string_lossy();
    let parsed = reqwest::Url::parse(&candidate)
        .map_err(|error| LpmError::Script(format!("invalid acceptance GitHub URL: {error}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LpmError::Script(
            "the acceptance GitHub URL must not contain credentials".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(LpmError::Script(
            "the acceptance GitHub URL must not contain a query or fragment".into(),
        ));
    }
    if !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1")) {
        return Err(LpmError::Script(
            "the acceptance GitHub URL must use a loopback host".into(),
        ));
    }
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(LpmError::Script(
            "the acceptance GitHub URL must use HTTP or HTTPS".into(),
        ));
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err(LpmError::Script(
            "the acceptance GitHub URL must not contain a path".into(),
        ));
    }
    Ok(candidate.trim_end_matches('/').to_string())
}
